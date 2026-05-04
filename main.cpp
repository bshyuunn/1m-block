#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_set>
#include <chrono>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

void usage() {
	printf("syntax : 1m-block <site list file>\n");
	printf("sample : 1m-block top-1m.csv\n");
}

struct Param {
	const char *path_;
};

Param param;
std::unordered_set<std::string> blocklist;

void load_blocklist(const char *path) {
	auto t0 = std::chrono::steady_clock::now();

	FILE *fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "fopen failed: %s\n", path);
		exit(1);
	}

	char *line = nullptr;
	size_t cap = 0;
	ssize_t n;
	while ((n = getline(&line, &cap, fp)) != -1) {
		// "rank,domain\n" 에서 콤마 뒤만 취함
		char *comma = strchr(line, ',');
		if (comma == nullptr) continue;
		char *domain = comma + 1;
		size_t domain_len = n - (domain - line);
		while (domain_len > 0 && (domain[domain_len-1] == '\n' || domain[domain_len-1] == '\r'))
			domain_len--;
		if (domain_len == 0) continue;
		blocklist.emplace(domain, domain_len);
	}
	free(line);
	fclose(fp);

	auto t1 = std::chrono::steady_clock::now();
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
	printf("loaded %zu hosts in %ld ms\n", blocklist.size(), ms);
}

bool parse(Param *param, int argc, char *argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->path_ = argv[1];
	return true;
}

// 디버깅용 dump
void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}


// 콜백 안에서 verdict 회신할 때 필요한 패킷 id 추출
static uint32_t get_pkt_id(struct nfq_data *tb) {
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
	if (ph)
		return ntohl(ph->packet_id);
	return 0;
}

// 패킷 검사
static bool is_blocked(struct nfq_data *nfa) {
	unsigned char *data;
	int len = nfq_get_payload(nfa, &data);

	// 1. protocol 이 TCP 인지 확인
	struct iphdr *iph = (struct iphdr *)data;
	int ip_hlen = iph->ihl * 4;
	if (iph->protocol != IPPROTO_TCP) return false;

	// 2. dest 포트가 80인지 검사
	struct tcphdr *tcph = (struct tcphdr *)(data + ip_hlen);
	if (ntohs(tcph->dest) != 80) return false;
	int tcp_hlen = tcph->doff * 4;
	int hdr_len = ip_hlen + tcp_hlen;
	if (len <= hdr_len) return false;

	// 3. HTTP 페이로드 추출
	unsigned char *http = data + hdr_len;
	int http_len = len - hdr_len;

	// 4. Host 헤더 추출
	const char *host_start = (const char *)memmem(http, http_len, "\r\nHost: ", 8);
	if (host_start == nullptr) return false;
	host_start += 8;
	int rest = http_len - (host_start - (const char *)http);
	const char *host_end = (const char *)memmem(host_start, rest, "\r\n", 2);
	if (host_end == nullptr) return false;

	std::string host(host_start, host_end - host_start);
	printf("host: %s\n", host.c_str());

	return false;
}

// 패킷 도착할 때마다 호출되는 콜백 함수
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
	uint32_t id = get_pkt_id(nfa);

	if (is_blocked(nfa)) {
		return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

int main(int argc, char *argv[]) {
	if (!parse(&param, argc, argv))
		exit(1);

	printf("list file: %s\n", param.path_);
	load_blocklist(param.path_);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	// struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			// printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}

		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
