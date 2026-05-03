LDLIBS=-lnetfilter_queue

all: netfilter-test


main.o: main.cpp

netfilter-test: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f netfilter-test *.o
