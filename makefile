LDLIBS=-lpcap

all: arp-spoof

main.o: mac.h ip.h ethhdr.h arphdr.h main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o: mac.h mac.cpp

arpspoof.o: arpspoof.h arpspoof.cpp

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o arpspoof.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o

