LDLIBS=-lpcap
CXXFLAGS=-Iinclude  # include 디렉토리를 헤더 파일 경로로 추가

all: arp-spoof

utils.o: include/utils.h src/utils.cpp

extract.o: include/extract.h extract.cpp

mac.o: include/mac.h mac.cpp

ip.o: include/ip.h ip.cpp

attack.o: include/attack.h attack.cpp 

main.o: include/utils.h include/extract.h main.cpp

arp-spoof: main.o utils.o extract.o ip.o mac.o attack.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o

