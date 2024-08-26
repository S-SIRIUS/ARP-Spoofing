LDLIBS=-lpcap
CXXFLAGS=-Iinclude  # include 디렉토리를 헤더 파일 경로로 추가

all: arp-spoof

main.o: include/utils.h include/extract.h main.cpp

arp-spoof: main.o utils.o extract.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o

