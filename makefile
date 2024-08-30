LDLIBS = -lpcap
CXXFLAGS = -Iinclude

all: arp-spoof

src/utils.o: include/utils/utils.h src/utils.cpp
	$(CXX) $(CXXFLAGS) -c src/utils.cpp -o src/utils.o

src/extract.o: include/spoof/extract.h src/extract.cpp
	$(CXX) $(CXXFLAGS) -c src/extract.cpp -o src/extract.o

src/mac.o: include/protocols/mac.h src/mac.cpp
	$(CXX) $(CXXFLAGS) -c src/mac.cpp -o src/mac.o

src/ip.o: include/protocols/ip.h src/ip.cpp
	$(CXX) $(CXXFLAGS) -c src/ip.cpp -o src/ip.o

src/attack.o: include/spoof/attack.h src/attack.cpp
	$(CXX) $(CXXFLAGS) -c src/attack.cpp -o src/attack.o

src/main.o: include/utils/utils.h include/spoof/extract.h src/main.cpp
	$(CXX) $(CXXFLAGS) -c src/main.cpp -o src/main.o

arp-spoof: src/main.o src/utils.o src/extract.o src/ip.o src/mac.o src/attack.o
	$(CXX) $^ $(LDLIBS) -o $@

clean:
	rm -f arp-spoof src/*.o



