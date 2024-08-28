#include <stdio.h>
#include <pcap.h>           // pcap 관련 함수들

// 설명서 출력
void usage() {
	printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

// 명령어 인자가 4보다 작거나 홀수인지 검증
int argcValidate(int argc){ 
    if (argc < 6 || argc %2 != 0) {
		fprintf(stderr, "Invalid number of arguments\n");
		usage();
		return -1;
	}
	return 0;
}

// 인터페이스 오류 검증
int handlerValidate(pcap_t * handle, char* dev, char * errbuf){
    if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
        }
	return 0;

}