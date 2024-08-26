#include <pcap.h>           // pcap 관련 함수들
#include <stdio.h>          
#include <stdlib.h>         // 메모리 할당 및 프로세스 제어 함수
#include <string.h>         // 문자열 관련 함수
#include <thread>           // C++ 표준 스레드 라이브러리 (std::thread 사용)

#include "utils.h"
#include "extract.h"



int main(int argc, char* argv[]) {
	
	// 사용자가 입력한 명령어 검증
	argcValidate(argc);
	
	// 사용자가 입력한 인터페이스
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE]; //오류메시지를 저장하기 위한 버퍼

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); // 네트워크 인터페이스 열고 핸들러를 반환(1:promiscuous, 1:1m/s)
	
	// 핸들러 검증
	handlerValidate(handle, dev, errbuf);
	
	// 자신의 맥주소(Attacker) 추출
	char * my_mac = getAttackerMac(argv[1]);
	printf("MY MAC %s\n", my_mac);
	
    /*
	int i=2;
	for(i=2; i<argc; i+=2){
    	
        Mac sender_mac = send_arp(handle, my_mac, "192.168.0.106", argv[i]);
		Mac target_mac = send_arp(handle, my_mac,  "192.168.0.106", argv[i+1]);	
		arp_attack(handle, Mac(my_mac),sender_mac, argv[i], argv[i+1]); 		
		std::thread relay_thread(packet_relay, handle, Mac(my_mac), target_mac, sender_mac, argv[i], argv[i+1]);
        std::thread recover_thread(recover_check, handle, Mac(my_mac), target_mac, sender_mac, argv[i], argv[i+1]);
		
		relay_thread.join();
		
		recover_thread.join();
		}
	*/
    free(my_mac);
	pcap_close(handle);
}

