#include <stdio.h>      // sprintf, printf
#include <stdlib.h>     // malloc, free
#include <string.h>     // strncpy
#include <sys/socket.h> // socket, AF_INET
#include <sys/ioctl.h>  // ioctl
#include <net/if.h>     // ifreq 구조체와 SIOCGIFHWADDR
#include <unistd.h>     // close 함수
#include <pcap.h>           // pcap 관련 함수들

#include "mac.h"
#include "ip.h"
#include "arphdr.h"
#include "ethhdr.h"
#include "extract.h"

// Attacker 맥주소 추출
char* getAttackerMac(const char* iface)
{
	int fd;
    struct ifreq ifr; //ifreq 구조체 생성
    char *macAddress = (char *)malloc(18); // 6바이트 메모리 공간 생성

	// 인터페이스 정보를 얻기 위해 소켓을 생성
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET; // IPv4 주소체계 지정
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1); // 입력받은 인터페이스 이름 구조체 안에 복사

    ioctl(fd, SIOCGIFHWADDR, &ifr); // 인터페이스의 맥주소(하드웨어주소)를 가지고 옴 -> 결과는 ifr구조체에 저장

    close(fd); // 소켓닫기

    unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data; // 맥주소 추출
    
    sprintf(macAddress, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); // 지정된 형식으로 출력

    return macAddress; // 맥주소 반환
}

// Attacker ip 주소 추출
char* getAttackerIP(const char* iface) {
    int fd;
    struct ifreq ifr;
    char *ipAddress = (char *)malloc(INET_ADDRSTRLEN); // IPv4 주소의 문자열을 저장할 공간 할당

    // 인터페이스 정보를 얻기 위해 소켓 생성
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET; // IPv4 주소 체계 지정
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1); // 입력받은 인터페이스 이름을 구조체에 복사

    ioctl(fd, SIOCGIFADDR, &ifr); // 인터페이스의 IP 주소를 가져옴 -> 결과는 ifr 구조체에 저장

    close(fd); // 소켓 닫기

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    unsigned char *ip = (unsigned char *)&ipaddr->sin_addr.s_addr; // IP 주소를 바이트 단위로 접근

    sprintf(ipAddress, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

    return ipAddress; // IP 주소 반환
}

// Sender, Target Mac 주소 추출
Mac sendArp(pcap_t *handle, const char* my_mac, const char* attacker_ip, const char* sender_ip)
{
    EthArpPacket packet; // 1) 이더넷 헤더 + 2) ARP 헤더
    struct pcap_pkthdr *header;
    const u_char *response;

    // 이더넷 헤더
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // 목적지 맥을 브로드캐스트 주소로 설정
    packet.eth_.smac_ = Mac(my_mac); // 소스 맥은 자신의 맥주소로 설정   
    packet.eth_.type_ = htons(EthHdr::Arp); // type을 ARP 프로토콜로 설정

    // ARP 헤더
    packet.arp_.hrd_ = htons(ArpHdr::ETHER); //하드웨어 타입 이더넷
    packet.arp_.pro_ = htons(EthHdr::Ip4); // 프로토콜 타입 ipv4
    packet.arp_.hln_ = Mac::SIZE; // 맥주소 길이
    packet.arp_.pln_ = Ip::SIZE; // IP 주소 길이
    packet.arp_.op_ = htons(ArpHdr::Request); // ARP Request
    packet.arp_.smac_ = Mac(my_mac); // 요청자의 맥주소  
    packet.arp_.sip_ = htonl(Ip(attacker_ip)); // 요정자의 ip주소 
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // 대상의 맥주소(알수없음 아직: 00~으로 표기)
    packet.arp_.tip_ = htonl(Ip(sender_ip)); //  대상의 ip 주소

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)); // 네트워크에 ARP Request 패킷 전송

    // 실패시   
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // 무한루프 돌면서 ARP Reply 패킷 기다림
    while (1) {
        int pcap_next_res = pcap_next_ex(handle, &header, &response);
        if (pcap_next_res == 1) {// 정상적으로 패킷 수신시
            EthArpPacket *recv_packet = (EthArpPacket *)response; // EthArpPacket 구조체로 타입 캐스팅
            if (ntohs(recv_packet->eth_.type_) == EthHdr::Arp && // 받은 패킷의 type이 ARP 이고
                ntohs(recv_packet->arp_.op_) == ArpHdr::Reply && // 받은 패킷의 ARP가 Reply 이고
                recv_packet->arp_.sip_ == packet.arp_.tip_ &&  // 받은 패킷의 source ip가 우리가 지정한 target ip 이고
                recv_packet->arp_.tip_ == packet.arp_.sip_) { // 받은 패킷의 target ip가 내 ip 이면
                return recv_packet->arp_.smac_; // 빋은 패킷의 soure mac 반환 (찾고자하는 타겟의 맥주소)
            }
        } else if (pcap_next_res == -1 || pcap_next_res == -2) { // 패킷 수신중 오류(-1)거나 타임아웃(-2) 발생시
            printf("Error or Timeout reading the response: %s\n", pcap_geterr(handle)); // 오류 메시지 출력
            return Mac::nullMac(); // 무효한 MAC 주소 반환
        }
    }
}
