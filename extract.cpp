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

// Sender, Target Mac 주소 추출
Mac send_arp(pcap_t *handle, const char* my_mac, const char* attacker_ip, const char* sender_ip)
{
    EthArpPacket packet;
    struct pcap_pkthdr *header;
    const u_char *response;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(my_mac);  
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac);  
    packet.arp_.sip_ = htonl(Ip(attacker_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (1) {
        int pcap_next_res = pcap_next_ex(handle, &header, &response);
        if (pcap_next_res == 1) {
            EthArpPacket *recv_packet = (EthArpPacket *)response;
            if (ntohs(recv_packet->eth_.type_) == EthHdr::Arp && 
                ntohs(recv_packet->arp_.op_) == ArpHdr::Reply &&
                recv_packet->arp_.sip_ == packet.arp_.tip_ && 
                recv_packet->arp_.tip_ == packet.arp_.sip_) {
                    
                return recv_packet->arp_.smac_;
            }
        } else if (pcap_next_res == -1 || pcap_next_res == -2) {
            printf("Error or Timeout reading the response: %s\n", pcap_geterr(handle));
            return Mac::nullMac();
        }
    }
}
