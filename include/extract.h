#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

char* getAttackerMac(const char* iface);
Mac send_arp(pcap_t *handle, const char* my_mac, const char* attacker_ip, const char* sender_ip);