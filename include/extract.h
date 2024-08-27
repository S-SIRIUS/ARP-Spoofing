#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"
#include <pcap.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

char* getAttackerMac(const char* iface);
char* getAttackerIP(const char* iface);
Mac sendArp(pcap_t *handle, const char* my_mac, const char* attacker_ip, const char* sender_ip);
