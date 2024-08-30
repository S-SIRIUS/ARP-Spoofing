#include "protocols/mac.h"
#include <pcap.h>

char* getAttackerMac(const char* iface);
char* getAttackerIP(const char* iface);
Mac sendArp(pcap_t *handle, const char* my_mac, const char* attacker_ip, const char* sender_ip);
