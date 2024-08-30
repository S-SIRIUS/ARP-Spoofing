#include <cstdio>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>

#include "protocols/ethhdr.h"
#include "protocols/arphdr.h"

void arpInfect(pcap_t *handle, Mac my_mac, Mac sender_mac, const char* sender_ip, const char* target_ip);
void packetRelay(pcap_t *handle, Mac my_mac, Mac sender_mac, Mac target_mac, const char* sender_ip, const char* target_ip);
void recoveryCheck(pcap_t *handle, Mac my_mac, Mac sender_mac, Mac target_mac, const char* sender_ip, const char* target_ip);


