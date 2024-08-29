#include <cstdio>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <thread>

void arpAttack(pcap_t *handle, Mac my_mac, Mac sender_mac, const char* sender_ip, const char* target_ip);
void recover_check(pcap_t *handle, Mac my_mac, Mac target_mac, Mac sender_mac, const char* sender_ip, const char* target_ip);
void packetRelay(pcap_t *handle, Mac my_mac, Mac target_mac, Mac sender_mac, const char* sender_ip, const char* target_ip);


