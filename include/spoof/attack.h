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

void arpInfect(pcap_t *handle, Mac my_mac, Mac sender_mac, const char* sender_ip, const char* target_ip);
void packetRelay(pcap_t *handle, Mac my_mac, Mac sender_mac, Mac target_mac, const char* sender_ip, const char* target_ip);
void recoveryCheck(pcap_t *handle, Mac my_mac, Mac sender_mac, Mac target_mac, const char* sender_ip, const char* target_ip);


