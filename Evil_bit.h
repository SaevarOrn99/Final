#ifndef EVIL_BIT_H
#define EVIL_BIT_H

#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <iostream>
#include <cstring>
#include <string>
#include <netinet/udp.h>
#include <vector>

struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t len;
    uint16_t checksum;
};

struct pseudo_header {
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

unsigned short csum(unsigned short *ptr, int nbytes);

int getUDPpackageRaw(const char* ip, int port, u_int32_t XOR, int assignedPort);

#endif // EVIL_BIT_H