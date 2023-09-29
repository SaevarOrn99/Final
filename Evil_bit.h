#ifndef EVIL_BIT_H
#define EVIL_BIT_H

#include <cstdlib> // this header defines miscellaneous symbolic constants and types, and declares miscellaneous functions
#include <unistd.h> // this header defines miscellaneous symbolic constants and types, and declares miscellaneous functions
#include <sys/socket.h> // defines the following macros to gain access to the data arrays in the ancillary data associated with a message header
#include <netinet/in.h> // defines the IN6ADDR_ANY_INIT macro
#include <netinet/ip.h> // defines the in_addr structure
#include <arpa/inet.h> 
#include <netinet/tcp.h> // defines the tcp header structure
#include <iostream> //declares objects that control reading from and writing to the standard streams
#include <cstring> //tracks the string length for faster performance, but it also retains the NULL character in the stored character data to support conversion to LPCWSTR
#include <string> // defines the string structure
#include <netinet/udp.h> // defines the udp header structure
#include <vector> // defines the vector structure

// Define the structure of a UDP header for Raw socket
struct udp_h {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t len;
    uint16_t checksum;
};
// Define the structure of a pseudo header for Raw socket
struct pseudo_header1 {
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

unsigned short csum(unsigned short *ptr, int nbytes); // computes the checksum
int getUDPpackageRaw(const char* ip, int port, u_int32_t XOR); // creates a raw socket and send a UDP package to get the secret port

#endif // EVIL_BIT_H