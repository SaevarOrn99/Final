
#ifndef IPV4_H
#define IPV4_H
#include <cstdlib>
#include <unistd.h> // this header defines miscellaneous symbolic constants and types, and declares miscellaneous functions
#include <sys/socket.h> // defines the following macros to gain access to the data arrays in the ancillary data associated with a message header
#include <netinet/in.h> // defines the IN6ADDR_ANY_INIT macro
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <iostream> //declares objects that control reading from and writing to the standard streams
#include <cstring> //tracks the string length for faster performance, but it also retains the NULL character in the stored character data to support conversion to LPCWSTR
#include <cstdint>
#include <string>
#include "Port_talker.h"
// Define the structure of a UDP header
struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t len;
    uint16_t checksum;
};
// Define the structure of a pseudo header
struct pseudo_header {
    struct in_addr src;
    struct in_addr dest;
    uint8_t zero; // placeholder for the zero byte
    uint8_t protocol; 
    uint16_t udp_length;
};

// Function declarations

uint16_t computeChecksum(const char *buffer, int len); // computes the checksum
std::string getSecretPhrase(const char* ip, int port, uint32_t signature); // gets the secret phrase
// Add any other relevant functions, structs, or constants here...

#endif // IPV4_H
