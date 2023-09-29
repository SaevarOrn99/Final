#ifndef KNOCK_H
#define KNOCK_H

#include <arpa/inet.h> // defines the in_addr structure
#include <unistd.h> // this header defines miscellaneous symbolic constants and types, and declares miscellaneous functions 
#include <netinet/ip.h> // 
#include <vector> // defines the vector structure
#include <iostream> //declares objects that control reading from and writing to the standard streams
#include <cstring> //tracks the string length for faster performance, but it also retains the NULL character in the stored character data to support conversion to LPCWSTR
#include <sys/socket.h> // defines the following macros to gain access to the data arrays in the ancillary data associated with a message header
#include <netinet/udp.h> // defines the udp header structure
#include <sstream> // defines the stringstream structure
#include <vector> // defines the vector structure
#include <string> // defines the string structure
#include "Port_talker.h" // defines the Port_talker structure


// Function declarations
std::vector<int> getPortsList(const std::string& s); // gets the ports list
int knockOnPort(const char* ipAddress, int port, uint32_t signature, const char* secretPhrase, const char* secretPorts); // knocks on a port

#endif //KNOCK_H
