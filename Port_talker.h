#ifndef PORT_TALKER_H
#define PORT_TALKER_H

#include <cstdlib> // this header defines miscellaneous symbolic constants and types, and declares miscellaneous functions
#include <unistd.h> // this header defines miscellaneous symbolic constants and types, and declares miscellaneous functions
#include <sys/socket.h> // defines the following macros to gain access to the data arrays in the ancillary data associated with a message header
#include <netinet/in.h> // defines the IN6ADDR_ANY_INIT macro
#include <netinet/ip.h> // defines the in_addr structure
#include <arpa/inet.h> // defines the in_addr structure
#include <utility> // defines the pair structure
#include <regex> // defines the regex structure 
#include <netinet/tcp.h> // defines the tcp header structure
#include <iostream>  //declares objects that control reading from and writing to the standard streams
#include <cstring> //tracks the string length for faster performance, but it also retains the NULL character in the stored character data to support conversion to LPCWSTR 
#include <string> // defines the string structure

int createUDPSocket(); // creates a UDP socket

void configureServerAddr(struct sockaddr_in &serverAddr, const char* ip, int port); // configures the server address

bool setSocketTimeout(int socket, int seconds, int microseconds); // sets the socket timeout

bool sendUDPMessage(int udpsock, const char* msg, size_t msgSize, const struct sockaddr_in &serverAddr); // sends a UDP message

int receiveUDPMessage(int udpsock, char *buffer, size_t bufSize, struct sockaddr_in &serverAddr); // receives a UDP message

std::pair<int, uint32_t> getSignature(const char* ip, int port, uint32_t secret, u_int8_t groupNumber); // gets the signature

#endif // UDP_UTILITIES_H
