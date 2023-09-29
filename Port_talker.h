#ifndef PORT_TALKER_H
#define PORT_TALKER_H

#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <utility>
#include <netinet/tcp.h>
#include <iostream>
#include <cstring>
#include <string>

int createUDPSocket();

void configureServerAddr(struct sockaddr_in &serverAddr, const char* ip, int port);

bool setSocketTimeout(int socket, int seconds, int microseconds);

bool sendUDPMessage(int udpsock, const char* msg, size_t msgSize, const struct sockaddr_in &serverAddr);

int receiveUDPMessage(int udpsock, char *buffer, size_t bufSize, struct sockaddr_in &serverAddr);

std::pair<std::string, uint32_t> getSignature(const char* ip, int port, uint32_t secret, u_int8_t groupNumber);

#endif // UDP_UTILITIES_H
