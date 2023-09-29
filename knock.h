#ifndef KNOCK_H
#define KNOCK_H

#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <vector>
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <sstream>
#include <vector>
#include <string>
#include "Port_talker.h"


// Function declarations
std::vector<int> getPortsList(const std::string& s);
int knockOnPort(const char* ipAddress, int port, uint32_t signature, const char* secretPhrase, const char* secretPorts);

#endif //KNOCK_H
