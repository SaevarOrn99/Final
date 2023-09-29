#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

#include <cstdlib>
#include <unistd.h> // this header defines miscellaneous symbolic constants and types, and declares miscellaneous functions
#include <sys/socket.h> // defines the following macros to gain access to the data arrays in the ancillary data associated with a message header
#include <netinet/in.h> // defines the IN6ADDR_ANY_INIT macro
#include <netinet/ip.h> // defines the in_addr structure
#include <netinet/udp.h> // defines the udp header structure
#include <arpa/inet.h> //
#include <netinet/tcp.h>  
#include <iostream> //declares objects that control reading from and writing to the standard streams
#include <sstream> // defines the stringstream structure
#include <cstring> //tracks the string 
#include <string> // defines the string structure
#include <vector>  // This is necessary because you're using std::vector in the function prototype.

bool is_port_open(const char* ip, int port); // checks if a port is open
std::vector<int> get_open_ports(const char* ip, int start_port, int end_port); // gets the open ports

#endif // SCANNER_H