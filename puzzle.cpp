#include <cstdlib>
#include <unistd.h> // this header defines miscellaneous symbolic constants and types, and declares miscellaneous functions
#include <sys/socket.h> // defines the following macros to gain access to the data arrays in the ancillary data associated with a message header
#include <netinet/in.h> // defines the IN6ADDR_ANY_INIT macro
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <iostream> //declares objects that control reading from and writing to the standard streams
#include <sstream>
#include <cstring> //tracks the string 
#include <string>
#include <vector>
#include "Port_scanner.h"
#include "Port_talker.h"

struct secret {
    int signature; // Note: corrected spelling of "signature"
    int secretPortOne;
    int secretPortTwo;
    char secretPhrase[1024];
};


secret s;
// A function that finds the port with the 
int getSignaturePort(std::vector<int> ports, const char* ip) {
    int udpsock = createUDPSocket();
    if (udpsock < 0) {
        perror("Error creating UDP socket");
        return -1;
    } 

    // Now look for the port that sends the 
    for (int port : ports) {
        struct sockaddr_in serverAddr;
        configureServerAddr(serverAddr, ip, port);
        if (!sendUDPMessage(udpsock, "Hi", strlen("Hi"), serverAddr)) {
            perror("Error sending data");
            close(udpsock);
            return -1;
        }
        
        char recvBuffer[1024];
        int recvBytes = receiveUDPMessage(udpsock, recvBuffer, sizeof(recvBuffer), serverAddr);
        if (recvBytes > 0) {
            
            if (strstr(recvBuffer, "Greetings from S.E.C.R.E.T")) {
                std::cout << "\nReceived message from port " << port << ": " << recvBuffer << std::endl;
                close(udpsock);
                return port;
            }
        }
    }
    perror("No Signature port found.");
    close(udpsock);
    return -1; 
}


int main(int argc, char* argv[]) {
    uint8_t groupNo = 99; 
    uint32_t secret = 0xbdcedd8c;
    const char* ipAddress = argv[1];
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <IP address> <low port> <high port>" << std::endl;
        return -1;
    }
    
    // Scan the open ports and add to a list
    std::vector<int> openPorts = get_open_ports(argv[1], std::atoi(argv[2]), std::atoi(argv[3]));
    // Check if the number of ports is four
    if (openPorts.size() != 4) {
        perror("Could not scan four ports. For this puzzle to be solved at lease four ports need to be open.");
        return -1; // break the function    
    }
    // Number of ports is four, now print them out 
    for (int port : openPorts) {
        std::cout << "Port " << port << " is open" << std::endl;
    }

    //////// 1. GET THE SECRET SIGNATURE ////////
    int signaturePort = getSignaturePort(openPorts, ipAddress); //
    if (signaturePort < 0) {
        return -1;
    }
    std::cout << signaturePort << std::endl;
    auto result = getSignature(ipAddress, signaturePort, secret, groupNo);
    s.secretPortOne = result.first; // skilar secret port one
    s.signature = result.second; // skilar signature
    //s.secretPortOne = getSignature(ipAddress, signaturePort); // setur the secret port one jafnt og portið
    




    // Hér skilum við signiture 
    
    // Hér skilum við secret port twö

    // hér skilum við secret phrase 

    // hér bönkum við og klárum þetta
    

    return 0;
}