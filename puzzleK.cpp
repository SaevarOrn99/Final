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
    int signature;
    int secretPortOne;
    int secretPortTwo;
    char secretPhrase[1024];
};
secret s;
// A function that finds the port with the 
int getPort(std::vector<int> ports, const char* ip, int part) {
    int udpsock = createUDPSocket();
    if (udpsock < 0) {
        perror("Error creating UDP socket");
        return -1;
    } 
        // Look for the port that sends the 
    for (int port : ports) {
        
        std::cout << port << std::endl;
        struct sockaddr_in serverAddr;
        configureServerAddr(serverAddr, ip, port);
        if (!sendUDPMessage(udpsock, "Hi", strlen("Hi"), serverAddr)) {
            perror("Error sending data");
            close(udpsock);
            continue; // continue to the next port
        }
        
        char recvBuffer[1024] = "";
        int recvBytes = receiveUDPMessage(udpsock, recvBuffer, sizeof(recvBuffer), serverAddr);
        if (recvBytes > 0) {
            if (part == 1 && strstr(recvBuffer, "Greetings from S.E.C.R.E.T")) {
                std::cout << "\nReceived message from port " << port << ": " << recvBuffer << std::endl;
                close(udpsock);
                return port;
            } else if (part == 2 && strstr(recvBuffer, "Hello group 99! To get the secret phrase, reply to this message with a UDP message where the payload is a encapsulated")) {
                std::cout << "\nReceived message from port " << port << ": " << recvBuffer << std::endl;
                close(udpsock);
                return port;
            } else continue;
            
        } else continue;  
    }
    std::cerr << "Error getting port" << std::endl;
    return -1;
    
}


int main(int argc, char* argv[]) {
    uint8_t groupNo = 99; 
    uint32_t secret = 0xbdcedd8c;
    const char* ipAddress = argv[1];
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] << " <IP address> <port 1> <port 2> <port 3> <port 4>" << std::endl;
        return -1;
    }
    
    // Append the four ports in a list. argument count is 6
    std::vector<int> openPorts;
    for (int i = 2; i <= 5; i++) {
        openPorts.push_back(std::atoi(argv[i]));
    }

    // Number of ports is four, now print them out 
    for (int port : openPorts) {
        std::cout << "Port " << port << " is open" << std::endl;
    }

    std::cout << "\n --------- Part 1: Get the secret signature ---------\n" << std::endl;
    // Hér kemur virknin úr Port_talker.cpp

    int signaturePort = getPort(openPorts, ipAddress, 1); //
    if (signaturePort < 0) {
        return -1;
    }
    
    std::cout << signaturePort << std::endl;

    auto result = getSignature(ipAddress, signaturePort, secret, groupNo);
    
    s.signature = result.second;
    s.secretPortOne = result.first;
    std::cout << "signature&secretport: " << ntohl(s.signature) << " --- " << s.secretPortOne << std::endl;
    // Hér skilum við secret port twö

    std::cout << "\n --------- Part 2: Get the secret phrase ---------\n" << std::endl;
    // Hér kemur virknin í ipv4.cpp og við skilum secret phrase
    int secretPhrasePort = getPort(openPorts, ipAddress, 2);
    std::cout << secretPhrasePort << std::endl;
    

    // hér skilum við secret phrase

    // hér bönkum við og klárum þetta
    

    return 0;
}