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
#include <cstdio>
#include <vector>
#include "Port_scanner.h"
#include "Port_talker.h"
#include "ipv4.h"
#include "knock.h"


struct secret {
    u_int32_t signature;
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
            } else if (part == 2 && strstr(recvBuffer, "Send me a 4-byte message containing the signature you got from S.E.C.R.E.T in the first 4 bytes (in network byte order).")) {
                std::cout << "\nReceived message from port " << port << ": " << recvBuffer << std::endl;
                close(udpsock);
                return port;
            } else if (part == 3 && strstr(recvBuffer, "Greetings! I am E.X.P.S.T.N, which stands for \"Enhanced X-link Port Storage Transaction Node\".")) {
                std::cout << "\nReceived message from port " << port << ": " << recvBuffer << std::endl;
                close(udpsock);
                return port;
            }
        }
    }
    std::cerr << "Error getting port" << std::endl;
    return -1;
    
}


int main(int argc, char* argv[]) {
    uint8_t groupNo = 99; // our group number
    uint32_t secret = 0xbdcedd8c; // our group secret
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

    std::cout << "\n ----------- Part 1: Get secret port no. 1 -----------\n" << std::endl;
    // Hér kemur virknin úr Port_talker.cpp

    int signaturePort = getPort(openPorts, ipAddress, 1); //
    if (signaturePort < 0) {
        return -1;
    }
    
    std::cout << signaturePort << std::endl;

    auto result = getSignature(ipAddress, signaturePort, secret, groupNo);
    
    s.signature = result.second;
    s.secretPortOne = result.first;
    s.secretPortTwo = 4070;
    if (s.signature == 0 || s.secretPortOne == 0) {
        std::cerr << "Error getting signature" << std::endl;
        return -1;
    }
    
    // Hér skilum við secret port twö
    std::cout << "\n ----------- Part 2: Get secret port no. 2 -----------\n" << std::endl;
    //SÆÆÆÆÆVAAAAARRR


    std::cout << "\n ----------- Part 3: Get the secret phrase -----------\n" << std::endl;
    // Hér kemur virknin í ipv4.cpp og við skilum secret phrase
    int secretPhrasePort = getPort(openPorts, ipAddress, 2);
    std::string secretPhrase =  getSecretPhrase(ipAddress, secretPhrasePort, s.signature);

    strncpy(s.secretPhrase, secretPhrase.c_str(), sizeof(s.secretPhrase) - 1);
    s.secretPhrase[sizeof(s.secretPhrase) - 1] = '\0'; // here is the secret phrase
    
    //if (secretPhrase == "error") {
      //  return -1;
    //}
    //s.secretPhrase = secretPhrase;
    
    std::cout << "\n ----------- Part 4: Knocking on heaven's door -----------\n" << std::endl;
    char secretPortBuffer[256];
    snprintf(secretPortBuffer, sizeof(secretPortBuffer), "%d,%d", s.secretPortOne, s.secretPortTwo);
    std::cout << "Portin splæsuð saman: " << secretPortBuffer << std::endl;
    
    int knockPort = getPort(openPorts, ipAddress, 3); // Getting port for part 4
    if (knockPort < 0) {
        return -1;
    }
    if (knockOnPort(ipAddress, knockPort, s.signature, s.secretPhrase, secretPortBuffer) < 0) {
        return -1;
    }
    

    // hér bönkum við og klárum þetta
    

    return 0;
}