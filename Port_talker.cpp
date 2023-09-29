#include <cstdlib>
#include <unistd.h> // this header defines miscellaneous symbolic constants and types, and declares miscellaneous functions
#include <sys/socket.h> // defines the following macros to gain access to the data arrays in the ancillary data associated with a message header
#include <netinet/in.h> // defines the IN6ADDR_ANY_INIT macro
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <utility> // For std::pair
#include <iostream> //declares objects that control reading from and writing to the standard streams
#include <cstring> //tracks the string length for faster performance, but it also retains the NULL character in the stored character data to support conversion to LPCWSTR
#include "Port_talker.h"
#include <string>

int createUDPSocket() {
    int udpsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpsock < 0) {
        perror("Error creating UDP socket ");
    }
    return udpsock;
}

void configureServerAddr(struct sockaddr_in &serverAddr, const char* ip, int port) {
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serverAddr.sin_addr);
}

bool setSocketTimeout(int socket, int seconds, int microseconds) {
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = microseconds;
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) >= 0;
}

bool sendUDPMessage(int udpsock, const char* msg, size_t msgSize, const struct sockaddr_in &serverAddr) {
    return sendto(udpsock, msg, msgSize, 0, (const struct sockaddr*)&serverAddr, sizeof(serverAddr)) >= 0;
}


int receiveUDPMessage(int udpsock, char *buffer, size_t bufSize, struct sockaddr_in &serverAddr) {
    socklen_t addr_size = sizeof(serverAddr);
    int bytes = recvfrom(udpsock, buffer, bufSize, 0, (struct sockaddr*)&serverAddr, &addr_size);
    if (bytes > 0) {
        buffer[bytes] = '\0'; // Null-terminate the received string
    }
    return bytes;
}




std::pair<std::string, uint32_t> getSignature(const char* ip, int port, uint32_t secret, u_int8_t groupNumber) {
    int udpsock = createUDPSocket();
    if (udpsock < 0) return {"", 0};
    u_int32_t signature;
    std::cout << "Komst hér inn" << std::endl;
    struct sockaddr_in serverAddr;
    configureServerAddr(serverAddr, ip, port);

    if (!setSocketTimeout(udpsock, 1, 0)) {
        perror("Error setting options");
        close(udpsock);
        return {"-1", 0};
    }
    
    uint8_t groupNo = 99; 
    if (sendto(udpsock, &groupNo, sizeof(groupNo), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Error sending group number");
        close(udpsock);
        return {"-1", 0};
    }

    uint32_t fourByteChallenge; 
    int msgBytes = receiveUDPMessage(udpsock, (char*) &fourByteChallenge, sizeof(fourByteChallenge), serverAddr);
        
    if (msgBytes == sizeof(fourByteChallenge)) {
        fourByteChallenge = ntohl(fourByteChallenge);
        std::cout << "Received second message from port no. " << port << ": " << fourByteChallenge << std::endl;
        

        signature = fourByteChallenge ^ secret; // htonl(3164325502 ^ 0xbdcedd8c)
        uint32_t new_signature = htonl(signature);

        uint8_t fiveByteMessage[5];
        fiveByteMessage[0] = groupNumber; // Group number
        memcpy(&fiveByteMessage[1], &new_signature, sizeof(new_signature));

        if (sendto(udpsock, fiveByteMessage, sizeof(fiveByteMessage), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            perror("Error sending signature");
            close(udpsock);
            return {"-1", 0};
        }

        char secretPort[1024]; // 
        int finalBytes = receiveUDPMessage(udpsock, secretPort, sizeof(secretPort), serverAddr);
        if(finalBytes > 0) {
            std::cout << "Received final message from port no. " << port << ": " << secretPort << "\n---------------------------------------------------\n" << std::endl;
            close(udpsock);
            return {std::string(secretPort), new_signature};
        } else {
            std::cerr << "Failed to get final response." << std::endl;
            close(udpsock);
            return {"-1", 0};
        }  
    } else {
        std::cerr << "Failed to get second message." << std::endl;
        close(udpsock);
        return {"-1", 0};
    }

    close(udpsock);
    return {"0", 0}; 
}
