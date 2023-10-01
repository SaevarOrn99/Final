// Authors: Katrín Ósk Kristinsdóttir and Sævar Örn Valsson
#include <cstdlib>
#include <unistd.h> // this header defines miscellaneous symbolic constants and types, and declares miscellaneous functions
#include <sys/socket.h> // defines the following macros to gain access to the data arrays in the ancillary data associated with a message header
#include <netinet/in.h> // defines the IN6ADDR_ANY_INIT macro
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <regex>
#include <utility> // For std::pair
#include <iostream> //declares objects that control reading from and writing to the standard streams
#include <cstring> //tracks the string length for faster performance, but it also retains the NULL character in the stored character data to support conversion to LPCWSTR
#include "Port_talker.h"
#include <string>

int createUDPSocket() { // Creates a UDP socket
    int udpsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // creates a UDP Socket
    if (udpsock < 0) {
        perror("Error creating UDP socket ");
    }
    return udpsock;
}

void configureServerAddr(struct sockaddr_in &serverAddr, const char* ip, int port) { // Configures the server address
    memset(&serverAddr, 0, sizeof(serverAddr));  // Zero out memory of address struct
    serverAddr.sin_family = AF_INET; // IPv4
    serverAddr.sin_port = htons(port); // set the port number
    inet_pton(AF_INET, ip, &serverAddr.sin_addr); // set the ip address 
}

bool setSocketTimeout(int socket, int seconds, int microseconds) { // Sets the socket timeout
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = microseconds;
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) >= 0;
}

// Function that sends an UDP messages
bool sendUDPMessage(int udpsock, const char* msg, size_t msgSize, const struct sockaddr_in &serverAddr) { // Sends a UDP message 
    return sendto(udpsock, msg, msgSize, 0, (const struct sockaddr*)&serverAddr, sizeof(serverAddr)) >= 0; 
}


int receiveUDPMessage(int udpsock, char *buffer, size_t bufSize, struct sockaddr_in &serverAddr) { // Receives a UDP message
    if (!setSocketTimeout(udpsock, 0, 100000)) {
        return -1;
    }
    socklen_t addr_size = sizeof(serverAddr); // Size of the address
    int bytes = recvfrom(udpsock, buffer, bufSize, 0, (struct sockaddr*)&serverAddr, &addr_size); // Receive message
    if (bytes > 0) {
        buffer[bytes] = '\0'; // Null-terminate the received string 
    }
    return bytes;
}



// This gets a pair of the secret port and the signature
std::pair<int, uint32_t> getSignature(const char* ip, int port, uint32_t secret, u_int8_t groupNo) { 
    int udpsock = createUDPSocket(); // Creates a UDP socket
    if (udpsock < 0) return {0, 0};
    u_int32_t signature; // Signature
    struct sockaddr_in serverAddr; // Server address
    configureServerAddr(serverAddr, ip, port); // Configures the server address

    if (!setSocketTimeout(udpsock, 0, 100000)) { // Sets the socket timeout
        perror("Error setting options");
        close(udpsock); 
        return {0, 0};  
    }
    
    if (sendto(udpsock, &groupNo, sizeof(groupNo), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) { // Sends the group number
        perror("Error sending group number");
        close(udpsock); 
        return {-1, 0}; 
    }

    uint32_t fourByteChallenge; // Four byte challenge
    int msgBytes = receiveUDPMessage(udpsock, (char*) &fourByteChallenge, sizeof(fourByteChallenge), serverAddr); // Receives the four byte challenge
         
    if (msgBytes == sizeof(fourByteChallenge)) { // If the message bytes is equal to the size of the four byte challenge
        fourByteChallenge = ntohl(fourByteChallenge); // Converts the four byte challenge to host byte order
        std::cout << "Received second message from port no. " << port << ": " << fourByteChallenge << std::endl;
        

        signature = fourByteChallenge ^ secret; // htonl(3164325502 ^ 0xbdcedd8c)
        uint32_t new_signature = htonl(signature); 

        uint8_t fiveByteMessage[5]; // Five byte message
        fiveByteMessage[0] = groupNo; // Group number
        memcpy(&fiveByteMessage[1], &new_signature, sizeof(new_signature)); // Copies the new signature to the five byte message

        
        if (sendto(udpsock, fiveByteMessage, sizeof(fiveByteMessage), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) { // Sends the five byte message
            perror("Error sending signature");
            close(udpsock);
            return {-1, 0};
        }

        char portBuffer[1024]; // Port buffer
        int finalBytes = receiveUDPMessage(udpsock, portBuffer, sizeof(portBuffer), serverAddr); // Receives the final message
        if(finalBytes > 0) {
            int  secretPort = 0;
            sscanf(portBuffer, "Well done group %*d. You have earned the right to know the port: %d!", &secretPort); // ná í Port 4066
            std::cout << "Received final message from port no. " << port << ": " << portBuffer << std::endl;
            close(udpsock); // Closes the socket
            return {secretPort, new_signature}; // Returns the secret port and the new signature
        } else {
            std::cerr << "Failed to get final response." << std::endl; // Prints out an error message
            close(udpsock); 
            return {-1, 0}; 
        }  
    } else {
        std::cerr << "Failed to get second message." << std::endl;
        close(udpsock);
        return {-1, 0};
    }

    close(udpsock); 
    return {0, 0}; 
}
