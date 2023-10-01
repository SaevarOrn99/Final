// Authors: Katrín Ósk Kristinsdóttir and Sævar Örn Valsson
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include "Port_scanner.h"

// Function to check if a port is open
bool is_port_open(const char* ip, int port) { // checks if port are open
    struct sockaddr_in serverAddr; 
    int sockfd;

    // Create UDP socket
    if ((sockfd = socket(AF_INET ,SOCK_DGRAM ,IPPROTO_UDP)) < 0) { // creates UDP socket
        perror("Could not create socket");
        return(-1);
    }
    memset(&serverAddr, 0, sizeof(serverAddr)); // Zero out memory of address struct 
    // Configure settings in address struct
    serverAddr.sin_family = AF_INET; // IPv4
    serverAddr.sin_port = htons(port); // Port to scan
    serverAddr.sin_addr.s_addr = inet_addr(ip); // assigns the ip to the sin struct
    

    // Set timeout for socket to wait for a reply
    struct timeval timeout; // sets timeout for socket
    timeout.tv_sec = 0;  // 
    timeout.tv_usec = 200000; // 200000 microseconds = 0.2 seconds
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) { // sets timeout for socket
        perror("Error setting options");
        return false;
    }



    char buffer[10] = "test"; // string message to send
    if (sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) { // sends the message
        perror("Error sending data");
        return false;
    }  

    char recvBuffer[100];
    socklen_t addr_size = sizeof(serverAddr); // size of address struct
    int recvBytes = recvfrom(sockfd, recvBuffer, 100, 0, (struct sockaddr*)&serverAddr, &addr_size); // receives data

    if (recvBytes > 0) // if we receive data return true
        return true;

    close(sockfd);

    // If we received a reply, then the port might be open.
    // (But note, UDP is connectionless and stateless, so a lack of response doesn't necessarily mean a port is closed)

    return false;
}

std::vector<int> get_open_ports(const char* ip, int start_port, int end_port) { // gets open ports
    std::vector<int> open_ports;  // vector to store open ports
    for (int port = start_port; port <= end_port; port++) { // goes through all the ports
        if (is_port_open(ip, port)) {
            open_ports.push_back(port);
        }
    }
    return open_ports;
}