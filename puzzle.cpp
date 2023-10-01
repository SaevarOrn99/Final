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
#include "Evil_bit.h"


struct secret { // Struct for the secret for 
    u_int32_t signature; 
    int secretPortOne; 
    int secretPortTwo;
    char secretPhrase[1024]; 
};
secret s; // Global struct for the secret
// A function that finds the port with the 
int getPort(std::vector<int> ports, const char* ip, int part) { // Gets the port
    int udpsock = createUDPSocket(); // Creates a UDP socket
    if (udpsock < 0) { // If the socket is less than 0
        perror("Error creating UDP socket"); // Print error
        return -1; // Return -1
    } 
        // Look for the port that sends the 
    for (int port : ports) { // For each port in the ports vector
        struct sockaddr_in serverAddr; // Server address
        configureServerAddr(serverAddr, ip, port); // Configures the server address
        if (!sendUDPMessage(udpsock, "Hi", strlen("Hi"), serverAddr)) { // If the message is not sent
            perror("Error sending data"); // Print error
            close(udpsock); // Close the socket before returning
            continue; // continue to the next port
        }
        // checks the port for the message and assigns each part to the correct port
        char recvBuffer[1024] = ""; // Receive buffer
        int recvBytes = receiveUDPMessage(udpsock, recvBuffer, sizeof(recvBuffer), serverAddr); // Receive message
        if (recvBytes > 0) { // If the message is received
            if (part == 1 && strstr(recvBuffer, "Greetings from S.E.C.R.E.T")) { // If the message is the first part 
                std::cout << "\nReceived message from port " << port << ": " << recvBuffer << std::endl; // Print the message
                close(udpsock); // Close the socket before returning
                return port; // Return the port
            } else if (part == 2 && strstr(recvBuffer, "Send me a 4-byte message containing the signature you got from S.E.C.R.E.T in the first 4 bytes (in network byte order).")) {
                std::cout << "\nReceived message from port " << port << ": " << recvBuffer << std::endl;
                close(udpsock); // Close the socket before returning
                return port; // Return the port
            } else if (part == 3 && strstr(recvBuffer, "Greetings! I am E.X.P.S.T.N, which stands for \"Enhanced X-link Port Storage Transaction Node\".")) {
                std::string hexPort = std::to_string(port); 
                std::cout << "\nReceived message from port " << std::stoul(hexPort, nullptr, 16) << ": " << recvBuffer << std::endl;
                close(udpsock); 
                return port;
            } else if (part == 4 && strstr(recvBuffer, "The dark side of network programming is a pathway to many abilities")) {
                std::cout << "\nReceived message from port " << port << ": " << recvBuffer << std::endl;
                close(udpsock);
                return port;
            }
        }
    }
    std::cerr << "Error getting port" << std::endl;
    return -1;
    
}


int main(int argc, char* argv[]) { // Main function
    uint8_t groupNo = 99; // our group number
    uint32_t secret = 0xbdcedd8c; // our group secret
    const char* ipAddress = argv[1];
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] << " <IP address> <port 1> <port 2> <port 3> <port 4>" << std::endl;
        return -1;
    }
    // Append the four ports in a list. argument count is 6
    std::vector<int> openPorts; // Vector for the open ports
    for (int i = 2; i <= 5; i++) { // For each port
        openPorts.push_back(std::atoi(argv[i]));
    }

    // Number of ports is four, now print them out 
    for (int port : openPorts) { // For each port in the open ports vector
        std::cout << "Port " << port << " is open" << std::endl;
    }

    std::cout << "\n ----------- Part 1: Get secret port no. 1 -----------\n" << std::endl; 

    int signaturePort = getPort(openPorts, ipAddress, 1); // get signature port from getPort function
    if (signaturePort < 0) {
        return -1;
    }
    
    std::cout << signaturePort << std::endl;

    auto result = getSignature(ipAddress, signaturePort, secret, groupNo); // Gets the signature and a secret port
    
    s.signature = result.second; // Assigns the signature to the struct
    s.secretPortOne = result.first; // Assigns the secret port one to the struct
    
    if (s.signature == 0 || s.secretPortOne == 0) { // If the signature or the secret port one is 0
        std::cerr << "Error getting signature or getting the secret port" << std::endl; // Print error
        return -1; 
    }
    
    std::cout << "\n ----------- Part 2: Get secret port no. 2 -----------\n" << std::endl;
    
    
    int evilPort = getPort(openPorts, ipAddress, 4); // Getting port for part 2
    if (evilPort < 0) { // If the port is less than 0
        return -1; 
    }
    int secretPortTwo = getUDPpackageRaw(ipAddress , evilPort, s.signature); // Gets the secret port two
    s.secretPortTwo = secretPortTwo; // Assigns the secret port two to the struct
    
    if (s.secretPortTwo == 0) { // If the secret port two is 0
        std::cerr << "Error getting secret port two" << std::endl; // Print error
        return -1; 
    }
    
    
    std::cout << "\n ----------- Part 3: Get the secret phrase -----------\n" << std::endl;
    // Here comes the Checksum part
    
    int secretPhrasePort = getPort(openPorts, ipAddress, 2); // Getting port for part 3
    std::string secretPhrase =  getSecretPhrase(ipAddress, secretPhrasePort, s.signature); // Gets the secret phrase

    strncpy(s.secretPhrase, secretPhrase.c_str(), sizeof(s.secretPhrase) - 1); // Copies the secret phrase to the struct
    s.secretPhrase[sizeof(s.secretPhrase) - 1] = '\0'; // here is the secret phrase
    
    if (secretPhrase == "error") {
        return -1;
    }
    

    std::cout << "\n ----------- Part 4: Knocking on heaven's door -----------\n" << std::endl;

    char secretPortBuffer[256]; // Secret port buffer
    snprintf(secretPortBuffer, sizeof(secretPortBuffer), "%d,%d", s.secretPortOne, s.secretPortTwo); // Prints the secret port one and two to the secret port buffer
    
    int knockPort = getPort(openPorts, ipAddress, 3); // Getting port for part 4
    if (knockPort < 0) { // If the port is less than 0
        return -1;
    }
    if (knockOnPort(ipAddress, knockPort, s.signature, s.secretPhrase, secretPortBuffer) < 0) { // If the knocking on port fails
        return -1;
    }

    return 0;
}