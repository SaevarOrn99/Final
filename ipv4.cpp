#include <cstdlib>
#include <unistd.h> // this header defines miscellaneous symbolic constants and types, and declares miscellaneous functions
#include <sys/socket.h> // defines the following macros to gain access to the data arrays in the ancillary data associated with a message header
#include <netinet/in.h> // defines the IN6ADDR_ANY_INIT macro
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <iostream> //declares objects that control reading from and writing to the standard streams
#include <cstring> //tracks the string length for faster performance, but it also retains the NULL character in the stored character data to support conversion to LPCWSTR
// Define the structure of a UDP header
struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t len;
    uint16_t checksum;
};

struct pseudo_header {
    struct in_addr src;
    struct in_addr dest;
    uint8_t zero; // placeholder for the zero byte
    uint8_t protocol; 
    uint16_t udp_length;
};

uint16_t computeChecksum(const char *buffer, int len) {
    uint32_t computedChecksum = 0;
    const uint16_t *word;

    // Go through every word (2 bytes) and add to computedChecksum
    for (word = (const uint16_t *)buffer; len > 1; len -= 2, word++) {
        computedChecksum += *word;
    }
    // If there's a byte left over, we pad it with zeros and then add to computedChecksum
    if (len) {
        uint16_t lastByte = *(const uint8_t *)word << 8;  // Left shift to make it the high byte
        computedChecksum += lastByte;
    }
    // While there's a carry, keep adding it back in
    while (computedChecksum >> 16) {
        computedChecksum = (computedChecksum & 0xFFFF) + (computedChecksum >> 16);
    }
    return ~computedChecksum;  // Return the one's complement of the sum
}


std::string getSecretPhrase(const char* ip, int port, uint32_t signature) {
    struct sockaddr_in serverAddr;
    int udpsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpsock < 0) {
        perror("Error creating UDP socket ");
    }
    if (udpsock < 0) {
        return "error"; // If error creating an udp socket
    }
    // Configure settings in address struct
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serverAddr.sin_addr);
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    // Set timeout for socket to wait for a reply
    if (setsockopt(udpsock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Error setting options");
        close(udpsock);
        return "error";
    }

    if (sendto(udpsock, &signature, sizeof(signature), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Error sending data");
        close(udpsock);
        return "error";
    } 
    char recvBuffer[1024];
    socklen_t addr_size = sizeof(serverAddr);
    int recvBytes = recvfrom(udpsock, recvBuffer, 1024, 0, (struct sockaddr*)&serverAddr, &addr_size);

    if (recvBytes < 0) {
        perror("Error receiving data");
    }
    recvBuffer[recvBytes] = '\0'; // Add null-terminator
    std::cout << "Received message: " << recvBuffer << std::endl;

    // Now ectract the last 6 bytes and place them in required checksum and ip
    int length = strlen(recvBuffer);
    if(length >= 6) {
        uint8_t *lastSixBytes = (uint8_t *)&recvBuffer[length - 6]; // Extracting the last 6 bytes
        
        // Extracting the checksum from the first 2 bytes and converting it from network byte order
        
        uint16_t requiredChecksum = *((uint16_t *)lastSixBytes);
        
        struct in_addr addr;
        memcpy(&addr, &lastSixBytes[2], 4); // Copy the 4 bytes for the IPv4 address
        char *requiredIP = inet_ntoa(addr); // Converting the binary address to a string
        // Printing the extracted values
        std::cout << "Extracted checksum: 0x" << std::hex << requiredChecksum << std::endl;
        std::cout << "Extracted source address: " << requiredIP << std::endl;

        // Create UDP pseudo-header for checksum calculation
        struct pseudo_header ph;
        ph.src.s_addr = inet_addr(requiredIP);
        ph.dest.s_addr = serverAddr.sin_addr.s_addr;
        ph.zero = 0;
        ph.protocol = IPPROTO_UDP;
        ph.udp_length = htons(sizeof(udp_header) + sizeof(signature));  // Signature is payload

        // Create UDP header
        struct udp_header udp;
        udp.src_port = htons(rand() % 65535);  // Use any source port
        udp.dest_port = serverAddr.sin_port;
        udp.len = ph.udp_length;
        

        // Create buffer for checksum calculation
        char buf[sizeof(pseudo_header) + sizeof(udp_header) + sizeof(signature)];
        
        udp.checksum = 0;  // Set to 0 initially for calculation
        memcpy(buf, &ph, sizeof(pseudo_header));
        memcpy(buf + sizeof(pseudo_header), &udp, sizeof(udp_header));
        memcpy(buf + sizeof(pseudo_header) + sizeof(udp_header), &signature, sizeof(signature));

        // Calculate UDP checksum including the pseudo header
        uint16_t calculated_checksum = computeChecksum(buf, sizeof(buf));

        // If the checksum isn't correct, change the source port or data slightly and recompute until it matches.
        int attempts = 0;
        while (calculated_checksum != requiredChecksum ) { //&& attempts < 65535
            udp.src_port = htons(rand() % 65535);
            // repeat the buffer creation and checksum calculation process untill it matches the required one
            memcpy(buf + sizeof(pseudo_header), &udp, sizeof(udp_header));
            calculated_checksum = computeChecksum(buf, sizeof(buf));
            
            if(attempts == 65535) {
                attempts = 0;
            }
            attempts++;
        }
        std::cout << "attempts: " << attempts << std::endl;
        if (attempts == 65535) {
            std::cerr << "Failed to generate packet with desired checksum after 65,535 attempts. Please, try again." << std::endl;
            return "error"; 
        }
        udp.checksum = calculated_checksum; //
        //uint8_t first = flipChecksum 
/////////// Now send the UDP packet
        char packet[sizeof(struct ip) + sizeof(udp_header) + sizeof(signature)]; // Signature as the payload

        struct ip *iph = (struct ip *)packet;
        udp_header *udph = (udp_header *)(packet + sizeof(struct ip));
        char *payload = packet + sizeof(struct ip) + sizeof(udp_header);

        // Fill the IP header fields
        iph->ip_v = 4;
        iph->ip_hl = 5;
        iph->ip_tos = 0;
        iph->ip_len = htons(sizeof(packet));
        iph->ip_id = 0;
        iph->ip_off = 0;
        iph->ip_ttl = 64;
        iph->ip_p = IPPROTO_UDP;
        iph->ip_sum = 0;  // Set to zero before calculating
        iph->ip_sum = computeChecksum((const char *)iph, sizeof(struct ip)); // ip checksum
        iph->ip_src.s_addr = inet_addr(requiredIP);
        iph->ip_dst.s_addr = serverAddr.sin_addr.s_addr;

        // Copy udp_header and payload into packet
        memcpy(udph, &udp, sizeof(udp));
        memcpy(payload, &signature, sizeof(signature));

        // Now send the packet
        if (sendto(udpsock, packet, sizeof(packet), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            perror("Error sending UDP packet.");
            close(udpsock);
            return "error";
        }
        char recvBufferTwo[1024];
        socklen_t addr_size = sizeof(serverAddr);
        int recvBytesTwo = recvfrom(udpsock, recvBufferTwo, 1024, 0, (struct sockaddr*)&serverAddr, &addr_size);
        
        if (recvBytesTwo < 0) {
            perror("Error receiving second data.");
        }
        recvBufferTwo[recvBytesTwo] = '\0'; // Add null-terminator
        std::cout << "Received second message: " << recvBufferTwo << std::endl;

        // Now extract the secret phrase
        char secretPhrase[512];
        if (sscanf(recvBufferTwo, "Congratulations group 99! Here is the secret phrase: \"%[^\"]", secretPhrase) == 1) {
            std::cout << "\nSecret Phrase: " << secretPhrase << std::endl;
            return std::string(secretPhrase);
        }
        perror("failed to extract secret phrase.");
        close(udpsock);
        return "error";

        
    }
    perror("Received message does not contain any checksum or source address");

    close(udpsock);
    // If we received a reply, then the port might be open.
    // (But note, UDP is connectionless and stateless, so a lack of response doesn't necessarily mean a port is closed)
    return "error";
}