// Authors: Katrín Ósk Kristinsdóttir and Sævar Örn Valsson
#include "Port_talker.h"
#include "knock.h"

std::vector<int> getPortsList(const std::string& s) { // Gets a list of ports from a string
    std::vector<int> ports; // Vector to store the ports
    std::stringstream stream(s); // Create a stringstream from the string
    std::string item; // String to store the item

    while (getline(stream, item, ',')) { // Split the string by commas
        ports.push_back(std::stoi(item)); // Add the port to the vector
    }
    return ports;
}
// Knocks on a port in specific order
int knockOnPort(const char* ipAddress, int port, uint32_t signature, const char* secretPhrase, const char* secretPorts) { 
    int udpsock = createUDPSocket(); // Creates a UDP socket

    //Configure settings in address struct
    struct sockaddr_in serverAddr;
    socklen_t addr_size = sizeof(serverAddr);
    configureServerAddr(serverAddr, ipAddress, port);

    //Setting options for sockets
    if (!setSocketTimeout(udpsock, 0, 200000)) {//Setting timeout to wait for a reply
        perror("Error setting options");
        close(udpsock);
        return -1;
    }
        //Sending secret ports as a string, comma separated
        if (sendto(udpsock, secretPorts, strlen(secretPorts), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) { // Send the secret ports
            perror("Error sending Ports");
            return -1;
        }
        //Receiving 
        char receiveBuffer_two[1024];
        int receiveBytes_two = recvfrom(udpsock, receiveBuffer_two, 1024, 0, (struct sockaddr*)&serverAddr, &addr_size); // Receive data

        //Check if we have received anything from the port, if so return true, the port is open
        if (receiveBytes_two < 0) {
            perror("Error receiving message after sending ");
            return -1;
        }

        receiveBuffer_two[receiveBytes_two] = '\0'; // Add null-terminator
        std::string hexPort = std::to_string(port); // convert port from hex to string
        std::cout << "Received sequence of knocks from port " << std::stoul(hexPort, nullptr, 16) << ": " << receiveBuffer_two << std::endl;



        // Now we have the order of knocks in the receiveBuffer_two
        // 1. Each "knock" must be paired with both a secret phrase and your unique S.E.C.R.E.T signature.
        // 2. The correct format to send a knock: First, 4 bytes containing your S.E.C.R.E.T signature, followed by the secret phrase.
        std::vector<int> ports = getPortsList(receiveBuffer_two); // A list of all the ports to knock on in the correct order

        // Construct the packet to send with the knocks
        size_t bufferSize = sizeof(signature) + strlen(secretPhrase); // Size of the buffer to send
        std::vector<uint8_t> knockBuffer(bufferSize); // Buffer to send
        memcpy(knockBuffer.data(), &signature, sizeof(signature)); // Copy the signature into the buffer
        memcpy(knockBuffer.data() + sizeof(signature), secretPhrase, strlen(secretPhrase)); // Copy the secret phrase into the buffer 

        for (int portToSend : ports) { // Loop through all the ports to knock on
            serverAddr.sin_port = htons(portToSend); // Assigns the port to the sin struct
             std::string hexPort = std::to_string(portToSend); // convert port from hex to string
            
            if (sendto(udpsock, knockBuffer.data(), knockBuffer.size(), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
                perror("Error sending knock");
                return -1;
            }
            char receiveFromKnock[1024]; // Möguleiki að socklen_t gæti þurft að komahér f neðan
            int receiveKnockBytes = recvfrom(udpsock, receiveFromKnock, 1024, 0, (struct sockaddr*)&serverAddr, &addr_size);

            //Check if we have received anything from the port, if so return true, the port is open
            if (receiveKnockBytes < 0) {
                perror("Error receiving message after knocking");
            }
            receiveFromKnock[receiveKnockBytes] = '\0'; // Add null-terminator
            std::cout << "Knocking on port " << std::stoul(hexPort, nullptr, 16) <<  ": " << receiveFromKnock << "\n" << std::endl;
        }
    close(udpsock);
    return 0; //The port is closed
    }