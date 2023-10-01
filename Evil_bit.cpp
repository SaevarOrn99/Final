// Authors: Katrín Ósk Kristinsdóttir and Sævar Örn Valsson
#include "Evil_bit.h" // For std::pair
#include "Port_talker.h"


unsigned short csum(unsigned short *ptr,int nbytes) //calculates the checksum
{
	register long sum; // 32 bit register a long sum
	unsigned short oddbyte; // 16 bit
	register short answer; // 16 bit

	sum=0;
	while(nbytes>1) { // This loops through the packet and sums up the bytes
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff); 
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer); // returns the checksum
}	


// Creates a raw socket and sends a UDP packet to the specified port
// Then uses a dummy socket that connects to a server and receives a message
int getUDPpackageRaw(const char* ip, int port, u_int32_t XOR) {
	
	//Create a UDP socket to send to the port Hi
	int udpsock = createUDPSocket(); // Creates a UDP socket
    if (udpsock < 0) return -1; 

    struct sockaddr_in serverAddr;
    configureServerAddr(serverAddr, ip, port);


    if (!setSocketTimeout(udpsock, 0, 200000)) { // Set the socket timeout to 200 ms
        perror("Error setting options"); 
        close(udpsock); // Close the socket before returning
        return -1;
    }
    
	// Sends the message Hi to the server
    if (!sendUDPMessage(udpsock, "Hi", strlen("Hi"), serverAddr)) { 
        perror("Error sending data");
        close(udpsock); // Close the socket before returning
        return -1;
    }

    // Insert the getsockname call here
    struct sockaddr_in localAddress;
    socklen_t addressLength = sizeof(localAddress);
    if (getsockname(udpsock, (struct sockaddr*)&localAddress, &addressLength) == -1) { // Get the local address
        perror("getsockname");
        close(udpsock);
        return -1;
    }
    int assignedPort = ntohs(localAddress.sin_port); // Get the port number
	close(udpsock); // Close the socket



    //Create a raw socket of type IPPROTO
	int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // Raw socket
	if(raw_socket == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create raw socket");
		exit(1);
	}
	
	char datagram[4096] , source_ip[32] , *data , *pseudogram; 
	memset(datagram, 0, 4096);//zero out the packet buffer

	//IP header
	struct iphdr *iph = (struct iphdr *) datagram; // IP header
	
	//UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip)); // UDP header
	
	struct sockaddr_in sin; 
	struct pseudo_header1 psh; 
	
	//Data part
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	u_int32_t networkXOR = XOR; // Convert to network byte order þetta er S.E.C.R.E.T. XOR signature
    memcpy(data, &networkXOR, sizeof(u_int32_t));
	
	
	//Create dummy socket
	int Dummy_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // cretes a dummy socket for listening
    if (Dummy_sock < 0) {
        perror("Error creating UDP socket");
        return -1;
    }

	int yes = 1;
	if (setsockopt(Dummy_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) { // set the socket options
    	perror("Error setting socket options");
    	close(Dummy_sock);
    	return -1;
	}

    struct sockaddr_in localAddr; // local address
    memset(&localAddr, 0, sizeof(localAddr)); // Zero out memory of address struct
    localAddr.sin_family = AF_INET; // IPv4
    localAddr.sin_port = htons(assignedPort); // assigneing the port from earlier to receive the messege the raw socket sent.
   	localAddr.sin_addr.s_addr = INADDR_ANY; // any address


	// Binda dummy socketið
    if (bind(Dummy_sock, (struct sockaddr*) &localAddr, sizeof(localAddr)) < 0) { // bind the socket to the local address on the computer
        perror("Error binding UDP socket");
        close(Dummy_sock);
        return -1;
    }



	//address resolution
	strcpy(source_ip , ip); 

	// The destination server 
	memset(&sin, 0, sizeof(sin)); // Zero out memory of address struct
	sin.sin_family = AF_INET; // IPv4
	sin.sin_port = htons(port); // assigns the port to the sin struct

	sin.sin_addr.s_addr = inet_addr (ip); // assigns the ip to the sin struct
	
	//Fill in the IP Header
	iph->ihl = 5; // header length
	iph->version = 4; // IPv4
	iph->tos = 0; // Type of service
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data); // total length of the packet
	iph->id = htonl(54321);	//Id of this packet
	iph->frag_off = htons(0x8000); // Setting the evil bit in the fragment offset field

	iph->ttl = 255; // time to live
	iph->protocol = IPPROTO_UDP; // UDP
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr =  localAddr.sin_addr.s_addr; // Source address
	iph->daddr =  inet_addr (ip);	//Destination address
	
	//Ip checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len); // The checksum
	
	//UDP header
	udph->source = htons(assignedPort); // assigns the port from earlier to the source port
	udph->dest = sin.sin_port; // assigns the port from earlier to the destination port
	udph->len = htons(8 + strlen(data));	//tcp header size
	udph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	
	//Now the UDP checksum using the pseudo header
	psh.source_address = inet_addr(source_ip); // Assign the phsudo header to the source ip
	psh.dest_address = sin.sin_addr.s_addr;  // Assign the phsudo header to the destination ip
	psh.placeholder = 0; 
	psh.protocol = IPPROTO_UDP; // UDP
	psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) ); // UDP header size
	
	int psize = sizeof(struct pseudo_header1) + sizeof(struct udphdr) + strlen(data); // size of the phsudo header
	pseudogram = (char*) malloc(psize); // allocate memory for the phsudo header

	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header1)); // copy the phsudo header to the pseudogram
	memcpy(pseudogram + sizeof(struct pseudo_header1) , udph , sizeof(struct udphdr) + strlen(data)); // copy the UDP header to the pseudogram
	
	udph->check = csum( (unsigned short*) pseudogram , psize); // calculate the checksum for the UDP header


	// connecta áður en ég sendi pakkann og bind líka útaf annars fæ ég aldrei pakkana
	// Connect to the server
    if (connect(raw_socket, (struct sockaddr*)&sin, sizeof(sin)) < 0) { // connect to the server
        std::cerr << "Error: Could not connect to server." << std::endl; 
        close(raw_socket);
        return 1;
    }

    std::cout << "Connected successfully to the server." << std::endl; 

	// Continue looping until the expected message is received
	char portStr[5]; // For extracting 4 characters plus null terminator
	while (true) { // Loop until the expected message is received
		// Send the packet
			if (sendto (raw_socket, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
		{
			perror("sendto failed");
		} else {
			printf ("Packet Send. Length : %d \n" , iph->tot_len);
		}

		// Receive a packet
		char buffer[1024];
		socklen_t addrSize = sizeof(localAddr);
		int bytesReceived = recvfrom(Dummy_sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&localAddr, &addrSize); // Receive a message
		if (bytesReceived < 0) {
			perror("Error receiving data");
			return -1;
		}
		buffer[bytesReceived] = '\0'; // Null-terminate the received data

		std::cout << "Received message from port "<< port << " is: " << buffer << std::endl;

		// Check for the expected message using strstr()
		if (strstr(buffer, "Yes, strong in the dark side you are")) { // If the message is the expected message
			strncpy(portStr, &buffer[bytesReceived - 4], 4);
			portStr[4] = '\0';  // Null terminate the string
			break; // Exit the loop
		}
	}

	close(Dummy_sock); // Close the listening socket
	close(raw_socket); // Close the socket before returning
	return atoi(portStr); // Return the port number
}