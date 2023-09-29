#include "Evil_bit.h" // For std::pair
#include "Port_talker.h"

unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
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
	
	return(answer);
}	


// Þetta er raw port dæmi

int getUDPpackageRaw(const char* ip, int port, u_int32_t XOR) {
	
	//Create a UDP socket to send to the port Hi
	int udpsock = createUDPSocket();
    if (udpsock < 0) return -1;

    struct sockaddr_in serverAddr;
    configureServerAddr(serverAddr, ip, port);


    if (!setSocketTimeout(udpsock, 0, 100000)) {
        perror("Error setting options");
        close(udpsock); // Close the socket before returning
        return -1;
    }

    if (!sendUDPMessage(udpsock, "Hi", strlen("Hi"), serverAddr)) {
        perror("Error sending data");
        close(udpsock); // Close the socket before returning
        return -1;
    }

    // Insert the getsockname call here
    struct sockaddr_in localAddress;
    socklen_t addressLength = sizeof(localAddress);
    if (getsockname(udpsock, (struct sockaddr*)&localAddress, &addressLength) == -1) {
        perror("getsockname");
        close(udpsock);
        return -1;
    }
    int assignedPort = ntohs(localAddress.sin_port);
	close(udpsock); // Close the socket



    //Create a raw socket of type IPPROTO
	int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(raw_socket == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create raw socket");
		exit(1);
	}
	
	char datagram[4096] , source_ip[32] , *data , *pseudogram;
	memset(datagram, 0, 4096);//zero out the packet buffer

	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
	
	struct sockaddr_in sin; // fyrri destination
	struct pseudo_header psh;
	
	//Data part
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	u_int32_t networkXOR = htonl(22354930); // Convert to network byte order þetta er S.E.C.R.E.T. XOR signature
    memcpy(data, &networkXOR, sizeof(u_int32_t));
	// Bý til dummy socket

	int Dummy_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (Dummy_sock < 0) {
        perror("Error creating UDP socket");
        return -1;
    }

	int yes = 1;
	if (setsockopt(Dummy_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
    	perror("Error setting socket options");
    	close(Dummy_sock);
    	return -1;
	}

    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(assignedPort); // setja random port hérna
   	localAddr.sin_addr.s_addr = INADDR_ANY;


	// Binda dummy socketið
    if (bind(Dummy_sock, (struct sockaddr*) &localAddr, sizeof(localAddr)) < 0) {
        perror("Error binding UDP socket");
        close(Dummy_sock);
        return -1;
    }



	//some address resolution
	strcpy(source_ip , ip); // source ip getur verið villa hérna !!!!!!!

	// connect a þetta dæmi 
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port); // þetta er portið sem ég sendi á

	sin.sin_addr.s_addr = inet_addr (ip); // skoða skoða raw socketið
	
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
	iph->id = htonl(54321);	//Id of this packet
	iph->frag_off = htons(0x8000); // Setting the evil bit in the fragment offset field

	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr =  localAddr.sin_addr.s_addr; // þetta þarf að vera annað ipið sem ég sendi á
	iph->daddr =  inet_addr (ip);	//Spoof the source ip address
	
	//Ip checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);
	
	//UDP header
	udph->source = htons(assignedPort);
	udph->dest = sin.sin_port; // þarf að setja range hérna Skoða !!!!! for lykkja? eða 
	udph->len = htons(8 + strlen(data));	//tcp header size
	udph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	
	//Now the UDP checksum using the pseudo header
	psh.source_address = inet_addr(source_ip);
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
	pseudogram = (char*) malloc(psize);

	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));
	
	udph->check = csum( (unsigned short*) pseudogram , psize);


	// connecta áður en ég sendi pakkann og bind líka útaf annars fæ ég aldrei pakkana
	// Connect to the server
    if (connect(raw_socket, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        std::cerr << "Error: Could not connect to server." << std::endl;
        close(raw_socket);
        return 1;
    }

    std::cout << "Connected successfully to the server." << std::endl;

	// Continue looping until the expected message is received
	char portStr[5]; // For extracting 4 characters plus null terminator
	while (true) {
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
		int bytesReceived = recvfrom(Dummy_sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&localAddr, &addrSize);
		if (bytesReceived < 0) {
			perror("Error receiving data");
			return -1;
		}
		buffer[bytesReceived] = '\0'; // Null-terminate the received data

		std::cout << "Received message from port "<< port << " is: " << buffer << std::endl;

		// Check for the expected message using strstr()
		if (strstr(buffer, "Yes, strong in the dark side you are")) {
			strncpy(portStr, &buffer[bytesReceived - 4], 4);
			portStr[4] = '\0';  // Null terminate the string
			break; // Exit the loop
		}
	}

	close(Dummy_sock); // Close the listening socket
	close(raw_socket); // Close the socket before returning
	return atoi(portStr);
}

//getUDPpackageRaw(argv[1],std::stoi(argv[2]),4001);