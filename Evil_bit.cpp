#include <cstdlib>
#include <unistd.h> // this header defines miscellaneous symbolic constants and types, and declares miscellaneous functions
#include <sys/socket.h> // defines the following macros to gain access to the data arrays in the ancillary data associated with a message header
#include <netinet/in.h> // defines the IN6ADDR_ANY_INIT macro
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <iostream> //declares objects that control reading from and writing to the standard streams
#include <cstring> //tracks the string length for faster performance, but it also retains the NULL character in the stored character data to support conversion to LPCWSTR
#include <string>
#include <netinet/udp.h>
#include <vector>

struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t len;
    uint16_t checksum;
};

struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

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

std::pair<int32_t, int> getSecretpackage(const char* ip, int port) {
    int udpsock = createUDPSocket();
    if (udpsock < 0) return std::make_pair(-1, -1);

    struct sockaddr_in serverAddr;
    configureServerAddr(serverAddr, ip, port);


    if (!setSocketTimeout(udpsock, 0, 100000)) {
        perror("Error setting options");
        close(udpsock); // Close the socket before returning
        return std::make_pair(-1, -1);
    }

    if (!sendUDPMessage(udpsock, "Hi", strlen("Hi"), serverAddr)) {
        perror("Error sending data");
        close(udpsock); // Close the socket before returning
        return std::make_pair(-1, -1);
    }

    // Insert the getsockname call here
    struct sockaddr_in localAddress;
    socklen_t addressLength = sizeof(localAddress);
    if (getsockname(udpsock, (struct sockaddr*)&localAddress, &addressLength) == -1) {
        perror("getsockname");
        close(udpsock);
        return std::make_pair(-1, -1);
    }
    int assignedPort = ntohs(localAddress.sin_port);
    std::cout << "Assigned Source Port: " << assignedPort << std::endl;




    char recvBuffer[1024];
    int recvBytes = receiveUDPMessage(udpsock, recvBuffer, sizeof(recvBuffer), serverAddr);
    if (recvBytes > 0) {
    std::cout << "Received first message from port no. " << port << ": " << recvBuffer << "\n---------------------------------------------------\n" << std::endl;
        uint8_t groupNo = 99;  //25 //99
        if (sendto(udpsock, &groupNo, sizeof(groupNo), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            perror("Error sending group number");
            return std::make_pair(-1, -1);
        }

        uint32_t fourByteChallenge; 
        int msgBytes = receiveUDPMessage(udpsock, (char*) &fourByteChallenge, sizeof(fourByteChallenge), serverAddr);
        
        // þetta er fyrir Greetings portið
        if (msgBytes == sizeof(fourByteChallenge)) {
            fourByteChallenge = ntohl(fourByteChallenge);
            std::cout << "Received second message from port no. " << port << ": " << fourByteChallenge << "\n---------------------------------------------------\n" << std::endl;
            
            uint32_t secret = 0xbdcedd8c;    // 0xbdcedd8c
            uint32_t signature = fourByteChallenge ^ secret; // htonl(3164325502 ^ 0xbdcedd8c)
           // signature = htonl(signature); ekki htnl því það er bara fyrir send
            close(udpsock); // Close the socket before returning
            return std::make_pair(signature, assignedPort); // Return the signature and the assignedPort
            }
        }

        close(udpsock); // Close the socket before returning
        return std::make_pair(-1, -1); // Return -1 if we didn't receive the challenge or any other error conditions. 
    }


// Þetta er raw port dæmi

int getUDPpackageRaw(const char* ip, int port, u_int32_t XOR, int assignedPort) {
    //Create a raw socket of type IPPROTO
	int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(s == -1)
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
	u_int32_t networkXOR = htonl(XOR); // Convert to network byte order þetta er S.E.C.R.E.T. XOR signature
    memcpy(data, &networkXOR, sizeof(u_int32_t));
	// Bý til dummy socket

	int udpsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpsock < 0) {
        perror("Error creating UDP socket");
        return -1;
    }

	int yes = 1;
	if (setsockopt(udpsock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
    	perror("Error setting socket options");
    	close(udpsock);
    	return -1;
	}

    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(assignedPort); // setja random port hérna
   	localAddr.sin_addr.s_addr = INADDR_ANY;


	// Binda dummy socketið
    if (bind(udpsock, (struct sockaddr*) &localAddr, sizeof(localAddr)) < 0) {
        perror("Error binding UDP socket");
        close(udpsock);
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
    if (connect(s, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        std::cerr << "Error: Could not connect to server." << std::endl;
        close(s);
        return 1;
    }

    std::cout << "Connected successfully to the server." << std::endl;


	

   // while (true) { // infinite loop to keep listening for new connections
	//Send the packet
	if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	{
		perror("sendto failed");
	}
	//Data send successfully
	else
	{
		printf ("Packet Send. Length : %d \n" , iph->tot_len);
	}


	//Receive a packet
	char buffer[1024];
	//struct sockaddr_in senderAddr; // hérna gæti verið villann !!!!!!!!
	socklen_t addrSize = sizeof(localAddr);
	int bytesReceived = recvfrom(udpsock, buffer, sizeof(buffer), 0, (struct sockaddr*)&localAddr, &addrSize);
	if (bytesReceived < 0) {
		perror("Error receiving data");
		return -1;
	}
	buffer[bytesReceived] = '\0'; // Null-terminate the received data
	std::cout << "Received message from port "<< port << " is: " << buffer << std::endl;


	close(udpsock); // Close the listening socket
	close(s); // Close the socket before returning
	return 0;
}


int main(int argc, char* argv[]) { 
    if (argc != 3) { // See if the argument count is correct, should be three
        std::cerr << "Usage: " << argv[0] << " <IP address> <port>" << std::endl;
        return 1; //for error
    }
    auto [result, assignedPort] = getSecretpackage(argv[1], 4010);
    getUDPpackageRaw(argv[1],std::stoi(argv[2]),result, assignedPort);

    return 0;
}