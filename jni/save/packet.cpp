#include "packet.h"

CPacket::CPacket()
{
	m_pDeviceName = NULL;
	m_pHandle     = NULL;
	m_pLogfile    = NULL;
	m_pPacket = this;
}

void CPacket::SelectDevice()
{
	pcap_if_t *alldevsp , *device;
	char errbuf[100] , devs[100][100];
	int count = 1;

	//First get the list of available devices
	printf("[*] Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");

	//Print the available devices
	printf("\n[*] Available Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}

	//Ask user which device to sniff
	int nDeviceNumber = 0;
	printf("[*] Enter the number of the device you want to sniff : ");
	scanf("%d" , &nDeviceNumber);
	m_pDeviceName = devs[nDeviceNumber];
}

void CPacket::ProcessPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer)
{
	int tcp=0, udp=0, icmp=0, others=0, igmp=0, total=0; 
	int size = header->len;

	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp;
			//print_icmp_packet( buffer , size);
			break;

		case 2:  //IGMP Protocol
			++igmp;
			break;

		case 6:  //TCP Protocol
			++tcp;
			m_pPacket->ProcessTCPPacket(buffer, size);
			break;

		case 17: //UDP Protocol
			++udp;
			//print_udp_packet(buffer , size);
			break;

		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
	printf("| TCP : %5d | UDP : %5d | ICMP : %5d | IGMP : %5d | Others : %5d | Total : %5d | \r", tcp , udp , icmp , igmp , others , total);

}

void CPacket::Sniffing()
{
	char errbuf[100];
	memset(errbuf, 0x00, 100);

	//Open the device for sniffing
	printf("Opening device %s for sniffing ... " , m_pDeviceName);
	m_pHandle = pcap_open_live(m_pDeviceName , 65536 , 1 , 0 , errbuf);

	if (m_pHandle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , m_pDeviceName , errbuf);
		exit(1);
	}
	printf("Done\n");

	m_pLogfile = fopen("log.txt","w");
	if(m_pLogfile == NULL) 
	{
		printf("Unable to create file.");
	}

	//Put the device in sniff loop
	pcap_loop(m_pHandle , -1 , ProcessPacket , NULL);
}

bool CPacket::SearchItem(vector<string>& vStrSearchList, unsigned char* pData, long int lStartAddress, long int lMemorySize, bool bExtraSearch)
{
	bool bSearchResult = false;
	vector<string>::iterator itr;
	for(itr = vStrSearchList.begin(); itr < vStrSearchList.end(); itr++)
	{
		// 원본 키워드를 얻어온다
		string strKeyword = *itr;
		cout << "  [*] TRY TO SEARCH [" << strKeyword << "] " << endl;

		// ASCII, UNICODE 문자로 변환한다
		int nKeywordSize = strKeyword.size();
		unsigned char* pStrKeyword = (unsigned char*) malloc(nKeywordSize);
		unsigned char* pUniKeyword = (unsigned char*) malloc(nKeywordSize * 2);
		memset(pStrKeyword, 0x00, nKeywordSize  );
		memset(pUniKeyword, 0x00, nKeywordSize*2);

		memcpy(pStrKeyword, strKeyword.c_str(), nKeywordSize);
		for(int i = 0; i < nKeywordSize; i++)
			pUniKeyword[i*2] = strKeyword[i];

		// SEARCHING for String Keyword
		for(long int i = 0; i < lMemorySize; i++)
		{
			if(memcmp(pData+i, pStrKeyword, nKeywordSize) == 0)
			{
				//DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, SEARCH_TYPE_STRING);
				bSearchResult = true;
			}
		}

		// SEARCHING for UNICODE Keyword
		for(long int i = 0; i < lMemorySize; i++)
		{
			if(memcmp(pData+i, pUniKeyword, nKeywordSize * 2) == 0)
			{
				//DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, SEARCH_TYPE_UNICODE);
				bSearchResult = true;
			}
		}
		
		// EXTRA SEARCH
		if( bExtraSearch == true )
		{
			// SEARCHING for STRING to BASE64 Keyword 
			string strSTRBase64Keyword = base64_encode(pStrKeyword, nKeywordSize);
			for(int i = 0; i < lMemorySize; i++)
			{
				if(memcmp(pData+i, strSTRBase64Keyword.c_str(), strSTRBase64Keyword.size()) == 0)
				{
					//DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, SEARCH_TYPE_BASE64);
				}
			}
			
			// SEARCHING for UNICODE to BASE64 Keyword 
			string strUNIBase64Keyword = base64_encode(pUniKeyword, nKeywordSize*2);
			for(int i = 0; i < lMemorySize; i++)
			{
				if(memcmp(pData+i, strUNIBase64Keyword.c_str(), strUNIBase64Keyword.size()) == 0)
				{
					//DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, SEARCH_TYPE_BASE64);
				}
			}

			// SEARCHING for STRING to MD5 Keyword 
			md5_state_t state;
			md5_byte_t digest[16];
			char hex_output[16*2 + 1];

			md5_init(&state);
			md5_append(&state, (const md5_byte_t*)pStrKeyword, nKeywordSize);
			md5_finish(&state, digest); 

			//for (int di = 0; di < 16; ++di)
			//sprintf(hex_output + di * 2, "%02x", digest[di]);
			//cout << "md5 : " << string(hex_output) << endl;
		
			for(int i = 0; i < lMemorySize; i++)
			{
				if(memcmp(pData+i, digest, 16) == 0)
				{
					//DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, SEARCH_TYPE_BASE64);
				}
			}
		}


		free(pStrKeyword);
		free(pUniKeyword);
	}
	return bSearchResult;
}

void CPacket::ProcessTCPPacket(const unsigned char* pBuffer, int nSize)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)( pBuffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)(pBuffer + iphdrlen + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

	fprintf(m_pLogfile , "\n\n***********************TCP Packet*************************\n");  

	//print_ip_header(pBuffer, nSize);
	ProcessIPHeader(pBuffer, nSize);

	fprintf(m_pLogfile , "\n");
	fprintf(m_pLogfile , "TCP Header\n");
	fprintf(m_pLogfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(m_pLogfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(m_pLogfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(m_pLogfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(m_pLogfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//fprintf(m_pLogfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(m_pLogfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(m_pLogfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(m_pLogfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(m_pLogfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(m_pLogfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(m_pLogfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(m_pLogfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(m_pLogfile , "   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(m_pLogfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(m_pLogfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(m_pLogfile , "\n");
	fprintf(m_pLogfile , "                        DATA Dump                         ");
	fprintf(m_pLogfile , "\n");

	fprintf(m_pLogfile , "IP Header\n");
	PrintData(pBuffer,iphdrlen);

	fprintf(m_pLogfile , "TCP Header\n");
	PrintData(pBuffer+iphdrlen,tcph->doff*4);

	fprintf(m_pLogfile , "Data Payload\n");    
	PrintData(pBuffer + header_size , nSize - header_size );

	fprintf(m_pLogfile , "\n###########################################################");


}

void CPacket::ProcessIPHeader(const unsigned char* pBuffer, int nSize)
{
	struct sockaddr_in source, dest;
	//print_ethernet_header(Buffer , Size);

	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(pBuffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(m_pLogfile , "\n");
	fprintf(m_pLogfile , "IP Header\n");
	fprintf(m_pLogfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(m_pLogfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(m_pLogfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(m_pLogfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(m_pLogfile , "   |-Identification    : %d\n",ntohs(iph->id));
	//fprintf(m_pLogfile , "   |-Reserved ZERO Field   : %d\n", (unsigned int)iphdr->ip_reserved_zero);
	//fprintf(m_pLogfile , "   |-Dont Fragment Field   : %d\n", (unsigned int)iphdr->ip_dont_fragment);
	//fprintf(m_pLogfile , "   |-More Fragment Field   : %d\n", (unsigned int)iphdr->ip_more_fragment);
	fprintf(m_pLogfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(m_pLogfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(m_pLogfile , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(m_pLogfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(m_pLogfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );

}

void CPacket::ProcessEthernetHeader(const unsigned char* pBuffer, int nSize)
{
	struct ethhdr *eth = (struct ethhdr *)pBuffer;
	fprintf(m_pLogfile , "\n");
	fprintf(m_pLogfile , "Ethernet Header\n");
	fprintf(m_pLogfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", 
			eth->h_dest[0], eth->h_dest[1] , eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5] );
	fprintf(m_pLogfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", 
			eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(m_pLogfile , "   |-Protocol            : %u \n", (unsigned short)eth->h_proto);
}


void CPacket::PrintData(const unsigned char* pBuffer, int nSize)
{

}
