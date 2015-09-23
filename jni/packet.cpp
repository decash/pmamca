#include "packet.h"


CPacket::CPacket(vector<string>& vStrSearchList)
{
	m_pDeviceName = NULL;
	m_pHandle     = NULL;
	m_pPacket     = this;
	m_vStrSearchList = vStrSearchList;
	m_fLogfile = fopen("SniffingLog.txt", "w");
	m_fPrintType    = m_fLogfile;
}

void CPacket::SelectDevice()
{
	
	pcap_if_t *alldevsp , *device;
	char errbuf[100] , devs[100][100];
	int count = 1;

	//First get the list of available devices
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf(" [!] Error finding devices : %s" , errbuf);
		exit(1);
	}

	//Print the available devices
	printf(" [*] Network Device Lists\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("  [%d] %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}

	//Ask user which device to sniff
	int nDeviceNumber = 0;
	printf(" [*] Enter the number of the device you want to sniff : ");
	scanf("%d" , &nDeviceNumber);
	m_pDeviceName = devs[nDeviceNumber];


	/*
	char errbuf[100];
	memset(errbuf, 0x00, 100);

	m_pDeviceName = pcap_lookupdev(errbuf);
	if( m_pDeviceName == NULL )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf(" [*] Find Network Device(%s) \n", m_pDeviceName);

	bpf_u_int32 net;
	bpf_u_int32 mask;
	struct in_addr net_addr, mask_addr;
	if(pcap_lookupnet(m_pDeviceName, &net, &mask, errbuf) < 0) 
	{
		perror(errbuf);
		exit(1);
	}

	net_addr.s_addr = net;
	mask_addr.s_addr = mask;

	//printf(" [*] Find Network Device(%s) \n", m_pDeviceName);
	//printf(" [*] Net Address : %s\n", inet_ntoa(net_addr));
	//printf(" [*] Netmask : %s\n", inet_ntoa(mask_addr));
	*/
	
}



void CPacket::ProcessPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer)
{
	int size = header->len;
	int static nCount = 1;

	char strProtocol[10];
	memset(strProtocol, 0x00, 10);

	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			strcpy(strProtocol, "ICMP");
			break;

		case 2:  //IGMP Protocol
			strcpy(strProtocol, "IGMP");
			break;

		case 6:  //TCP Protocol
			strcpy(strProtocol, "TCP");
			break;

		case 17: //UDP Protocol
			strcpy(strProtocol, "UDP");
			break;

		default: //Some Other Protocol like ARP etc.
			strcpy(strProtocol, "OTHER");
			break;
	}
	
	// get Source IP
	struct sockaddr_in source,dest;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	// get Destination IP
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	// change Integer IP string IP
	char strSrcIP[20], strDestIP[20];
	memset(strSrcIP,  0x00, 20);
	memset(strDestIP, 0x00, 20);

	register char *p;
	p = (char *)&source.sin_addr;
	snprintf(strSrcIP,  sizeof(strSrcIP),  "%3d.%3d.%3d.%3d", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));
	p = (char *)&dest.sin_addr;
	snprintf(strDestIP, sizeof(strDestIP), "%3d.%3d.%3d.%3d", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));
	
	printf("[%5d] | [%5s] | [%15s]->[%15s] | [%5dbyte] |\r" , nCount++, strProtocol, strSrcIP, strDestIP, size);

	((CPacket*)m_pPacket)->SetPrintType(PRINT_TYPE_SCREEN);
	((CPacket*)m_pPacket)->SearchItem( ((CPacket*)m_pPacket)->GetSearchList(), buffer, 0, size, false);

	((CPacket*)m_pPacket)->SetPrintType(PRINT_TYPE_FILE);
	((CPacket*)m_pPacket)->DumpPacket(buffer, size);
}

void CPacket::Sniffing()
{
	char errbuf[100];
	memset(errbuf, 0x00, 100);

	//Open the device for sniffing
	m_pHandle = pcap_open_live(m_pDeviceName , 65536 , 1 , 0 , errbuf);

	if (m_pHandle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , m_pDeviceName , errbuf);
		exit(1);
	}

	if(m_fPrintType == NULL) 
	{
		printf("Unable to create file.");
	}
	
	printf(" [+] Start to Sniffing (stop press : ctrl+c)\n");
	printf("|======================================================================|\n");
	printf("[COUNT] | [ TYPE] | [         Source]->[    Destination] | [     Size] |\n");
	printf("|======================================================================|\n");
        //      [  533] | [  TCP] | [125.209.230.238]->[192.168.  0. 23] | [   54byte] |

	signal(SIGINT, TerminateSniffing);
	pcap_loop(m_pHandle , -1 , ProcessPacket , NULL);

}

void CPacket::TerminateSniffing(int nSignum)
{
	fflush(stdin);
	char ch;
	scanf("%c", &ch); 
	printf("\n");
	pcap_breakloop(m_pHandle);
	pcap_close(m_pHandle);
}

bool CPacket::SearchItem(vector<string>& vStrSearchList, const unsigned char* pData, long int lStartAddress, long int lMemorySize, bool bExtraSearch)
{
	bool bSearchResult = false;
	vector<string>::iterator itr;
	for(itr = vStrSearchList.begin(); itr < vStrSearchList.end(); itr++)
	{
		string strKeyword = *itr;

		// ASCII, UNICODE
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
				DisplayPacketData(pData, lStartAddress, i, 3, SEARCH_TYPE_STRING);
				SetPrintType(PRINT_TYPE_SCREEN);
				DumpPacket(pData, lMemorySize);
				bSearchResult = true;
			}
		}

		// SEARCHING for UNICODE Keyword
		for(long int i = 0; i < lMemorySize; i++)
		{
			if(memcmp(pData+i, pUniKeyword, nKeywordSize * 2) == 0)
			{
				DisplayPacketData(pData, lStartAddress, i, 3, SEARCH_TYPE_UNICODE);
				SetPrintType(PRINT_TYPE_SCREEN);
				DumpPacket(pData, lMemorySize);
				bSearchResult = true;
			}
		}

		// SEARCHING for STRING to BASE64 Keyword 
		string strSTRBase64Keyword = base64_encode(pStrKeyword, nKeywordSize);
		for(int i = 0; i < lMemorySize; i++)
		{
			if(memcmp(pData+i, strSTRBase64Keyword.c_str(), strSTRBase64Keyword.size()) == 0)
			{
				DisplayPacketData(pData, lStartAddress, i, 3, SEARCH_TYPE_STRING);
				SetPrintType(PRINT_TYPE_SCREEN);
				DumpPacket(pData, lMemorySize);
			}

		}

		// SEARCHING for UNICODE to BASE64 Keyword 
		string strUNIBase64Keyword = base64_encode(pUniKeyword, nKeywordSize*2);
		for(int i = 0; i < lMemorySize; i++)
		{
			if(memcmp(pData+i, strUNIBase64Keyword.c_str(), strUNIBase64Keyword.size()) == 0)
			{
				DisplayPacketData(pData, lStartAddress, i, 3, SEARCH_TYPE_UNICODE);
				SetPrintType(PRINT_TYPE_SCREEN);
				DumpPacket(pData, lMemorySize);
			}
		}


		free(pStrKeyword);
		free(pUniKeyword);
	}
	return bSearchResult;
}

vector<string>& CPacket::GetSearchList()
{
	return m_vStrSearchList;
}

void CPacket::DisplayPacketData(const unsigned char* pData, int nStartAddress, int nSearchPoint, int nLineNumber, int nSearchType)
{
	if(nLineNumber < 3) 
		nLineNumber = 3;
	int nStartLine = (nLineNumber)  / 2;


	if     ( nSearchType == SEARCH_TYPE_STRING )
		printf("\n-FIND STRING at BLOW PACKET------------------------------------------------\n");
	
	else if( nSearchType == SEARCH_TYPE_UNICODE )
		printf("\n--FIND UNICODE at BLOW PACKET----------------------------------------------\n");

	else if( nSearchType == SEARCH_TYPE_BASE64 )
		printf("\n--FIND BASE64 ENCODED STRING at BLOW PACKET--------------------------------\n");

	// FORMAT
	// 0x12345678  11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66  1.2.3.4.5.6.7.8. 
	// 0x12345678  11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66  F.I.N.D.S.T.R.01 
	// 0x12345678  11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66  FINDSTR123456789 
	// 0x12345678  11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66  1234567890123456 
	for(int i = 0; i < nLineNumber; i++)
	{
		int nOffset = nSearchPoint + 16 * (i-nStartLine);

		// 1
		printf("0x%08x", nStartAddress + nOffset );
		printf("  ");

		// 2
		for(int j = 0; j < 16; j++)
		{
			printf("%02x ", pData[nOffset + j] ); 
		}
		printf("  ");

		// 3
		for(int j = 0; j < 16; j++)
		{
			unsigned char ch = pData[nOffset + j];
			if( ch >= 33 && ch <= 125 ) printf("%c", ch); 
			else	                    printf("."); 
		}
		printf("\n");
	}

	printf("------------------------------------------------------------------------------\n");
}


void CPacket::DumpPacket(const unsigned char* pBuffer, int nSize)
{
	
	DumpETHERNETPacket(pBuffer, nSize);
	
	int nProtocolType = DumpIPPacket(pBuffer, nSize);

	switch (nProtocolType)
	{
		case 1: // ICPM
			DumpICMPPacket(pBuffer, nSize);
			break;

		case 6: // TCP
			DumpTCPPacket(pBuffer, nSize);
			break;

		case 17: // UDP
			DumpUDPPacket(pBuffer, nSize);
			break;

		default: // UnSupport
			DumpUnSupportPacket(pBuffer, nSize);
			break;
	}
}

void CPacket::DumpETHERNETPacket(const unsigned char* pBuffer, int nSize)
{
	struct ethhdr *eth = (struct ethhdr *)pBuffer;

	fprintf(m_fPrintType , "\n");
	fprintf(m_fPrintType , "[+]Ethernet Header\n");
	fprintf(m_fPrintType , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", 
			eth->h_dest[0], 
			eth->h_dest[1], 
			eth->h_dest[2], 
			eth->h_dest[3], 
			eth->h_dest[4], 
			eth->h_dest[5] );

	fprintf(m_fPrintType , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", 
			eth->h_source[0] , 
			eth->h_source[1] , 
			eth->h_source[2] , 
			eth->h_source[3] , 
			eth->h_source[4] , 
			eth->h_source[5] );

	fprintf(m_fPrintType , "   |-Protocol            : %u \n", (unsigned short)eth->h_proto);
}


int CPacket::DumpIPPacket(const unsigned char* pBuffer, int nSize)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(pBuffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;

	struct sockaddr_in source,dest;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(m_fPrintType , "\n");
	fprintf(m_fPrintType , "[+]IP Header\n");
	fprintf(m_fPrintType , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(m_fPrintType , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(m_fPrintType , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(m_fPrintType , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(m_fPrintType , "   |-Identification    : %d\n",ntohs(iph->id));
	//fprintf(m_fPrintType , "   |-Reserved ZERO Field   : %d\n", (unsigned int)iphdr->ip_reserved_zero);
	//fprintf(m_fPrintType , "   |-Dont Fragment Field   : %d\n", (unsigned int)iphdr->ip_dont_fragment);
	//fprintf(m_fPrintType , "   |-More Fragment Field   : %d\n", (unsigned int)iphdr->ip_more_fragment);
	fprintf(m_fPrintType , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(m_fPrintType , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(m_fPrintType , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(m_fPrintType , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(m_fPrintType , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );

	return iph->protocol;
}

void CPacket::DumpTCPPacket(const unsigned char* pBuffer, int nSize)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)( pBuffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)(pBuffer + iphdrlen + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

	fprintf(m_fPrintType , "\n[+]TCP Header\n");
	fprintf(m_fPrintType , "   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(m_fPrintType , "   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(m_fPrintType , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(m_fPrintType , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(m_fPrintType , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//fprintf(m_fPrintType , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(m_fPrintType , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(m_fPrintType , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(m_fPrintType , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(m_fPrintType , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(m_fPrintType , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(m_fPrintType , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(m_fPrintType , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(m_fPrintType , "   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(m_fPrintType , "   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(m_fPrintType , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(m_fPrintType , "\n");

	fprintf(m_fPrintType , "[+]Data Payload\n");    
	PrintData(pBuffer + header_size , nSize - header_size );

	fprintf(m_fPrintType , "\n###########################################################\n");


}

void CPacket::DumpUDPPacket(const unsigned char* pBuffer, int nSize)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(pBuffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;

	struct udphdr *udph = (struct udphdr*)(pBuffer + iphdrlen  + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	fprintf(m_fPrintType , "\n[+]UDP Header\n");
	fprintf(m_fPrintType , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(m_fPrintType , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(m_fPrintType , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(m_fPrintType , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));

	fprintf(m_fPrintType , "\n");

	fprintf(m_fPrintType , "[+]Data Payload\n");    
	PrintData(pBuffer + header_size , nSize - header_size);

	fprintf(m_fPrintType , "\n###########################################################\n");

}


void CPacket::DumpICMPPacket(const unsigned char* pBuffer, int nSize)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(pBuffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct icmphdr *icmph = (struct icmphdr *)(pBuffer + iphdrlen  + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

	fprintf(m_fPrintType , "\nICMP Header\n");
	fprintf(m_fPrintType , "   |-Type : %d",(unsigned int)(icmph->type));

	if((unsigned int)(icmph->type) == 11)
	{
		fprintf(m_fPrintType , "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(m_fPrintType , "  (ICMP Echo Reply)\n");
	}

	fprintf(m_fPrintType , "   |-Code : %d\n",(unsigned int)(icmph->code));
	fprintf(m_fPrintType , "   |-Checksum : %d\n",ntohs(icmph->checksum));
	//fprintf(m_fPrintType , "   |-ID       : %d\n",ntohs(icmph->id));
	//fprintf(m_fPrintType , "   |-Sequence : %d\n",ntohs(icmph->sequence));
	fprintf(m_fPrintType , "\n");


	fprintf(m_fPrintType , "[+]Data Payload\n");    
	PrintData(pBuffer + header_size , (nSize - header_size) );

	fprintf(m_fPrintType , "\n###########################################################\n");

}

void CPacket::SetPrintType(int nType)
{
	if     (nType == PRINT_TYPE_SCREEN)
		m_fPrintType = stdout;

	else if(nType == PRINT_TYPE_FILE)
		m_fPrintType = m_fLogfile;
}

void CPacket::PrintData (const unsigned char* pBuffer, int nSize)
{
	int i , j;
	for(i=0 ; i < nSize ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(m_fPrintType , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(pBuffer[j]>=32 && pBuffer[j]<=128)
					fprintf(m_fPrintType , "%c",(unsigned char)pBuffer[j]); //if its a number or alphabet

				else fprintf(m_fPrintType , "."); //otherwise print a dot
			}
			fprintf(m_fPrintType , "\n");
		} 

		if(i%16==0) fprintf(m_fPrintType , "   ");
		fprintf(m_fPrintType , " %02X",(unsigned int)pBuffer[i]);

		if( i==nSize-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
				fprintf(m_fPrintType , "   "); //extra spaces
			}

			fprintf(m_fPrintType , "         ");

			for(j=i-i%16 ; j<=i ; j++)
			{
				if(pBuffer[j]>=32 && pBuffer[j]<=128) 
				{
					fprintf(m_fPrintType , "%c",(unsigned char)pBuffer[j]);
				}
				else
				{
					fprintf(m_fPrintType , ".");
				}
			}

			fprintf(m_fPrintType ,  "\n" );
		}
	}
}


void CPacket::DumpUnSupportPacket(const unsigned char* pBuffer, int nSize)
{
	struct iphdr *iph = (struct iphdr *)(pBuffer  + sizeof(struct ethhdr));
	int iphdrlen = iph->ihl * 4;
	int header_size =  sizeof(struct ethhdr) + iphdrlen;

	fprintf(m_fPrintType , "\nUnSupport Packet\n");

	fprintf(m_fPrintType , "[+]Data Payload\n");    
	PrintData(pBuffer + header_size , (nSize - header_size) );

	fprintf(m_fPrintType , "\n###########################################################\n");

}

