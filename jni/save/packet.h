#ifndef __PACKET_H__
#define __PACKET_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <iostream>
#include <sys/ptrace.h>
#include <iostream>
#include <vector>
#include <ctype.h>
#include "base64.h"
#include "md5.h"

#include<pcap.h>
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<net/ethernet.h>
//#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<linux/icmp.h>   // for ndk linux icmp header, comment decash
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
using namespace std;

#define SEARCH_TYPE_STRING     10001
#define SEARCH_TYPE_UNICODE    10002
#define SEARCH_TYPE_BASE64     10003

#define REPLACE_TYPE_STRING    20001
#define REPLACE_TYPE_UNICODE   20002
#define REPLACE_TYPE_BASE64    20003


class CPacket
{
	private:
		pcap_t* m_pHandle;
		FILE* m_pLogfile;
		char* m_pDeviceName;
		static CPacket* m_pPacket;
		static void ProcessPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer);
		bool SearchItem(vector<string>& vStrSearchList, unsigned char* pData, long int lStartAddress, long int lMemorySize, bool bExtraSearch);
		void ProcessICMPPacket(unsigned char* pBuffer, int nSize);
		void ProcessTCPPacket( const unsigned char* pBuffer, int nSize);
		void ProcessUDPPacket( unsigned char* pBuffer, int nSize);

		void ProcessIPHeader( const unsigned char* pBuffer, int nSize);
		void ProcessEthernetHeader( const unsigned char* pBuffer, int nSize);
		void PrintData(const unsigned char* pBuffer, int nSize);


	public:
		CPacket();
		void SelectDevice();
		void Sniffing();
		
};

#endif

