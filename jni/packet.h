#ifndef __PACKET_H__
#define __PACKET_H__

#define UC(b) (((int)b)&0xff)

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

#define PRINT_TYPE_SCREEN      30001
#define PRINT_TYPE_FILE        30002


static void* m_pPacket;
static pcap_t* m_pHandle;
class CPacket
{
	private:
		FILE* m_fPrintType;
		FILE* m_fLogfile;
		char* m_pDeviceName;
		vector<string> m_vStrSearchList;
		static void ProcessPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer);
		static void TerminateSniffing(int nSignum);
		bool SearchItem(vector<string>& vStrSearchList, const unsigned char* pData, long int lStartAddress, long int lMemorySize, bool bExtraSearch);

	public:
		CPacket(vector<string>& vStrSearchList);
		void SelectDevice();
		void Sniffing();
		vector<string>& GetSearchList();
		void DisplayPacketData(const unsigned char* pData, int nStartAddress, int nSearchPoint, int nLineNumber, int nSearchType);
		void DumpPacket(const unsigned char* pBuffer, int nSize);
		void DumpETHERNETPacket(const unsigned char* pBuffer, int nSize);
		int  DumpIPPacket(const unsigned char* pBuffer, int nSize);
		void DumpTCPPacket(const unsigned char* pBuffer, int nSize);
		void DumpUnSupportPacket(const unsigned char* pBuffer, int nSize);
		void PrintData (const unsigned char * pBuffer, int nSize);
		void DumpUDPPacket(const unsigned char* pBuffer, int nSize);
		void DumpICMPPacket(const unsigned char* pBuffer, int nSize);
		void SetPrintType(int nType);
};

#endif

