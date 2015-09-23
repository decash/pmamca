#ifndef __MODULE_H__
#define __MODULE_H__

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

#define SEARCH_TYPE_STRING     10001
#define SEARCH_TYPE_UNICODE    10002
#define SEARCH_TYPE_BASE64     10003

#define REPLACE_TYPE_STRING    20001
#define REPLACE_TYPE_UNICODE   20002
#define REPLACE_TYPE_BASE64    20003

using namespace std;

class CModule
{
	private:
		int      m_nParentProcessID;
		int      m_nDisplayMemLineCount;
		string   m_strModuleName;
		long int m_lStartAddress;
		long int m_lEndAddress;
		long int m_lMemorySize;

	public:
		// 생성자
		CModule(int nParentProcessID, string strStartAddress, string strEndAddress, string strModuleName, int nDisplayMemLineCount);

		// GET & SET
		long int GetStartAddress();
		long int GetEndAddress();
		long int GetMemorySize();
		string   GetStrMemorySize();
		int      GetParentProcessID();
		string   GetModuleName();
		void     SetModuleName(string strModuleName);
	        
		// 메모리 덤프 함수	
		int      GetDumpMemory    (unsigned char* pDumpData);
		int      GetPartDumpMemory(unsigned char* pDumpData, int nDevideCount, int nDevideIndex, int nPartDumpSize);
	
		// 찾기 및 변조 함수
		bool     SearchOfMemory (vector<string>& vStrSearchList,  unsigned char* pData, long int lStartAddress, long int lMemorySize, bool bExtraSearch = false);
		void     ReplaceOfMemory(vector<string>& vStrReplaceList, unsigned char* pData, long int lStartAddress, long int lMemorySize);

		// 덤프 데이터 출력 함수
		void     DisplayMemoryData(unsigned char* pData, int nStartAddress, int SearchPoint, int nLineNumber, int nSearchType);
};
#endif
