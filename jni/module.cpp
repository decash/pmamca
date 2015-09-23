#include "module.h"
#include <sys/wait.h>
#include <pthread.h>


CModule::CModule(int nParentProcessID, string strStartAddress, string strEndAddress, string strModuleName, int nDisplayMemLineCount)
{
	m_nParentProcessID = nParentProcessID;
	m_lStartAddress    = strtol(strStartAddress.c_str(), NULL, 16);
	m_lEndAddress      = strtol(strEndAddress.c_str(),   NULL, 16);
	m_lMemorySize      = m_lEndAddress - m_lStartAddress;
	m_nDisplayMemLineCount = nDisplayMemLineCount;
	SetModuleName(strModuleName);
}

int CModule::GetDumpMemory(unsigned char* pDumpData)
{
	long int lStartPos     = m_lStartAddress;
	long int lEndPos       = m_lEndAddress;

	// MEMORY SIZE가 1MB 이하이면, 싱글 스레드로 동작
	long int nLoopCount = m_lMemorySize / 4;

	// MEMORY DUMP
	for(long int i = 0; i < nLoopCount; i++)
	{
		int nBuffer = ptrace(PTRACE_PEEKDATA, m_nParentProcessID, (void *)(lStartPos + i*4), NULL);
		memcpy(pDumpData+(i*4), &nBuffer, 4);
	}

	return 0;
}


string CModule::GetStrMemorySize()
{
	char strFileSize[20];
	memset(strFileSize, 0x00, 20);

	if     ( m_lMemorySize >= 1048576 )
		sprintf(strFileSize, "%ldMb", m_lMemorySize / 1048576);
	else if( m_lMemorySize > 1024 )
		sprintf(strFileSize, "%ldKb", m_lMemorySize / 1024);
	else   
		sprintf(strFileSize, "%ldb",  m_lMemorySize);

	return string(strFileSize);
}


int CModule::GetPartDumpMemory(unsigned char* pDumpData, int nDevideCount, int nDevideIndex, int nPartDumpSize)
{
	// 분할 Searching을 위하여 읽어올 메모리 주소 영역을 N등분 한다
	long int lDevideMemorySize = m_lMemorySize / nDevideCount;
	long int lStartAddress     = m_lStartAddress + nDevideIndex * lDevideMemorySize;
	long int nLoopCount        = nPartDumpSize / 4;

	// MEMORY DUMP
	for(int i = 0; i < nLoopCount; i++)
	{
		int nBuffer = ptrace(PTRACE_PEEKDATA, m_nParentProcessID, (void *)(lStartAddress + i*4), NULL);
		memcpy(pDumpData+(i*4), &nBuffer, 4);
	}

	return 0;
}


bool CModule::SearchOfMemory(vector<string>& vStrSearchList, unsigned char* pData, long int lStartAddress, long int lMemorySize, bool bExtraSearch)
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
				DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, SEARCH_TYPE_STRING);
				bSearchResult = true;
			}
		}

		// SEARCHING for UNICODE Keyword
		for(long int i = 0; i < lMemorySize; i++)
		{
			if(memcmp(pData+i, pUniKeyword, nKeywordSize * 2) == 0)
			{
				DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, SEARCH_TYPE_UNICODE);
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
					DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, SEARCH_TYPE_BASE64);
				}
			}
			
			// SEARCHING for UNICODE to BASE64 Keyword 
			string strUNIBase64Keyword = base64_encode(pUniKeyword, nKeywordSize*2);
			for(int i = 0; i < lMemorySize; i++)
			{
				if(memcmp(pData+i, strUNIBase64Keyword.c_str(), strUNIBase64Keyword.size()) == 0)
				{
					DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, SEARCH_TYPE_BASE64);
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
					DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, SEARCH_TYPE_BASE64);
				}
			}
	

		}


		free(pStrKeyword);
		free(pUniKeyword);
	}
	return bSearchResult;
}

void CModule::ReplaceOfMemory(vector<string>& vStrReplaceList, unsigned char* pData, long int lStartAddress, long int lMemorySize)
{
	int nReplaceCnt = vStrReplaceList.size() / 2;
	for(int cnt = 0; cnt < nReplaceCnt; cnt++)
	{
		//string strKeyword        = vStrReplaceList[0];
		//string strReplaceKeyword = vStrReplaceList[1];

		string strKeyword        = vStrReplaceList[cnt*2    ];
		string strReplaceKeyword = vStrReplaceList[cnt*2 + 1];


		int nKeywordSize = strKeyword.size();
		unsigned char* pStrKeyword        = (unsigned char*) malloc(nKeywordSize);
		unsigned char* pStrReplaceKeyword = (unsigned char*) malloc(nKeywordSize);
		unsigned char* pUniKeyword        = (unsigned char*) malloc(nKeywordSize * 2);
		unsigned char* pUniReplaceKeyword = (unsigned char*) malloc(nKeywordSize * 2);
		memset(pStrKeyword,        0x00, nKeywordSize  );
		memset(pStrReplaceKeyword, 0x00, nKeywordSize  );
		memset(pUniKeyword,        0x00, nKeywordSize*2);
		memset(pUniReplaceKeyword, 0x00, nKeywordSize*2);

		memcpy(pStrKeyword,        strKeyword.c_str(),        nKeywordSize);
		memcpy(pStrReplaceKeyword, strReplaceKeyword.c_str(), nKeywordSize);
		for(int i = 0; i < nKeywordSize; i++)
		{
			pUniKeyword[i*2]        = strKeyword[i];
			pUniReplaceKeyword[i*2] = strReplaceKeyword[i];
		}


		cout << "  [*] TRY TO Replace [" << strKeyword << "] →  [" << strReplaceKeyword << "] " << endl;


		// SEARCHING for String Keyword
		for(int i = 0; i < lMemorySize; i++)
		{
			if(memcmp(pData+i, pStrKeyword, nKeywordSize) == 0)
			{
				// 찾은 문자열 출력
				DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, SEARCH_TYPE_STRING);

				// 변환할 문자열 메모리 영역에 치환
				memcpy(pData+i, pStrReplaceKeyword, nKeywordSize);
				
			        /*	
				char strCheck[100];
				memset(strCheck, 0x00, 100);
				cout << " [*] Do YOU WANT CHANGE(c) or NOT(enter) : ";
				cin.getline(strCheck, 100);
				if(strCheck[0] == 'c')
				*/

				{
					// MEMORY DUMP
					int nLoopCount = 0;
					if( nKeywordSize % 4 == 0)
						nLoopCount = nKeywordSize / 4;
					else
						nLoopCount = nKeywordSize / 4 + 1;

					for(int j = 0; j < nLoopCount; j++)
					{
						int nTemp = 0;
						memcpy(&nTemp, pData+i+j*4, 4); 
						ptrace(PTRACE_POKEDATA, m_nParentProcessID, (void *)(lStartAddress + i + j*4), (void*)nTemp);
					}

					// 변환된 문자열 출력
					DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, REPLACE_TYPE_STRING);
				}
			}
		}

		// SEARCHING for UNICODE Keyword
		for(int i = 0; i < lMemorySize; i++)
		{
			if(memcmp(pData+i, pUniKeyword, nKeywordSize * 2) == 0)
			{
				// 찾은 문자열 출력
				DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, SEARCH_TYPE_UNICODE);

				// 변환할 문자열 메모리 영역에 치환
				memcpy(pData+i, pUniReplaceKeyword, nKeywordSize*2);

				/*	
					char strCheck[100];
					memset(strCheck, 0x00, 100);
					cout << " [*] Do YOU WANT CHANGE(c) or NOT(enter) : ";
					cin.getline(strCheck, 100);
					if(strCheck[0] == 'c')
				*/
			
				{
					// MEMORY DUMP
					int nLoopCount = 0;
					if( (nKeywordSize*2) % 4 == 0)
						nLoopCount = nKeywordSize*2 / 4;
					else
						nLoopCount = nKeywordSize*2 / 4 + 1;

					for(int j = 0; j < nLoopCount; j++)
					{	
						int nTemp = 0;
						memcpy(&nTemp, pData+i+j*4, 4); 
						ptrace(PTRACE_POKEDATA, m_nParentProcessID, (void *)(lStartAddress + i + j*4), (void*)nTemp);
					}

					// 찾은 문자열 출력
					DisplayMemoryData(pData, lStartAddress, i, m_nDisplayMemLineCount, REPLACE_TYPE_UNICODE);
				}
			
			}
		}			

		free(pStrKeyword);
		free(pUniKeyword);
		
	}
}

void CModule::DisplayMemoryData(unsigned char* pData, int nStartAddress, int nSearchPoint, int nLineNumber, int nSearchType)
{
	if(nLineNumber < 3) 
		nLineNumber = 3;
	int nStartLine = (nLineNumber)  / 2;


	if     ( nSearchType == SEARCH_TYPE_STRING )
		printf("-FIND STRING AT [%08x]----------------------------------------------------\n", nStartAddress + nSearchPoint);
	
	else if( nSearchType == SEARCH_TYPE_UNICODE )
		printf("-FIND UNICODE AT [%08x]---------------------------------------------------\n", nStartAddress + nSearchPoint);

	else if( nSearchType == SEARCH_TYPE_BASE64 )
		printf("-FIND BASE64 ENCODED STRING AT [%08x]-------------------------------------\n", nStartAddress + nSearchPoint);
	
	else if( nSearchType == REPLACE_TYPE_STRING )
		printf("-REPLACE STRING AT [%08x]-------------------------------------------------\n", nStartAddress + nSearchPoint);
	
	else if( nSearchType == REPLACE_TYPE_UNICODE )
		printf("-REPLACE UNICODE STRING AT [%08x]-----------------------------------------\n", nStartAddress + nSearchPoint);

	// FORMAT
	// 0x12345678  11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66  1.2.3.4.5.6.7.8. 
	// 0x12345678  11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66  F.I.N.D.S.T.R.01 
	// 0x12345678  11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66  FINDSTR123456789 
	// 0x12345678  11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66  1234567890123456 
	for(int i = 0; i < nLineNumber; i++)
	{
		int nOffset = nSearchPoint + 16 * (i-nStartLine);

		// 1. 주소 표기
		printf("0x%08x", nStartAddress + nOffset );
		printf("  ");

		// 2. HEX 표기
		for(int j = 0; j < 16; j++)
		{
			printf("%02x ", pData[nOffset + j] ); 
		}
		printf("  ");

		// 3. CHAR 표기
		for(int j = 0; j <16; j++)
		{
			unsigned char ch = pData[nOffset + j];
			if( ch >= 33 && ch <= 125 ) printf("%c", ch); 
			else	                    printf("."); 
		}
		printf("\n");
	}

        if     ( nSearchType == REPLACE_TYPE_STRING )
		printf("------------------------------------------------------------------------------\n");
	
	else if( nSearchType == REPLACE_TYPE_UNICODE )
		printf("------------------------------------------------------------------------------\n");

	printf("\n");


}

long int CModule::GetStartAddress()
{
	return m_lStartAddress;
}

long int CModule::GetEndAddress()
{
	return m_lEndAddress;
}

long int CModule::GetMemorySize()
{
	return m_lMemorySize;
}

int CModule::GetParentProcessID()
{
	return m_nParentProcessID;
}

void CModule::SetModuleName(string strModuleName)
{
	m_strModuleName.clear();
	m_strModuleName = strModuleName;
}

string CModule::GetModuleName()
{
	return m_strModuleName;
}


