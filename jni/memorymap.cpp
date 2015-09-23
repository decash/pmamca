#include "memorymap.h"

CMemoryMap::CMemoryMap()
{
	m_vModuleList.clear();
	m_strMapPath.clear();
	m_nProcessID = -1;
	m_strProcessName.clear();
	m_nDisplayMemLineCount = 3;
}

void CMemoryMap::SetMapPath()
{
	char strMapPath[1024];
	memset(strMapPath, 0x00, 1024);
	
	snprintf(strMapPath, 1024, "/proc/%d/maps", m_nProcessID);
	m_strMapPath = strMapPath;
}

void CMemoryMap::SetDisplayLineCount(int nDisplayLineCount)
{
	m_nDisplayMemLineCount = nDisplayLineCount;
}

int CMemoryMap::GetProcessID()
{
	return m_nProcessID;
}

bool CMemoryMap::Attach()
{
	int nLoopCount = 0;	
	while( ptrace(PTRACE_ATTACH, m_nProcessID, 0, 0) != 0)
	{
		if(nLoopCount++ >= 1000)
			return false;
	}

	return true;

}

bool CMemoryMap::Detach()
{
	int nLoopCount = 0;	
	while( ptrace(PTRACE_DETACH, m_nProcessID, 0, 0) != 0)
	{
		if(nLoopCount++ >= 1000)
			return false;
	}

	return true;
}

string CMemoryMap::GetProcessName()
{
	return m_strProcessName;
}

int CMemoryMap::SetProcessID(string strProcessID)
{
	m_nProcessID = atoi(strProcessID.c_str());
	SetMapPath();
	m_strProcessName = GetProcessNameUsingProcessID(strProcessID);
	
	if( m_strProcessName.empty() == true )
	{
		m_nProcessID = -1;
		return -1;
	}
	return 1;
}

/*
// Android 4.2이하에서 동작하는 함수
// Android 4.3이상에서 root권한을 가지 모듈은 시스템 함수를 호출이 제한 
int CMemoryMap::GetProcessListByName(vector<string>& vProcessList, string strProcessName)
{
	int status = 0;
	int count = 0;
	char line[200];
	vProcessList.clear();

	cout << "+ SEARCH PROCESS LIST OF KEYWORD : " << strProcessName << endl;

	// ps 명령어를 실행하고 해당 명령어의 실행 결과를 fp 로 받는다
	FILE *fp = popen("ps", "r");
	fgets(line, 200, fp);
	memset(line, 0x00, 200);

	// ps 명령어 실행 결과에서 찾고자 하는 프로세스를 키워드로 찾는다
	while (1)
	{
		// 라인단위로 읽어온다
		if( fgets(line, 200, fp) == NULL )
		{
			if(count == 0)
			{
				cout << "+ can not find Process of " << strProcessName << endl;
				return -1;
			}
			else
				cout << "+ find Process list of "    << strProcessName << endl;
			break;
		}

		string strLine(line);

		// 읽어들인 문자열에서 찾는 키워드의 프로세스가 있는지 확인한다
		if( strLine.find( strProcessName ) != -1 )
		{
			count++;
			vProcessList.push_back(strLine);
		}
		memset(line, 0x00, 200);
	}
	status = pclose(fp);
	return 0;
}
*/

int CMemoryMap::GetProcessListByName(vector<string>& vProcessList, string strProcessName)
{
	vProcessList.clear();

	DIR *dir;                   
	struct dirent *entry;     
	struct stat fileStat;  

	int nProcessID;                      
	char strProcessNamePath[256];
	char strProcessStatusPath[256];
	char strTempProcessName[256];
	char strProcessInfo[512];
	memset(strProcessNamePath,   0x00, 256);
	memset(strProcessStatusPath, 0x00, 256);
	memset(strTempProcessName,   0x00, 256);
	memset(strProcessInfo,       0x00, 512);

	dir = opendir("/proc");   

	// proc 디렉토리를 모두 조사
	while (1) 
	{  
		// 라인단위로 읽어온다 
		entry = readdir(dir);
		if( entry == NULL )
		{
			if(vProcessList.size() == 0)
			{
				cout << "+ can not find Process of " << strProcessName << endl;
				return -1;
			}
			else
				cout << "+ find Process list of "    << strProcessName << endl;
			break;
		}

		// 파일 정보를 얻어 온다
		lstat(entry->d_name, &fileStat);

		// 디렉토리 인 경우
		if (S_ISDIR(fileStat.st_mode))
		{
			// 파일 이름을 얻어와 숫자료 변환한다
			nProcessID = atoi(entry->d_name);   
			
			// 파일 이름이 숫자 인 경우
			if (nProcessID > 0)
			{
				// 프로세스 이름을 얻어올 경로를 설정한다
				sprintf(strProcessNamePath, "/proc/%d/cmdline", nProcessID); 

				// 프로세스 이름을 얻어온다	
				FILE* fp = fopen(strProcessNamePath, "r");            
				if(fp != NULL)
				{
					fgets(strTempProcessName, 256, fp);
					string strLine(strTempProcessName);

					// 읽어들인 문자열에서 찾는 키워드의 프로세스가 있는지 확인한다
					if( strLine.size() != 0 && strLine.find( strProcessName ) != -1 )
					{
						sprintf(strProcessInfo, " [+] %5d   %s ", nProcessID, strLine.c_str() ); 
						vProcessList.push_back( string(strProcessInfo) );
					}

				}
			
				// 파일을 닫는다
				memset(strProcessNamePath, 0x00, 256);
				memset(strTempProcessName, 0x00, 256);
				memset(strProcessInfo, 0x00, 512);
				fclose(fp);
			}
		}

	}

	// 디렉토리를 닫는다
	closedir(dir);
}

bool CMemoryMap::LoadWhiteList()
{
	char strLine[1024];
	char* pLine = NULL;

	FILE *fp = fopen(WHITE_LIST_NAME, "r");

	if( fp != NULL )	
	{
		while( !feof(fp)  )
		{
			memset(strLine, 0x0, 1024);
			fgets(strLine, 1024, fp);

			// 개행문자 제거
			if( ( pLine = strchr(strLine, '\n') ) != NULL)
				*pLine ='\0';

			// 개행문자 제거
			if( ( pLine = strchr(strLine, '\r') ) != NULL)
				*pLine ='\0';

			string Line(strLine);
			// "MODULE=" 제거, vector에 저장
			if(Line.compare(0, 7, "MODULE=") == 0)
				m_vWhiteList.push_back(Line.substr(7));	
			else if( Line.size() > 31 && Line.compare(0, 31, "DISPLAY_MEMORY_DUMP_LINE_COUNT=") == 0) 
			{
				m_nDisplayMemLineCount = atoi(Line.substr(31).c_str());
			}
		}
	}
	else
		return false;

	fclose(fp);
	return true;
}

bool CMemoryMap::LoadModuleList()
{
	char* pLine = NULL;
	char strLine[1024];
	memset(strLine, 0x0, 1024);

	// 프로세스의 메모리 정보(/proc/"PID"/maps)를 읽어 온다 
	FILE *fp = fopen(m_strMapPath.c_str(), "r");
	if(fp == NULL) 
		return false;

	vector<string>::iterator i;
	while( fgets( strLine, 1024, fp) != NULL )
	{
		// 읽어온 각각의 모듈정보에서 마지막 개행문자를 NULL로 교체
		if( ( pLine = strchr(strLine, '\n') ) != NULL)
			*pLine ='\0';

		// 읽어온 모듈 정보가 50보다 큰 경우(모듈이름이 기제되어 있는 경우)
		if(string(strLine).size() > 50)
		{
			// 읽어온 화이트 리스트와 비교
			for(i = m_vWhiteList.begin(); i != m_vWhiteList.end(); i++)
			{	
				string strModuleInfo = string(strLine);
				string strWhiteList  = *i;

				// 화이트 리스트에 있는 이름과 모듈이름에 포함되어 있는지 판별
				// 모듈의 메모리 영역이 읽기 모드인지 판별
				if( strModuleInfo.find(strWhiteList.substr(0, strWhiteList.size()-1))  != -1  &&
			            //strModuleInfo[18] == 'r') 
			            strModuleInfo[18] == 'r' && strModuleInfo[19] == 'w') 
				{
					AddModuleToList( strLine );
					break;
				}

			}
		}
		memset(strLine, 0x0, 1024);
	}
	return true;
}

int CMemoryMap::GetAllModuleInfo(vector<string>& vStrModuleList)
{
	char* pLine = NULL;
	char strLine[1024];
	memset(strLine, 0x00, 1024);

	// 프로세스의 메모리 정보(/proc/"PID"/maps)를 읽어 온다 
	FILE *fp = fopen(m_strMapPath.c_str(), "r");
	if( fp == NULL )	
		return -1;

	vector<string>::iterator i;
	while( fgets( strLine, 1024, fp) != NULL )
	{
		// 읽어온 각각의 모듈정보에서 마지막 개행문자를 NULL로 교체
		if( ( pLine = strchr(strLine, '\n') ) != NULL)
			*pLine ='\0';

		// 읽어온 모듈 정보가 50보다 큰 경우(모듈이름이 기제되어 있는 경우)
		// 모듈의 메모리 영역이 읽기 모드인 경우
		string strModuleInfo = string(strLine);
		if(strModuleInfo.size() > 50 && strModuleInfo[18] == 'r')
			vStrModuleList.push_back( strModuleInfo );

		memset(strLine, 0x00, 1024);
	}

	return 0;
}

int CMemoryMap::GetAllModuleName(vector<string>& vStrModuleList)
{
	char* pLine = NULL;
	char strLine[1024];
	memset(strLine, 0x00, 1024);

	// 프로세스의 메모리 정보(/proc/"PID"/maps)를 읽어 온다 
	FILE *fp = fopen(m_strMapPath.c_str(), "r");
	if( fp == NULL )	
		return -1;

	vector<string>::iterator i;
	while( fgets( strLine, 1024, fp) != NULL )
	{
		// 읽어온 각각의 모듈정보에서 마지막 개행문자를 NULL로 교체
		if( ( pLine = strchr(strLine, '\n') ) != NULL)
			*pLine ='\0';

		// 읽어온 모듈 정보가 50보다 큰 경우(모듈이름이 기제되어 있는 경우)
		// 모듈의 메모리 영역이 읽기 모드인 경우
		string strModuleInfo = string(strLine);
		//if(strModuleInfo.size() > 50 && strModuleInfo[18] == 'r' && strModuleInfo[18] == 'w')
		if(strModuleInfo.size() > 50 && strModuleInfo[18] == 'r')
		{
			string strModuleName   = strModuleInfo.substr(49    );
			vStrModuleList.push_back( strModuleName );
		}

		memset(strLine, 0x00, 1024);
	}

	return 0;
}

/*
// Android 4.2이하에서 동작하는 함수
// Android 4.3이상에서 root권한을 가지 모듈은 시스템 함수를 호출이 제한 
string CMemoryMap::GetProcessNameUsingProcessID(string strProcessID)
{
	// ProcessID가 지정되어 있지 않은경우 NULL 리턴
	if(m_nProcessID == -1)	
		return NULL;

	int status = 0;
	int count = 0;
	char line[100];
	char* pLine = NULL;

	// ps 명령어를 실행하고 해당 명령어의 실행 결과를 fp 로 받는다
	FILE *fp = popen("ps", "r");

	// ps 명령어 실행 결과에서 찾고자 하는 프로세스를 키워드로 찾는다
	while ( fgets(line, 100, fp) != NULL )
	{
		// 개행문자 제거
		if( ( pLine = strchr(line, '\n') ) != NULL)
			*pLine ='\0';

		// 라인단위로 읽어온다
		// 읽어들인 문자열에서 찾는 프로세스ID가 있는지 확인한다
		if(string(line).size() > 10)
		{
			string strTemp = string(line).substr(10, 6);
			if( strTemp.find( strProcessID ) == 0 )
			{
				pclose(fp);
				return string(line).substr(55); 
			}
		}

	}
	pclose(fp);
	return string("");
}
*/


string CMemoryMap::GetProcessNameUsingProcessID(string strProcessID)
{
	// ProcessID가 지정되어 있지 않은경우 NULL 리턴
	if(m_nProcessID == -1)	
		return NULL;

	// 프로세스 이름을 얻어올 경로를 설정한다
	char strProcessNamePath[256];
	memset(strProcessNamePath, 0x00, 256);
	sprintf(strProcessNamePath, "/proc/%d/cmdline", atoi(strProcessID.c_str()) ); 

	// 프로세스 이름을 얻어온다	
	FILE* fp = fopen(strProcessNamePath, "r");            
	if(fp != NULL)
	{
		char strTempProcessName[256];
		memset(strTempProcessName, 0x00, 256);
		fgets(strTempProcessName, 256, fp);
		fclose(fp);

		return string(strTempProcessName);
	}
	return string("");
}


void CMemoryMap::AddModuleToList(string strModuleInfo)
{
	// MAPS FORMAT
	// 0123456789x123456789x123456789x123456789x123456789x1234567
	// ffff0000-ffff1000 r-xp 00000000 00:00 0          [vectors]
        // 40c6a000-41fbc000 rw-p 00000000 00:04 8256       /dev/ashmem/dalvik-heap (deleted)
	string strStartAddress = strModuleInfo.substr( 0,  8);
	string strEndAddress   = strModuleInfo.substr( 9,  8);
	string strModuleName   = strModuleInfo.substr(49    );

	// Add Module To VectorList
	m_vModuleList.push_back( CModule(GetProcessID(), strStartAddress, strEndAddress, strModuleName, m_nDisplayMemLineCount) );
}


vector<CModule> CMemoryMap::GetModuleList()
{
 	return m_vModuleList;
}

void CMemoryMap::ClearModuleList()
{
	m_vModuleList.clear();
}

bool CMemoryMap::GetModuleListByModuleNameList(vector<string> vStrModuleNameList, vector<CModule>& vModuleList)
{
	char* pLine = NULL;
	char strLine[1024];
	memset(strLine, 0x0, 1024);

	// 프로세스의 메모리 정보(/proc/"PID"/maps)를 읽어 온다 
	FILE *fp = fopen(m_strMapPath.c_str(), "r");
	if(fp == NULL) 
		return false;

	vector<string>::iterator i;
	while( fgets( strLine, 1024, fp) != NULL )
	{
		// 읽어온 각각의 모듈정보에서 마지막 개행문자를 NULL로 교체
		if( ( pLine = strchr(strLine, '\n') ) != NULL)
			*pLine ='\0';

		// 읽어온 모듈 정보가 50보다 큰 경우(모듈이름이 기제되어 있는 경우)
		if(string(strLine).size() > 50)
		{
			// 읽어온 화이트 리스트와 비교
			for(i = vStrModuleNameList.begin(); i != vStrModuleNameList.end(); i++)
			{	
				string strModuleInfo = string(strLine);
				string strModuleList  = *i;

				// 화이트 리스트에 있는 이름과 모듈이름에 포함되어 있는지 판별
				// 모듈의 메모리 영역이 읽기 모드인지 판별
				if( strModuleInfo.substr(49).compare(strModuleList) == 0  &&
				//		strModuleInfo[18] == 'r' && strModuleInfo[19] == 'w') 
						strModuleInfo[18] == 'r' ) 
				{
					string strModuleInfo   = string( strLine );
					string strStartAddress = strModuleInfo.substr( 0,  8);
					string strEndAddress   = strModuleInfo.substr( 9,  8);
					string strModuleName   = strModuleInfo.substr(49    );

					// Add Module To VectorList
					vModuleList.push_back( CModule(GetProcessID(), strStartAddress, strEndAddress, strModuleName, m_nDisplayMemLineCount) );
				}
			}

		}
		memset(strLine, 0x0, 1024);
	}

	return true; 

}
