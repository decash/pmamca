#include "util.h"

using namespace std;

void DisplayLine(int nLineType, int nLineRow)
{
	if(nLineType == LINE_TYPE_NULL)
	{
		for(int i = 0; i < nLineRow; i++)
			cout << endl;
	}
	else if(nLineType == LINE_TYPE_DASH)
	{
		for(int i = 0; i < nLineRow; i++)
			cout << "+-----------------------------------------------------------+" << endl;
	}
}

void DisplayList(vector<string>& vList, int nDisplayType)
{
	int index = 1;

	if( nDisplayType == LIST_TYPE_RAW)
	{
		vector<string>::iterator i;
		for(i = vList.begin(); i != vList.end(); i++)
			cout << *i ;
	}
	else if(nDisplayType == LIST_TYPE_ITEM)
	{
		vector<string>::iterator i;
		for(i = vList.begin(); i != vList.end(); i++)
			cout << "+ [ITEM " << index++ << "]:" << *i << endl ;

	}
	else if(nDisplayType == LIST_TYPE_PROCESS)
	{
		DisplayLine(LINE_TYPE_DASH, 1);
		cout << " [*]   PID   ProcessName" << endl; 

		vector<string>::iterator i;
		for(i = vList.begin(); i != vList.end(); i++)
		{
			cout << *i << endl;	
		}
		/*
		cout << "+ USER       PID    NAME" << endl; 
		
		vector<string>::iterator i;
		for(i = vList.begin(); i != vList.end(); i++)
		{
			// 0123456789x123456789x123456789x123456789x123456789x123456789 
			// USER     PID   PPID  VSIZE  RSS     WCHAN    PC         NAME
			// root      1     0     468    332   c01356cc 0000e614 S /init
			cout << "+ ";	
			cout << setiosflags(ios::left) 
		             << setw(11) << i->substr( 0, 9)
			     << setw( 7) << i->substr(10, 6)
			     		 << i->substr(55   );
		}
		*/
	}
	else if(nDisplayType == LIST_TYPE_MODULE)
	{
		vector<string>::iterator i;
		for(i = vList.begin(); i != vList.end(); i++)
			cout << "[" << i -vList.begin() + 1 <<"] " << *i << endl;
	}
}

void StringTokenizer(vector<string>& vList, string strTarget, string strTok)
{
	int     nCutPos;
	int     nIndex     = 0;

	while ((nCutPos = strTarget.find_first_of(strTok)) != strTarget.npos)
	{
		if (nCutPos > 0)
		{
			vList.push_back(strTarget.substr(0, nCutPos));
		}
		strTarget = strTarget.substr(nCutPos+1);
	}

	if(strTarget.length() > 0)
	{
		vList.push_back(strTarget.substr(0, nCutPos));
	}

}   

string GetCurrentPath()
{
	char line[100];
	memset(line, 0x00, 100);
	
	getcwd(line, 100);

	return string(line);
}

string GetFilePath()
{
	// 폴더 경로 생성	
	int nFolderCnt = 1;
	char strFolderPath[20];
	string strCurrentPath = GetCurrentPath();
	string strFullPath;
	while(1)
	{
		strFullPath += strCurrentPath;
		strFullPath += '/';
	
		memset( strFolderPath, 0x00, 20);
		sprintf(strFolderPath, "AMC-DUMP-[%d]", nFolderCnt++);  
		
		strFullPath += string(strFolderPath);

		if( mkdir( strFullPath.c_str(), S_IRWXU | S_IRWXG ) == 0 ) break;
		else strFullPath.clear();

		if( nFolderCnt > 1000) return string(NULL);
	}

	return strFullPath;
}

int SaveToFile(string strFolderPath, string strFileName, unsigned char* pData, int nFileSize)
{
	char       strFileFullName[200];
	FILE*      fp = NULL;
	int static nFileCnt = 1;

	// 모듈명을 파일 이름으로 활용하기 위해서 '/'를 '-'로 교체
	for(int i = 0; i < strFileName.size(); i++)
		if(strFileName[i] == '/') strFileName[i] = '-';
		
	// 파일 이름을 포함한 파일 전체 경로 생성 
	memset( strFileFullName, 0x00, 200);
	sprintf(strFileFullName, "%s/DUMP-[%d]-[%s].txt", strFolderPath.c_str(), nFileCnt++, strFileName.c_str());
	fp = fopen(strFileFullName, "wb");
	if( fp == NULL ) return -1;

	// FILE WRITE
	fwrite(pData, nFileSize, 1, fp); 
	
	fclose(fp);
	chmod(strFileFullName, 0777);

	return 0;
}

bool LoadItemList(vector<string>& vStrItemList)
{
	char* pLine = NULL;
	char strLine[1024];
	memset(strLine, 0x0, 1024);

	FILE *fp = fopen(ITEM_LIST_FILE_NAME, "r");
	if(fp == NULL) 
		return false;

	while( fgets( strLine, 1024, fp) != NULL )
	{
		// 읽어온 각각의 모듈정보에서 마지막 개행문자를 NULL로 교체
		if( ( pLine = strchr(strLine, '\n') ) != NULL)
			*pLine ='\0';

		// 읽어온 각각의 모듈정보에서 마지막 개행문자를 NULL로 교체
		if( ( pLine = strchr(strLine, '\r') ) != NULL)
			*pLine ='\0';


		string Line(strLine);
		if(Line.compare(0, 5, "ITEM=") == 0)
			vStrItemList.push_back( Line.substr(5) );

		memset(strLine, 0x0, 1024);
	}
	return true;
}

void SearchItemInFile(vector<string>& vStrSearchItemList, string strFilePath)
{
	string strFileFullPath("/data/data/");
	strFileFullPath += strFilePath;

	vector<string>::iterator itr;
	for( itr = vStrSearchItemList.begin(); itr < vStrSearchItemList.end(); itr++ )
	{
		// SEARCH PLAIN ITEM
		string strSearchPlainItem = *itr;
		cout << "[+] START SEARCH ITEM [PLAIN] : [" << strSearchPlainItem <<"]" << endl;

		char strFindCommand[200];
		memset(strFindCommand, 0x00, 200);
		sprintf(strFindCommand, "find %s ! -type d ! -name \"*.so\" ! -name \"*.der\" ! -name \"*.jpg\" ! -name \"*.png\" -name \"*\" | xargs -n 20 grep \"%s\" -s", strFileFullPath.c_str(), strSearchPlainItem.c_str() );  
		cout << "[+] " << strFindCommand << endl;  

		system(strFindCommand);
		cout << "[-] END SEARCH ITEM [PLAIN] : [" << strSearchPlainItem <<"]" << endl << endl;

		// SEARCH BASE64 ITEM
		int nKeywordSize = strSearchPlainItem.size();
		string strSearchBase64Item = base64_encode((unsigned char*)strSearchPlainItem.c_str(), nKeywordSize);
		cout << "[+] START SEARCH ITEM [BASE64] : [" << strSearchBase64Item <<"]" << endl;
		
		memset(strFindCommand, 0x00, 200);
		sprintf(strFindCommand, "find %s ! -type d ! -name \"*.so\" ! -name \"*.der\" ! -name \"*.jpg\" ! -name \"*.png\" -name \"*\" | xargs -n 20 grep \"%s\" -s", strFileFullPath.c_str(), strSearchBase64Item.c_str() );  
		cout << "[+] " << strFindCommand << endl;  

		system(strFindCommand);
		cout << "[-] END SEARCH ITEM [BASE64] : [" << strSearchBase64Item <<"]" << endl << endl << endl;
	}

}



