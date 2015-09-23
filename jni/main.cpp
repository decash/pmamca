#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <vector>
#include <iostream>
#include <algorithm>
#include "memorymap.h"
#include "util.h"
#include "packet.h"

// #NAME SPCAE DEFINE
using namespace std;

// #DEFINE
#define MAX_STRING_SIZE       100
#define FSA_AMC_VERSION       "1.2.0"

// #FUNCTION DEFINE
int  DisplayMenu();
void DisplayInfo(vector<string>& vList);
int  ProcessUserTask(int nSelectedMenuNumber);

// #GLOVAL VALUE DEFINE
vector<string>  vStrItemList;
vector<string>  vStrAllModuleList;
CMemoryMap      MemoryMap;

int main(int argc, char **argv)
{
	// Display Version
	cout << "[*] AMC Version : " << FSA_AMC_VERSION;

	// Load "white.txt"
	if( MemoryMap.LoadWhiteList() == false)
	{
		cout <<"[!] LOAD WHITE LIST FAIL!" ;
		return -1;
	}

	// Load "amc_item.txt" 
	DisplayLine(LINE_TYPE_NULL, 1);
	if( LoadItemList(vStrItemList) == true )
	{
		cout <<"[*] LOAD ITEM LIST!" ;
	}

	// 메뉴입력 처리 
	DisplayLine(LINE_TYPE_NULL, 1);
	while(1)
	{
		DisplayInfo(vStrItemList);

		if ( ProcessUserTask( DisplayMenu() ) == -1 )
			break;
	}

	return 0;
}

int ProcessUserTask(int nSelectedMenuNumber)
{
	char strProcessName[MAX_STRING_SIZE]; 
	char strProcessID[MAX_STRING_SIZE]; 
	char strDummyItem[MAX_STRING_SIZE];
	char*          ptrTemp   = NULL;
	unsigned char* pDumpData = NULL;

	memset(strProcessName, 0x00, MAX_STRING_SIZE);
	memset(strProcessID,   0x00, MAX_STRING_SIZE);
	memset(strDummyItem,   0x00, MAX_STRING_SIZE);

	vector<CModule> vModuleList;
	vector<CModule>::iterator i;

	switch( nSelectedMenuNumber )
	{
		case '1' :
		{
			cout << "  [1]>>>> INPUT PROCESS KEYWORD : " ; 
			cin.getline(strProcessName, MAX_STRING_SIZE);

			DisplayLine(LINE_TYPE_NULL, 2);
			DisplayLine(LINE_TYPE_DASH, 1);

			//  키워드로 검색된 프로세스 리스트를 보여준다
			vector<string>  vStrProcessList;
			if( MemoryMap.GetProcessListByName(vStrProcessList, strProcessName) != -1 )
				DisplayList(vStrProcessList, LIST_TYPE_PROCESS);


			// 검색된 결과가 1개 인 경우 곧바로 Process를 SET한다
			if( vStrProcessList.size() == 1 )
				MemoryMap.SetProcessID( vStrProcessList[0].substr(5, 5) ); 

			DisplayLine(LINE_TYPE_DASH, 1);
			DisplayLine(LINE_TYPE_NULL, 2);

			vStrProcessList.clear();

			break;
		}

		case '2' :
				cout << "  [2]>>>> INPUT PROCESS ID : " ; 
				cin.getline(strProcessID, MAX_STRING_SIZE);

				DisplayLine(LINE_TYPE_NULL, 1);

				// 입력된 프로세스 아이디를 저장해둔다
				if( MemoryMap.SetProcessID(strProcessID) == -1 )
					cout <<"+ CAN'T FIND PROCESS ID(" << strProcessID << ")!" << endl;		
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;

		case '3' :	
				cout << "  [3]>>>> INPUT ITEM for ADD(you can input one or multiple item) : " ; 
				cin.getline(strDummyItem, MAX_STRING_SIZE);

				// 입력된 문자열에서 공백을 기준으로 아이템을 나누고 이를 리스트에 저장	
				StringTokenizer(vStrItemList, string(strDummyItem), string(" "));

				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;

		case '4' :
		{
			cout << "  [4]>>>> INPUT ITEM NUMBER for DELETE(you can input one item number) : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);


			int nInputNumber = atoi(strDummyItem);
			int nItemCount = vStrItemList.size();
			if( nInputNumber > 0 || nInputNumber <= nItemCount )
				vStrItemList.erase( vStrItemList.begin()+nInputNumber-1 );
			else
				printf("  [!]PLEASE ENTER A NUMBER BETWEEN %d to %d NUMBER!\n", 1, nItemCount);

			DisplayLine(LINE_TYPE_DASH, 1);
			DisplayLine(LINE_TYPE_NULL, 2);

			break;
		}

		case '5' :
		{
			if(vStrItemList.size() == 0)
			{
				cout << "  [!]PLEASE ADD an ITEM by USING the MENU[3]!" << endl;					
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}

			cout << "  [5]>>>> INPUT ITEM NUMBER(you can input one or multiple item number) : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);

			// 찾을 ITEM의 번호를 받아온다  
			vector<string> vStrTempList;
			StringTokenizer(vStrTempList, string(strDummyItem), string(" "));

			// 입력된 문자열이 숫자 인지 검증


			// 찾을 ITEM을 String으로 구성한다
			vector<string> vStrSearchList;
			vector<string>::iterator itr;
			for( itr = vStrTempList.begin(); itr < vStrTempList.end(); itr++ )
			{
				string strSelectItemIndex = *itr;
				int    nSelectItemIndex   = atoi( strSelectItemIndex.c_str() ) - 1;

				// 입력된 아이템 번호의 유효성 검증 시행
				if( nSelectItemIndex < 0 || nSelectItemIndex >= vStrItemList.size() )
				{
					printf("  [!]PLEASE ENTER A NUMBER BETWEEN %d to %d NUMBER!\n", 1, vStrItemList.size());
					return 0;
				}
				vStrSearchList.push_back( vStrItemList[nSelectItemIndex] );
			}

			DisplayLine(LINE_TYPE_NULL, 1);
			DisplayLine(LINE_TYPE_DASH, 1);

			// 프로세스에 연결된 모듈 리스트에서 white.txt에 명시된 모듈 로드
			if( MemoryMap.LoadModuleList() == false )
			{
				cout << "  [!]FAIL TO READ MEMORY MAP!" << endl;
				cout << "  [!]PLEASE FIND THE PROCESS AGAIN by USING the MENU[1], [2]" << endl;
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}

			// 로드된 모듈의 메모리 영역에서 아이템을 찾는다 
			vModuleList = MemoryMap.GetModuleList();

			// PROCESS ATTACH
			MemoryMap.Attach();

			// 로드된 모듈별로 처리한다
			int nCheckLoopCount = 1;
			int nTotalLoopCount = vModuleList.size();
			for(i = vModuleList.begin(); i !=  vModuleList.end(); i++)
			{
				// 메모리 덤프 사이즈 만큼 메모리 할당	
				pDumpData = (unsigned char*) malloc(i->GetMemorySize()); 
				if(pDumpData == NULL)
					cout << "Memory Alloc Fail for Dump!" << endl;

				// 덤프 시작 메세지 출력
				DisplayLine(LINE_TYPE_DASH, 1);
				printf( "[+] [%d / %d] START DUMP [%s]'s MEMORY at [0x%08x]-[0x%08x] / SIZE[%s]\n", 
						nCheckLoopCount, 
						nTotalLoopCount, 
						i->GetModuleName().c_str(), 
						(unsigned int)i->GetStartAddress(), 
						(unsigned int)i->GetEndAddress(), 
						i->GetStrMemorySize().c_str() );    

				//  메모리 덤프
				i->GetDumpMemory(pDumpData);

				// 덤프 종료 메세지 출력
				printf( "[+] [%d / %d] FINISH DUMP\n", nCheckLoopCount++, nTotalLoopCount);    

				// 덤프한 메모리에서 키워드를 찾는다
				i->SearchOfMemory(vStrSearchList, pDumpData, i->GetStartAddress(), i->GetMemorySize()); 
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 1);

				// 메모리 해제
				free(pDumpData);
			}

			// PROCESS DETACH
			MemoryMap.Detach();

			// 이용한 모듈리스트를 clear한다
			MemoryMap.ClearModuleList();
			vModuleList.clear();
			vStrTempList.clear();
			vStrSearchList.clear();
			break;
		}

		case '6' :
		{
			if(vStrItemList.size() == 0)
			{
				cout << "  [!]PLEASE ADD an ITEM by USING the MENU[3]!" << endl;					
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}


			cout << "  [6]>>>> INPUT ITEM NUMBER(you can input one item number) : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);

			// 찾을 ITEM의 번호를 받아온다  
			vector<string> vStrTempList;
			StringTokenizer(vStrTempList, string(strDummyItem), string(" "));

			// 찾을 ITEM을 String으로 구성한다
			vector<string> vStrSearchList;
			vector<string>::iterator itr;
			for( itr = vStrTempList.begin(); itr < vStrTempList.end(); itr++ )
			{
				string strSelectItemIndex = *itr;
				int    nSelectItemIndex    = atoi( strSelectItemIndex.c_str() ) - 1;
				
				// 입력된 아이템 번호의 유효성 검증 시행
				if( nSelectItemIndex < 0 || nSelectItemIndex >= vStrItemList.size() )
				{
					printf("  [!]PLEASE ENTER A NUMBER BETWEEN %d to %d !\n", 1, vStrItemList.size());
					return 0;
				}
			
				vStrSearchList.push_back( vStrItemList[nSelectItemIndex] );
			}

			if(vStrSearchList.size() > 1)
			{
				cout << " [!] YOU MUST INPUT ONE ITEM NUMBER!" << endl;

				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				vStrSearchList.clear();
				break;
			}

			DisplayLine(LINE_TYPE_NULL, 1);
			DisplayLine(LINE_TYPE_DASH, 1);

			// 프로세스에 연결된 모듈 리스트에서 white.txt에 명시된 모듈 로드
			if( MemoryMap.LoadModuleList() == false )
			{
				cout << "  [!]FAIL TO READ MEMORY MAP!" << endl;
				cout << "  [!]PLEASE FIND THE PROCESS AGAIN by USING the MENU[1], [2]" << endl;
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}

			// 로드된 모듈의 메모리 영역에서 아이템을 찾는다 
			vModuleList = MemoryMap.GetModuleList();

			// 로드된 모듈별로 처리한다
			int nCheckLoopCount = 1;
			int nTotalLoopCount = vModuleList.size();
			int nSearchStringSize  = vStrSearchList[0].size(); 

			// PROCESS ATTACH
			MemoryMap.Attach();

			// 로드된 모듈별로 처리한다
			for(i = vModuleList.end()-1; i >=  vModuleList.begin(); i--)
			{
				// 덤프 시작 메세지 출력
				DisplayLine(LINE_TYPE_DASH, 1);
				printf( "[+] [%d / %d] START DUMP [%s]'s MEMORY at [0x%08x]-[0x%08x] / SIZE[%s]\n", 
						nCheckLoopCount, nTotalLoopCount, (i->GetModuleName()).c_str(), 
						(unsigned int)i->GetStartAddress(), (unsigned int)i->GetEndAddress(), i->GetStrMemorySize().c_str() );    

				for(int j = 0; j < 5; j++)
				{
					// 덤프할 사이즈를 계산한다
					int nPartDumpSize = 0;
					if( j == 4)
						// 마지막 남은 영역을 모두 덤프한다
						nPartDumpSize = i->GetMemorySize() - ( i->GetMemorySize() / 5) * 4;
					else
					        // 찾을 문자열 길이만큼 더 덤프한다
						nPartDumpSize = i->GetMemorySize() / 5 + nSearchStringSize;

					// 덤프를 4byte단위로 하기 때문에 4배수로 맞추어준다
					if(nPartDumpSize % 4 != 0)
						nPartDumpSize = ((nPartDumpSize / 4) + 1) * 4;

					long int lMemorySize   = i->GetMemorySize() / 5;
					long int lStartAddress = i->GetStartAddress() + lMemorySize * j;

					// 메모리 덤프 사이즈 만큼 메모리 할당	
					pDumpData = (unsigned char*) malloc(nPartDumpSize); 
					if(pDumpData == NULL)
						cout << "Memory Alloc Fail for Dump!" << endl;

					DisplayLine(LINE_TYPE_DASH, 1);
					printf("  [+] START PART DUMP [%d] OF [%d]\n", j+1,5);

					//  메모리 덤프
					i->GetPartDumpMemory(pDumpData, 5, j, nPartDumpSize);

					printf("  [-] END   PART DUMP [%d] OF [%d]\n", j+1, 5);
					DisplayLine(LINE_TYPE_DASH, 1);

					// 덤프한 메모리에서 키워드를 찾는다
					if( i->SearchOfMemory(vStrSearchList, pDumpData, lStartAddress, nPartDumpSize) == true ) 
					{
						while(1)
						{
							cout << endl << "[+] SELECT CONTINUE(c) or QUIT(q) : ";
							char strCheckContinue[MAX_STRING_SIZE];
							memset(strCheckContinue, 0x00, MAX_STRING_SIZE);
							cin.getline(strCheckContinue, MAX_STRING_SIZE);

							if(      strCheckContinue[0] == 'c' ) break;
							else if( strCheckContinue[0] == 'q' )
							{
								DisplayLine(LINE_TYPE_DASH, 1);
								DisplayLine(LINE_TYPE_NULL, 2);

								// PROCESS DETACH
								MemoryMap.Detach();

								// 이용한 모듈리스트를 clear한다
								MemoryMap.ClearModuleList();
								vModuleList.clear();
								vStrTempList.clear();
								vStrSearchList.clear();

								// 메모리 해제
								free(pDumpData);
								return 1;
							}
						}
					}

					// 메모리 해제
					free(pDumpData);
				}
				// 덤프 종료 메세지 출력
				printf( "[+] [%d / %d] FINISH DUMP\n\n", nCheckLoopCount++, nTotalLoopCount);    
			}


			// PROCESS DETACH
			MemoryMap.Detach();

			// 이용한 모듈리스트를 clear한다
			MemoryMap.ClearModuleList();
			vModuleList.clear();
			vStrTempList.clear();
			vStrSearchList.clear();
			break;
		}

		case '7' :
		{
			if(vStrItemList.size() < 2)
			{
				cout << "  [!]PLEASE ADD the TWO or MORE ITEMs by USING the MENU[3]!" << endl;
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}

			cout << "  [7]>>>> INPUT ITEM NUMBER(you can input two or multiple item number) : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);

			// 찾을 ITEM의 번호를 받아온다  
			vector<string> vStrTempList;
			StringTokenizer(vStrTempList, string(strDummyItem), string(" "));

			// 짝수개의 아이템 번호를 입력하였는지 확인
			if(vStrTempList.size() % 2 == 1)
			{
				cout << vStrTempList.size() << endl;
				cout << "  [!]PLEASE ENTER the EVEN NUMBER of ITEMs TO BE EXCHANGED!" << endl;
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}


			// 찾을 ITEM을 String으로 구성한다
			vector<string> vStrReplaceList;
			vector<string>::iterator itr;
			for( itr = vStrTempList.begin(); itr < vStrTempList.end(); itr++ )
			{
				string strSelectItemIndex = *itr;
				int    nSelectItemIndex    = atoi( strSelectItemIndex.c_str() ) - 1;
				vStrReplaceList.push_back( vStrItemList[nSelectItemIndex] );
			}

			DisplayLine(LINE_TYPE_NULL, 1);
			DisplayLine(LINE_TYPE_DASH, 1);

			// 프로세스에 연결된 모듈 리스트에서 white.txt에 명시된 모듈 로드
			if( MemoryMap.LoadModuleList() == false )
			{
				cout << "  [!]FAIL TO READ MEMORY MAP!" << endl;
				cout << "  [!]PLEASE FIND THE PROCESS AGAIN by USING the MENU[1], [2]" << endl;

				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;

			}

			// 로드된 모듈의 메모리 영역에서 아이템을 찾는다 
			vModuleList = MemoryMap.GetModuleList();

			// PRCESS ATTACH
			MemoryMap.Attach();

			// 로드된 모듈별로 처리한다
			int nCheckLoopCount = 1;
			int nTotalLoopCount = vModuleList.size();
			for(i = vModuleList.begin(); i !=  vModuleList.end(); i++)
			{
				// 메모리 덤프 사이즈 만큼 메모리 할당	
				pDumpData = (unsigned char*) malloc(i->GetMemorySize()); 
				if(pDumpData == NULL)
					cout << "Memory Alloc Fail for Dump!" << endl;

				// 덤프 시작 메세지 출력
				DisplayLine(LINE_TYPE_DASH, 1);
				printf( "[+] [%d / %d] START DUMP [%s]'s MEMORY at [0x%08x]-[0x%08x] / SIZE[%s]\n", 
						nCheckLoopCount, 
						nTotalLoopCount, 
						i->GetModuleName().c_str(), 
						(unsigned int)i->GetStartAddress(), 
						(unsigned int)i->GetEndAddress(), 
						i->GetStrMemorySize().c_str() );    


				//  메모리 덤프
				i->GetDumpMemory(pDumpData);

				// 덤프 종료 메세지 출력
				printf( "[+] [%d / %d] FINISH DUMP\n", nCheckLoopCount++, nTotalLoopCount);    

				// 덤프한 메모리에서 키워드를 찾는다
				//i->ReplaceOfMemory(vStrReplaceList, pDumpData, i->GetStartAddress(), i->GetMemorySize()); 
				i->ReplaceOfMemory(vStrReplaceList, pDumpData, i->GetStartAddress(), i->GetMemorySize());
				
				// 메모리 해제
				free(pDumpData);
			}
			// PROCESS DETACH
			MemoryMap.Detach();

			// 이용한 모듈리스트를 clear한다
			MemoryMap.ClearModuleList();
			vModuleList.clear();
			vStrTempList.clear();
			vStrReplaceList.clear();

			break;
		}

		case '8' :
		{
				int nStaticCnt = 0;
				nStaticCnt++;
					
				cout << "  [*]>>>> START DUMP\n" ; 
				DisplayLine(LINE_TYPE_DASH, 1);

				// 프로세스에 연결된 모듈 리스트에서 white.txt에 명시된 모듈 로드
				if( MemoryMap.LoadModuleList() == false )
				{
					cout << "  [!]FAIL TO READ MEMORY MAP!" << endl;
					cout << "  [!]PLEASE FIND THE PROCESS AGAIN by USING the MENU[1], [2]" << endl;

					DisplayLine(LINE_TYPE_DASH, 1);
					DisplayLine(LINE_TYPE_NULL, 2);

					break;
				}

				// 로드된 모듈의 메모리 영역에서 아이템을 찾는다 
				vModuleList = MemoryMap.GetModuleList();

				// PROCESS ATTACH
				MemoryMap.Attach();

				// Get DUMP FolderPATH
				string strFolderPath = GetFilePath();

				// 로드된 모듈별로 처리한다
				int nFileCnt   = 1;
				int nModuleCnt = vModuleList.size(); 
				for(i = vModuleList.begin(); i !=  vModuleList.end(); i++)
				{
					// 메모리 덤프 사이즈 만큼 메모리 할당	
					pDumpData = (unsigned char*) malloc(i->GetMemorySize()); 
					if(pDumpData == NULL)
					{
						cout << "Memory Alloc Fail for Dump!" << endl;
						break;
					}
					memset(pDumpData, 0x00, i->GetMemorySize());

					printf( " [-] [%d / %d] START File DUMP [%s] / SIZE[%s]\n", 
							nFileCnt, 
							nModuleCnt, 
							i->GetModuleName().c_str(), 
							i->GetStrMemorySize().c_str() );    

					//  메모리 덤프
					i->GetDumpMemory(pDumpData);

					// FILE에 저장한다
					int nResult = SaveToFile(strFolderPath, i->GetModuleName(), pDumpData, i->GetMemorySize());
					if(nResult == 0)
						printf(" [+] [%d / %d] DUMP FILE(%s) SAVED! \n\n", 
							nFileCnt, nModuleCnt, i->GetModuleName().c_str());
					else
						printf(" [!] [%d / %d] DUMP FILE(%s) SAVED ERROR! \n\n", 
							nFileCnt, nModuleCnt, i->GetModuleName().c_str());

					nFileCnt++;

					// 메모리 해제
					free(pDumpData);
				}
				// chmod 777
				DisplayLine(LINE_TYPE_DASH, 1);
				chmod(strFolderPath.c_str(), 0777);
				printf( "[*] EXCUTED CHANGE PERMISSION(chmod -R 777 %s)\n", strFolderPath.c_str() );	

				// Create adb command
				DisplayLine(LINE_TYPE_DASH, 1);
				cout << "[*] CREATE adb COMMAND : " << "adb pull " << strFolderPath << " ./" << endl;
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);
				
				// PROCESS DETACH
				MemoryMap.Detach();

				// 이용한 모듈리스트를 clear한다
				MemoryMap.ClearModuleList();
				vModuleList.clear();
				break;
		}

		case 'f' :
		{
			// CHECK Search Item
			if(vStrItemList.size() == 0)
			{
				cout << "  [!]PLEASE ADD an ITEM by USING the MENU[3]!" << endl;					
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}

			// CHOICE Serach Item Number 
			cout << "  [F]>>>> INPUT ITEM NUMBER(you can input one or multiple item number) : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);

			vector<string> vStrTempList;
			StringTokenizer(vStrTempList, string(strDummyItem), string(" "));

			// MAKE Search Item
			vector<string> vStrSearchList;
			vector<string>::iterator itr;
			for( itr = vStrTempList.begin(); itr < vStrTempList.end(); itr++ )
			{
				string strSelectItemIndex = *itr;
				int    nSelectItemIndex   = atoi( strSelectItemIndex.c_str() ) - 1;

				if( nSelectItemIndex < 0 || nSelectItemIndex >= vStrItemList.size() )
				{
					printf("  [!]PLEASE ENTER A NUMBER BETWEEN %d to %d NUMBER!\n", 1, (int)vStrItemList.size());
					return 0;
				}
				vStrSearchList.push_back( vStrItemList[nSelectItemIndex] );
			}

			if( MemoryMap.LoadModuleList() == false )
			{
				cout << "  [!]PLEASE FIND THE PROCESS AGAIN by USING the MENU[1], [2]" << endl;
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}


			DisplayLine(LINE_TYPE_NULL, 1);
			DisplayLine(LINE_TYPE_DASH, 1);


			SearchItemInFile(vStrSearchList, MemoryMap.GetProcessName());
			break;

		}

		case 'n' :
		{
			cout << "  [N]>>>> INPUT ITEM NUMBER(you can input one or multiple item number) : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);

			vector<string> vStrTempList;
			StringTokenizer(vStrTempList, string(strDummyItem), string(" "));

			vector<string> vStrSearchList;
			vector<string>::iterator itr;
			for( itr = vStrTempList.begin(); itr < vStrTempList.end(); itr++ )
			{
				string strSelectItemIndex = *itr;
				int    nSelectItemIndex   = atoi( strSelectItemIndex.c_str() ) - 1;

				if( nSelectItemIndex < 0 || nSelectItemIndex >= vStrItemList.size() )
				{
					printf("  [!]PLEASE ENTER A NUMBER BETWEEN %d to %d NUMBER!\n", 1, vStrItemList.size());
					return 0;
				}
				vStrSearchList.push_back( vStrItemList[nSelectItemIndex] );
			}
			
			for( itr = vStrSearchList.begin(); itr < vStrSearchList.end(); itr++ )
			{
				cout << "  [*] Search Item [" << *itr << "] in Network" << endl; 
			}
			DisplayLine(LINE_TYPE_DASH, 1);

			CPacket packet(vStrSearchList);
			packet.SelectDevice();
			packet.Sniffing();

			break;
		}

		case 's' :
		{
			cout << "  [S]>>>> ALL MODULE LIST " << endl ; 
			DisplayLine(LINE_TYPE_DASH, 1);

			//  키워드로 검색된 프로세스 리스트를 보여준다
			MemoryMap.GetAllModuleName(vStrAllModuleList);

			// 정렬
			sort( vStrAllModuleList.begin(), vStrAllModuleList.end(), less<string>() );

			// 연속적인 값 제거
			vStrAllModuleList.erase( unique(vStrAllModuleList.begin(), vStrAllModuleList.end()), vStrAllModuleList.end() );

			// 화면에 출력
			DisplayList(vStrAllModuleList, LIST_TYPE_MODULE);
			break;
		}

		case 'd' :
		{
			cout << "  [D]>>>> INPUT MODULE NUMBER(you can input one or multiple item number) : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);

			// 찾을 Module 번호를 받아온다  
			vector<string> vStrTempList;
			StringTokenizer(vStrTempList, string(strDummyItem), string(" "));

			// 찾을 Module String으로 구성한다
			vector<string> vStrSearchList;
			vector<string>::iterator itr;
			for( itr = vStrTempList.begin(); itr < vStrTempList.end(); itr++ )
			{
				string strSelectItemIndex = *itr;
				int    nSelectItemIndex   = atoi( strSelectItemIndex.c_str() ) - 1;

				// 입력된 아이템 번호의 유효성 검증 시행
				if( nSelectItemIndex < 0 || nSelectItemIndex >= vStrAllModuleList.size() )
				{
					printf("  [!]PLEASE ENTER A NUMBER BETWEEN %d to %d !\n", 1, vStrAllModuleList.size());
					return 0;
				}
				vStrSearchList.push_back( vStrAllModuleList[nSelectItemIndex] );
			}


			vector<CModule> vModuleList;
			MemoryMap.GetModuleListByModuleNameList(vStrSearchList, vModuleList);

			vector<CModule>::iterator i;

			// Get DUMP FolderPATH
			string strFolderPath = GetFilePath();



			int nFileCnt   = 1;
			int nModuleCnt = vModuleList.size(); 
			for(i = vModuleList.begin(); i !=  vModuleList.end(); i++)
			{
				// 메모리 덤프 사이즈 만큼 메모리 할당	
				pDumpData = (unsigned char*) malloc(i->GetMemorySize()); 
				if(pDumpData == NULL)
				{
					cout << "Memory Alloc Fail for Dump!" << endl;
					break;
				}
				memset(pDumpData, 0x00, i->GetMemorySize());

				printf( " [-] [%d / %d] START File DUMP [%s] / SIZE[%s]\n", 
						nFileCnt, 
						nModuleCnt, 
						i->GetModuleName().c_str(), 
						i->GetStrMemorySize().c_str() );    


				//  메모리 덤프
				i->GetDumpMemory(pDumpData);

				// FILE에 저장한다
				int nResult = SaveToFile(strFolderPath, i->GetModuleName(), pDumpData, i->GetMemorySize());
				if(nResult == 0)
					printf(" [+] [%d / %d] DUMP FILE(%s) SAVED! \n\n", 
							nFileCnt, nModuleCnt, i->GetModuleName().c_str());
				else
					printf(" [!] [%d / %d] DUMP FILE(%s) SAVED ERROR! \n\n", 
							nFileCnt, nModuleCnt, i->GetModuleName().c_str());

				nFileCnt++;

				// 메모리 해제
				free(pDumpData);
			}
			
			// chmod 777
			DisplayLine(LINE_TYPE_DASH, 1);
			chmod(strFolderPath.c_str(), 0777);
			printf( "[*] EXCUTED CHANGE PERMISSION(chmod -R 777 %s)\n", strFolderPath.c_str() );	

			// Create adb command
			DisplayLine(LINE_TYPE_DASH, 1);
			cout << "[*] CREATE adb COMMAND : " << "adb pull " << strFolderPath << " ./" << endl;
			DisplayLine(LINE_TYPE_DASH, 1);
			DisplayLine(LINE_TYPE_NULL, 2);

			// PROCESS DETACH
			MemoryMap.Detach();

			// 이용한 모듈리스트를 clear한다
			MemoryMap.ClearModuleList();
			vModuleList.clear();
			break;
		}

		case 'e' :
		{
			// MODULE INPUT
			char strDummyModule[MAX_STRING_SIZE];
			memset(strDummyModule, 0x00, MAX_STRING_SIZE);
			cout << "  [E]>>>> INPUT MODULE NUMBER(you can input one or multiple module number or write \"all\") : " ; 
			cin.getline(strDummyModule, MAX_STRING_SIZE);

			// ITEM INPUT
			char strDummyItem[MAX_STRING_SIZE];
			memset(strDummyItem, 0x00, MAX_STRING_SIZE);
			cout << "  [E]>>>> INPUT ITEM NUMBER(you can input one or multiple item number) : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);

			// 찾을 Module 번호를 받아온다  
			vector<string> vStrModuleTempList;
			StringTokenizer(vStrModuleTempList, string(strDummyModule), string(" "));

		
			vector<CModule> vModuleInfoList;
			vector<string>::iterator itr;

			// Check SEARCH ALL MODULE
			if(vStrModuleTempList[0].compare("all") == 0)
				MemoryMap.GetModuleListByModuleNameList(vStrAllModuleList, vModuleInfoList);
			else
			{

				// 찾을 Module String으로 구성한다
				vector<string> vStrModuleNameList;
				for( itr = vStrModuleTempList.begin(); itr < vStrModuleTempList.end(); itr++ )
				{
					string strSelectItemIndex = *itr;
					int    nSelectItemIndex   = atoi( strSelectItemIndex.c_str() ) - 1;

					// 입력된 아이템 번호의 유효성 검증 시행
					if( nSelectItemIndex < 0 || nSelectItemIndex >= vStrAllModuleList.size() )
					{
						printf("  [!]PLEASE ENTER A NUMBER BETWEEN %d to %d !\n", 1, vStrAllModuleList.size());
						return 0;
					}
					vStrModuleNameList.push_back( vStrAllModuleList[nSelectItemIndex] );
				}

				// 모듈 이름리스트로 모듈 정보를 리스트로 가저 온다
				MemoryMap.GetModuleListByModuleNameList(vStrModuleNameList, vModuleInfoList);
			}
			
			// 찾을 ITEM의 번호를 받아온다  
			vector<string> vStrTempItemList;
			StringTokenizer(vStrTempItemList, string(strDummyItem), string(" "));

			// 찾을 ITEM을 String으로 구성한다
			vector<string> vStrSearchItemList;
			for( itr = vStrTempItemList.begin(); itr < vStrTempItemList.end(); itr++ )
			{
				string strSelectItemIndex = *itr;
				int    nSelectItemIndex   = atoi( strSelectItemIndex.c_str() ) - 1;

				// 입력된 아이템 번호의 유효성 검증 시행
				if( nSelectItemIndex < 0 || nSelectItemIndex >= vStrItemList.size() )
				{
					printf("  [!]PLEASE ENTER A NUMBER BETWEEN %d to %d !\n", 1, vStrItemList.size());
					return 0;
				}
				vStrSearchItemList.push_back( vStrItemList[nSelectItemIndex] );
			}


			// MemoryMap attach
			MemoryMap.Attach();	

			int nModuleCnt = vModuleInfoList.size(); 
			vector<CModule>::iterator i;
			for(i = vModuleInfoList.begin(); i !=  vModuleInfoList.end(); i++)
			{
				int nIndex = i - vModuleInfoList.begin() + 1;

				// 메모리 덤프 사이즈 만큼 메모리 할당	
				pDumpData = (unsigned char*) malloc(i->GetMemorySize()); 
				if(pDumpData == NULL)
					cout << "Memory Alloc Fail for Dump!" << endl;

				// 덤프 시작 메세지 출력
				DisplayLine(LINE_TYPE_DASH, 1);
				printf( "[+] [%d / %d] START DUMP [%s]'s MEMORY at [0x%08x]-[0x%08x] / SIZE[%s]\n", 
						nIndex, 
						nModuleCnt, 
						i->GetModuleName().c_str(), 
						(unsigned int)i->GetStartAddress(), 
						(unsigned int)i->GetEndAddress(), 
						i->GetStrMemorySize().c_str() );    

				//  메모리 덤프
				i->GetDumpMemory(pDumpData);

				// 덤프 종료 메세지 출력
				printf( "[+] [%d / %d] FINISH DUMP\n", nIndex, nModuleCnt);    

				// 덤프한 메모리에서 키워드를 찾는다
				i->SearchOfMemory(vStrSearchItemList, pDumpData, i->GetStartAddress(), i->GetMemorySize(), true); 
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 1);

				// 메모리 해제
				free(pDumpData);

			}

			// PROCESS DETACH
			MemoryMap.Detach();

			// 이용한 모듈리스트를 clear한다
			MemoryMap.ClearModuleList();
			vModuleInfoList.clear();
			break;
		}

		case 'v' :
			// Display Version
			cout << "[*] AMC Version : " << FSA_AMC_VERSION << endl;
			break;

		case 'x' :
		{
			cout << "  [X]>>>> INPUT DISPLAY LINE COUNT : " ;
			cin.getline(strDummyItem, MAX_STRING_SIZE);

			int nInputNumber = atoi(strDummyItem);
			if( nInputNumber > 0 && nInputNumber <= 100 )
			{
				MemoryMap.SetDisplayLineCount(nInputNumber);
				cout << "  [*]>>>> SET DISPLAY LINE COUNT : " << nInputNumber << endl;
			}
			else
				printf("  [!]PLEASE ENTER A NUMBER BETWEEN %d to %d NUMBER!\n", 1, 100);

			DisplayLine(LINE_TYPE_DASH, 1);
			DisplayLine(LINE_TYPE_NULL, 2);

			break;
		}

		case 'q' :
				return -1;
 
		default :
				DisplayLine(LINE_TYPE_NULL, 1);
				DisplayLine(LINE_TYPE_DASH,  1);
				cout << "+YOU WRITE WRONG NUMBER : " << (char)nSelectedMenuNumber << endl;
			
				break;
	}


}

void DisplayInfo(vector<string>& vStrList)
{

	// 1. DISPLAY SET PROCESS INFO
	if(MemoryMap.GetProcessID() != -1)
	{		
		cout << "=====================[PROCESS INFO]==========================" << endl;
		cout << "+ SET PROCESS : " << MemoryMap.GetProcessName() << "(" << MemoryMap.GetProcessID() << ")" << endl;
	}
	else
	{
		cout << "=====================[PROCESS INFO]==========================" << endl;
		cout << "+ PROCESS WAS NOT SELECTED!                                 +" << endl; 
	}
	
	// 2. DISPLAY ITEM INFO
	if(vStrList.size() != 0)
	{
		cout << "=======================[ITEM LIST]===========================" << endl;
		DisplayList(vStrList, LIST_TYPE_ITEM);	
		cout << "=============================================================" << endl;
	}
	else
	{
		cout << "=======================[ITEM LIST]===========================" << endl;
		cout << "+ ITEM WAS NOT ADDED!                                       +" << endl;
		cout << "=============================================================" << endl;
	}
}


int DisplayMenu()
{
	char strInputNumber[MAX_STRING_SIZE];
	memset(strInputNumber, 0x00, MAX_STRING_SIZE);

	cout << "+-----------------------------------------------------------+" << endl;
	cout << "+ [1]. FIND PROCESS ID          + [3]. ADD    ITEM          +" << endl;
	cout << "+ [2]. SET  PROCESS ID          + [4]. DELETE ITEM          +" << endl;
	cout << "+-----------------------------------------------------------+" << endl;
	cout << "+ [5]. SEARCH ITEM(MULTI SCAN)  + [7]. REPLACE ITEM         +" << endl;
	cout << "+ [6]. SEARCH ITEM(PART  SCAN)  + [8]. DUMP to FILE         +" << endl;
	cout << "+-----------------------------------------------------------+" << endl;
	cout << "+ [S]. SHOW all MODULE LIST                                 +" << endl;
	cout << "+ [D]. DUMP to FILE                                         +" << endl;
	cout << "+ [E]. SEARCH ITEM                                          +" << endl;
	cout << "+-----------------------------------------------------------+" << endl;
	cout << "+ [F]. SEARCH ITEM(in FILE)                                 +" << endl;
        cout << "+ [N]. SEARCH ITEM(in NETWORK)                              +" << endl;
	cout << "+-----------------------------------------------------------+" << endl;
        cout << "+ >> SELECT MENU(QUIT is 'q') : ";

	cin.getline(strInputNumber, MAX_STRING_SIZE);
	return strInputNumber[0];
} 

