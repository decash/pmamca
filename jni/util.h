#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <vector>
#include <iostream>
#include <sys/stat.h>
#include <iomanip>
#include <unistd.h>
#include "base64.h"

#define LINE_TYPE_NULL 100
#define LINE_TYPE_DASH 101

#define LIST_TYPE_RAW     201
#define LIST_TYPE_ITEM    202
#define LIST_TYPE_PROCESS 203
#define LIST_TYPE_MODULE  204

#define ITEM_LIST_FILE_NAME   "amc_item.txt"

using namespace std;

// DISPLAY FUNCTIONS
void    DisplayLine(int nLineType, int nLineRow);
void    DisplayList(vector<string>& vList, int nDisplayType = LIST_TYPE_RAW);

// STRING TOKENIZER FUNCTION
void    StringTokenizer(vector<string>& vList, string strSource, string strDelimer);

// FILE SAVE FUNCTIONS
string  GetFilePath();
string  GetCurrentPath();
int     SaveToFile(string strFolderPath, string strFileName, unsigned char* pData, int nFileSize);

// LOAD ITEM FUNCTIONS
bool    LoadItemList(vector<string>& vStrItemList);

// SEARCH ITEM IN FileSYSTEM
void SearchItemInFile(vector<string>& vStrSearchItemList, string strFilePath);


