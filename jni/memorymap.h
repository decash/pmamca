#ifndef __MEMORY_MAP_H__
#define __MEMORY_MAP_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <vector>
#include <sys/ptrace.h>
#include <dirent.h>
#include <sys/stat.h>
#include "module.h"

#define WHITE_LIST_NAME "white.txt"


using namespace std;

class CMemoryMap 
{
	private:
		int             m_nProcessID;
		string          m_strMapPath;
		vector<string>  m_vWhiteList;
		vector<CModule> m_vModuleList;
		string          m_strProcessName;
		int             m_nDisplayMemLineCount;

	private:	
		void   SetMapPath();
		void   AddModuleToList(string strModuleInfo);
		string GetProcessNameUsingProcessID(string strProcessID);
	
	public:
		// Constructor
		CMemoryMap();

		// Get & Set 
		int    GetProcessID();
		int    SetProcessID(string strProcessID);
		string GetProcessName();
		int    GetAllModuleInfo(vector<string>& vStrModuleList);
		int    GetAllModuleName(vector<string>& vStrModuleList);
		int    GetProcessListByName(vector<string>& vProcessList, string strProcessName);
		void   SetDisplayLineCount(int nDisplayLineCount);

		// Load white.txt	
		bool   LoadWhiteList();

		// Attach & Detach
		bool Attach();
		bool Detach();
	
		// ModuleList Functions
		bool            LoadModuleList();
		vector<CModule> GetModuleList();
		bool            GetModuleListByModuleNameList(vector<string> vStrModuleNameList, vector<CModule>& vModuleList);
		void            ClearModuleList();
};

#endif
