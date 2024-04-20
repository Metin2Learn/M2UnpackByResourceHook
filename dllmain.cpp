#include <windows.h>
#include <Psapi.h>
#include <vector>
#include <string>
#include <memory>
#include <regex>
#include <map>
#include <filesystem>
#include "detours.h"


#include <fstream>
#include <sstream>

void DebugLog(const char* c_szLogData)
{
	std::ofstream outFile("debug.log", std::ios::app); 
	if (outFile.is_open())
	{
		outFile << c_szLogData << std::endl; 
		outFile.close(); 
	}
}

void __DebugLogf(const char* c_szFormat, ...)
{
	char szBuffer[16000];

	va_list vaArgList;
	va_start(vaArgList, c_szFormat);
	vsprintf_s(szBuffer, c_szFormat, vaArgList);
	va_end(vaArgList);

	DebugLog(szBuffer);
}

#ifdef _DEBUG
#define DebugLogf(log, ...)    __DebugLogf(log, __VA_ARGS__);
#else
#define DebugLogf(log, ...)
#endif



#define NtCurrentProcess ((HANDLE)-1)

bool Mem2File(const std::string& strFileName, uint8_t* pBuffer, uint32_t dwSize)
{
	auto hFile = CreateFileA(strFileName.c_str(), FILE_APPEND_DATA, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE)
	{
		DebugLogf(std::to_string(GetLastError()).c_str());
		MessageBoxA(0, "CreateFileA fail!", 0, 0);
		return false;
	}

	auto dwSetPtrRet = SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	if (dwSetPtrRet == INVALID_SET_FILE_POINTER)
	{
		MessageBoxA(0, "SetFilePointer fail!", 0, 0);
		CloseHandle(hFile);
		return false;
	}

	auto dwWritedBytes = 0UL;
	auto bWritten = WriteFile(hFile, pBuffer, dwSize, &dwWritedBytes, NULL);
	if (!bWritten || dwWritedBytes != dwSize)
	{
		char fileinf[1024];
		sprintf_s(fileinf, "WriteFile: %d (%u/%u) err: %u", bWritten, dwSize, dwWritedBytes, GetLastError());
		DebugLogf(fileinf);

		MessageBoxA(0, "WriteFile fail!", 0, 0);
		CloseHandle(hFile);
		return false;
	}

	if (!FlushFileBuffers(hFile))
	{
		MessageBoxA(0, "FlushFileBuffers fail!", 0, 0);
		CloseHandle(hFile);
		return false;
	}

	SetEndOfFile(hFile);
	CloseHandle(hFile);
	return true;
}

void replaceAll(std::string& s, const std::string& search, const std::string& replace)
{
	for (size_t pos = 0; ; pos += replace.length())
	{
		pos = s.find(search, pos);
		if (pos == std::string::npos)
			break;

		s.erase(pos, search.length());
		s.insert(pos, replace);
	}
}

std::vector <std::string> DirectoryList(const std::string &input, const std::string &delim = "\\")
{
	auto list = std::vector<std::string>();

	size_t start = 0;
	auto end = input.find(delim);
	while (end != std::string::npos)
	{
		list.emplace_back(input.substr(0, end));
		start = end + delim.length();
		end = input.find(delim, start);
	}

	return list;
}

std::map <void*, PBYTE> g_resourceContainer; // first: ecx - second: old OnLoad addr

typedef int(__thiscall* TResourceOnLoad)(void* This, DWORD iSize, DWORD c_pvBuf, DWORD dwUnk1);

int __fastcall ResourceOnLoadDetour(void* This, void* edx, DWORD iSize, DWORD c_pvBuf, DWORD dwUnk1)
{
	DebugLogf("===========ResourceOnLoadDetour");
	TResourceOnLoad oldFunc = nullptr;

	auto it = g_resourceContainer.find(This);
	if (it == g_resourceContainer.end())
		MessageBoxA(0, "FFFAAATTAAALLLLL", 0, 0);
	else
		oldFunc = (TResourceOnLoad)it->second;

	char* szName = (char*)((DWORD)This + 8);
//	if (*(DWORD*)((DWORD)This + 32) >= 0x10)
//		szName = (char*)(*(DWORD*)szName);

	char msg[1024];
	sprintf_s(msg, "ResourceOnLoadDetour: %p(%s) -- %p - %p / %p", This, szName, c_pvBuf, iSize, dwUnk1);
	DebugLogf(msg);

	auto ret = oldFunc(This, iSize, c_pvBuf, dwUnk1);

	// sanity
	if (!c_pvBuf || !iSize || !ret)
	{
		DetourRemove((PBYTE)oldFunc, (PBYTE)ResourceOnLoadDetour);
//		g_resourceContainer.erase(it);
		return ret;
	}

	auto stName = std::string(szName);
	replaceAll(stName, "d:", "d_");
	replaceAll(stName, "/", "\\");
	auto output = "dump\\" + stName;

	// exist file
	/*
	if (std::experimental::filesystem::exists(output))
	{
		DetourRemove((PBYTE)oldFunc, (PBYTE)ResourceOnLoadDetour);
		return ret;
	}
	*/
	auto directories = DirectoryList(output);
	if (directories.empty() == false)
	{
		for (const auto& current : directories)
		{
			CreateDirectoryA(current.c_str(), nullptr);
		}
	}

	Mem2File(output, (uint8_t*)c_pvBuf, iSize);

	DetourRemove((PBYTE)oldFunc, (PBYTE)ResourceOnLoadDetour);
//	g_resourceContainer.erase(it);
	return ret;
}

typedef void(__thiscall* TResourceLoad)(void* This);
static TResourceLoad ResourceLoad = nullptr;

void __fastcall ResourceLoadDetour(void* This, void* edx)
{
	DebugLogf("===========ResourceLoadDetour");
	char* szName = (char*)((DWORD)This + 8);
//	if (*(DWORD*)((DWORD)This + 32) >= 0x10)
//		szName = (char*)(*(DWORD*)szName);

	auto dwOnLoad = (unsigned __int32)(*(int(__thiscall **)(DWORD, DWORD, DWORD, DWORD))(*(DWORD *)This + 16));

	char msg[1024];
	sprintf_s(msg, "ResourceLoadDetour: %p(%s) %p hooks %u", This, szName, dwOnLoad, g_resourceContainer.size());
	DebugLogf(msg);

	if (g_resourceContainer.find(This) != g_resourceContainer.end() || strstr(szName, "dust.dds"))
		return ResourceLoad(This);

	auto dwOldOnLoad = DetourFunction((PBYTE)dwOnLoad, (PBYTE)ResourceOnLoadDetour);
	g_resourceContainer.emplace(This, dwOldOnLoad);
	
	return ResourceLoad(This);
}


void MainRoutine()
{
	DebugLogf("===========MainRoutine");// 0x005347C0  00490219
	ResourceLoad = (TResourceLoad)DetourFunction((PBYTE)0x00490219, (PBYTE)ResourceLoadDetour);
	DebugLogf("DetourFunction ! Error: %u", GetLastError());
	if (!ResourceLoad)
	{
		MessageBoxA(0, "Hook fail", 0, 0);
		return;
	} else {
		MessageBoxA(0, "Hook success", 0, 0);
	}
}

DWORD WINAPI Initialize(LPVOID)
{
	for (;;)
	{
		if (GetAsyncKeyState(VK_F8) & 0x8000) // down key
		{
			while (GetAsyncKeyState(VK_F8) & 0x8000) // wait for up key
				Sleep(1);

			MainRoutine();
			return 0;
		}
		Sleep(100);
	}
	return 0;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
	static auto initialized = false;

	if (initialized == false)
	{
		initialized = true;
		CreateThread(0, 0, Initialize, 0, 0, 0);
	}

	return TRUE;
}

