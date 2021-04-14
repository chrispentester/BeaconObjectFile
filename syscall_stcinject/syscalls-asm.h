#pragma once
#include "Syscalls.h"

#define ZwAllocateVirtualMemory NtAllocateVirtualMemory
__asm__("NtAllocateVirtualMemory: \n\
	mov rax, gs:[0x60]                                  \n\
NtAllocateVirtualMemory_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtAllocateVirtualMemory_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtAllocateVirtualMemory_Check_10_0_XXXX \n\
	jmp NtAllocateVirtualMemory_SystemCall_Unknown \n\
NtAllocateVirtualMemory_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtAllocateVirtualMemory_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtAllocateVirtualMemory_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtAllocateVirtualMemory_SystemCall_6_3_XXXX \n\
	jmp NtAllocateVirtualMemory_SystemCall_Unknown \n\
NtAllocateVirtualMemory_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtAllocateVirtualMemory_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtAllocateVirtualMemory_SystemCall_6_1_7601 \n\
	jmp NtAllocateVirtualMemory_SystemCall_Unknown \n\
NtAllocateVirtualMemory_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_19042 \n\
	jmp NtAllocateVirtualMemory_SystemCall_Unknown \n\
NtAllocateVirtualMemory_SystemCall_6_1_7600:           \n\
	mov eax, 0x0015 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_6_1_7601:           \n\
	mov eax, 0x0015 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0016 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0017 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_10240:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_10586:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_14393:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_15063:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_16299:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_17134:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_17763:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_18362:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_18363:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_19041:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_19042:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_Unknown:            \n\
	ret \n\
NtAllocateVirtualMemory_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwClose NtClose
__asm__("NtClose: \n\
	mov rax, gs:[0x60]                  \n\
NtClose_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtClose_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtClose_Check_10_0_XXXX \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtClose_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtClose_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtClose_SystemCall_6_3_XXXX \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtClose_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtClose_SystemCall_6_1_7601 \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtClose_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtClose_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtClose_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtClose_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtClose_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtClose_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtClose_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtClose_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtClose_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtClose_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtClose_SystemCall_10_0_19042 \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_SystemCall_6_1_7600:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_1_7601:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x000d \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x000e \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_10240:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_10586:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_14393:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_15063:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_16299:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_17134:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_17763:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_18362:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_18363:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_19041:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_19042:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_Unknown:            \n\
	ret \n\
NtClose_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwCreateThreadEx NtCreateThreadEx
__asm__("NtCreateThreadEx: \n\
	mov rax, gs:[0x60]                           \n\
NtCreateThreadEx_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtCreateThreadEx_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtCreateThreadEx_Check_10_0_XXXX \n\
	jmp NtCreateThreadEx_SystemCall_Unknown \n\
NtCreateThreadEx_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtCreateThreadEx_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtCreateThreadEx_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtCreateThreadEx_SystemCall_6_3_XXXX \n\
	jmp NtCreateThreadEx_SystemCall_Unknown \n\
NtCreateThreadEx_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtCreateThreadEx_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtCreateThreadEx_SystemCall_6_1_7601 \n\
	jmp NtCreateThreadEx_SystemCall_Unknown \n\
NtCreateThreadEx_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtCreateThreadEx_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtCreateThreadEx_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtCreateThreadEx_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtCreateThreadEx_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtCreateThreadEx_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtCreateThreadEx_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtCreateThreadEx_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtCreateThreadEx_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtCreateThreadEx_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtCreateThreadEx_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtCreateThreadEx_SystemCall_10_0_19042 \n\
	jmp NtCreateThreadEx_SystemCall_Unknown \n\
NtCreateThreadEx_SystemCall_6_1_7600:           \n\
	mov eax, 0x00a5 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_6_1_7601:           \n\
	mov eax, 0x00a5 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x00af \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x00b0 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_10240:         \n\
	mov eax, 0x00b3 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_10586:         \n\
	mov eax, 0x00b4 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_14393:         \n\
	mov eax, 0x00b6 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_15063:         \n\
	mov eax, 0x00b9 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_16299:         \n\
	mov eax, 0x00ba \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_17134:         \n\
	mov eax, 0x00bb \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_17763:         \n\
	mov eax, 0x00bc \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_18362:         \n\
	mov eax, 0x00bd \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_18363:         \n\
	mov eax, 0x00bd \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_19041:         \n\
	mov eax, 0x00c1 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_19042:         \n\
	mov eax, 0x00c1 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_Unknown:            \n\
	ret \n\
NtCreateThreadEx_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwGetContextThread NtGetContextThread
__asm__("NtGetContextThread: \n\
	mov rax, gs:[0x60]                             \n\
NtGetContextThread_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtGetContextThread_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtGetContextThread_Check_10_0_XXXX \n\
	jmp NtGetContextThread_SystemCall_Unknown \n\
NtGetContextThread_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtGetContextThread_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtGetContextThread_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtGetContextThread_SystemCall_6_3_XXXX \n\
	jmp NtGetContextThread_SystemCall_Unknown \n\
NtGetContextThread_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtGetContextThread_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtGetContextThread_SystemCall_6_1_7601 \n\
	jmp NtGetContextThread_SystemCall_Unknown \n\
NtGetContextThread_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtGetContextThread_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtGetContextThread_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtGetContextThread_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtGetContextThread_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtGetContextThread_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtGetContextThread_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtGetContextThread_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtGetContextThread_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtGetContextThread_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtGetContextThread_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtGetContextThread_SystemCall_10_0_19042 \n\
	jmp NtGetContextThread_SystemCall_Unknown \n\
NtGetContextThread_SystemCall_6_1_7600:           \n\
	mov eax, 0x00ca \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_6_1_7601:           \n\
	mov eax, 0x00ca \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x00dd \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x00e0 \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_10_0_10240:         \n\
	mov eax, 0x00e3 \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_10_0_10586:         \n\
	mov eax, 0x00e4 \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_10_0_14393:         \n\
	mov eax, 0x00e6 \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_10_0_15063:         \n\
	mov eax, 0x00e9 \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_10_0_16299:         \n\
	mov eax, 0x00ea \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_10_0_17134:         \n\
	mov eax, 0x00eb \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_10_0_17763:         \n\
	mov eax, 0x00ec \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_10_0_18362:         \n\
	mov eax, 0x00ed \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_10_0_18363:         \n\
	mov eax, 0x00ed \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_10_0_19041:         \n\
	mov eax, 0x00f2 \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_10_0_19042:         \n\
	mov eax, 0x00f2 \n\
	jmp NtGetContextThread_Epilogue \n\
NtGetContextThread_SystemCall_Unknown:            \n\
	ret \n\
NtGetContextThread_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwOpenProcess NtOpenProcess
__asm__("NtOpenProcess: \n\
	mov rax, gs:[0x60]                        \n\
NtOpenProcess_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtOpenProcess_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtOpenProcess_Check_10_0_XXXX \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtOpenProcess_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtOpenProcess_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtOpenProcess_SystemCall_6_3_XXXX \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtOpenProcess_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtOpenProcess_SystemCall_6_1_7601 \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtOpenProcess_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtOpenProcess_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtOpenProcess_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtOpenProcess_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtOpenProcess_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtOpenProcess_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtOpenProcess_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtOpenProcess_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtOpenProcess_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtOpenProcess_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtOpenProcess_SystemCall_10_0_19042 \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_SystemCall_6_1_7600:           \n\
	mov eax, 0x0023 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_1_7601:           \n\
	mov eax, 0x0023 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0024 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0025 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_10240:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_10586:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_14393:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_15063:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_16299:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_17134:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_17763:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_18362:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_18363:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_19041:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_19042:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_Unknown:            \n\
	ret \n\
NtOpenProcess_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwResumeThread NtResumeThread
__asm__("NtResumeThread: \n\
	mov rax, gs:[0x60]                         \n\
NtResumeThread_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtResumeThread_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtResumeThread_Check_10_0_XXXX \n\
	jmp NtResumeThread_SystemCall_Unknown \n\
NtResumeThread_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtResumeThread_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtResumeThread_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtResumeThread_SystemCall_6_3_XXXX \n\
	jmp NtResumeThread_SystemCall_Unknown \n\
NtResumeThread_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtResumeThread_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtResumeThread_SystemCall_6_1_7601 \n\
	jmp NtResumeThread_SystemCall_Unknown \n\
NtResumeThread_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtResumeThread_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtResumeThread_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtResumeThread_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtResumeThread_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtResumeThread_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtResumeThread_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtResumeThread_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtResumeThread_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtResumeThread_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtResumeThread_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtResumeThread_SystemCall_10_0_19042 \n\
	jmp NtResumeThread_SystemCall_Unknown \n\
NtResumeThread_SystemCall_6_1_7600:           \n\
	mov eax, 0x004f \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_6_1_7601:           \n\
	mov eax, 0x004f \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0050 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0051 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_10240:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_10586:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_14393:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_15063:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_16299:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_17134:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_17763:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_18362:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_18363:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_19041:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_19042:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_Unknown:            \n\
	ret \n\
NtResumeThread_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwSetContextThread NtSetContextThread
__asm__("NtSetContextThread: \n\
	mov rax, gs:[0x60]                             \n\
NtSetContextThread_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtSetContextThread_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtSetContextThread_Check_10_0_XXXX \n\
	jmp NtSetContextThread_SystemCall_Unknown \n\
NtSetContextThread_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtSetContextThread_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtSetContextThread_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtSetContextThread_SystemCall_6_3_XXXX \n\
	jmp NtSetContextThread_SystemCall_Unknown \n\
NtSetContextThread_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtSetContextThread_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtSetContextThread_SystemCall_6_1_7601 \n\
	jmp NtSetContextThread_SystemCall_Unknown \n\
NtSetContextThread_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtSetContextThread_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtSetContextThread_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtSetContextThread_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtSetContextThread_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtSetContextThread_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtSetContextThread_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtSetContextThread_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtSetContextThread_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtSetContextThread_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtSetContextThread_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtSetContextThread_SystemCall_10_0_19042 \n\
	jmp NtSetContextThread_SystemCall_Unknown \n\
NtSetContextThread_SystemCall_6_1_7600:           \n\
	mov eax, 0x0150 \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_6_1_7601:           \n\
	mov eax, 0x0150 \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0165 \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0168 \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_10_0_10240:         \n\
	mov eax, 0x016f \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_10_0_10586:         \n\
	mov eax, 0x0172 \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_10_0_14393:         \n\
	mov eax, 0x0178 \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_10_0_15063:         \n\
	mov eax, 0x017e \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_10_0_16299:         \n\
	mov eax, 0x0181 \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_10_0_17134:         \n\
	mov eax, 0x0183 \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_10_0_17763:         \n\
	mov eax, 0x0184 \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_10_0_18362:         \n\
	mov eax, 0x0185 \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_10_0_18363:         \n\
	mov eax, 0x0185 \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_10_0_19041:         \n\
	mov eax, 0x018b \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_10_0_19042:         \n\
	mov eax, 0x018b \n\
	jmp NtSetContextThread_Epilogue \n\
NtSetContextThread_SystemCall_Unknown:            \n\
	ret \n\
NtSetContextThread_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwWriteVirtualMemory NtWriteVirtualMemory
__asm__("NtWriteVirtualMemory: \n\
	mov rax, gs:[0x60]                               \n\
NtWriteVirtualMemory_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtWriteVirtualMemory_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtWriteVirtualMemory_Check_10_0_XXXX \n\
	jmp NtWriteVirtualMemory_SystemCall_Unknown \n\
NtWriteVirtualMemory_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtWriteVirtualMemory_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtWriteVirtualMemory_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtWriteVirtualMemory_SystemCall_6_3_XXXX \n\
	jmp NtWriteVirtualMemory_SystemCall_Unknown \n\
NtWriteVirtualMemory_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtWriteVirtualMemory_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtWriteVirtualMemory_SystemCall_6_1_7601 \n\
	jmp NtWriteVirtualMemory_SystemCall_Unknown \n\
NtWriteVirtualMemory_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_19042 \n\
	jmp NtWriteVirtualMemory_SystemCall_Unknown \n\
NtWriteVirtualMemory_SystemCall_6_1_7600:           \n\
	mov eax, 0x0037 \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_6_1_7601:           \n\
	mov eax, 0x0037 \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0038 \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0039 \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_10240:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_10586:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_14393:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_15063:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_16299:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_17134:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_17763:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_18362:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_18363:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_19041:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_19042:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_Unknown:            \n\
	ret \n\
NtWriteVirtualMemory_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

