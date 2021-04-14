# Syscall Shellcode Inject

Converted normal shellcode inject with win32 APIs to direct syscalls


# Compile
`x86_64-w64-mingw32-gcc -c syscall_shellcodeinject.c -o syscall_shellcodeinject.o -masm=intel`

# Usage

NOTE: Currently only for x64

Load the CNA script in Cobalt Strike, then the following command will be included:

`syscall_shellcodeinject PID Listener` - Inject shellcode created for listener to target PID

# OPSEC Concern

This will be caught by Get-InjectedThread because for NtCreateThreadEx it uses the allocated memory's base address "Alloc" as StartRoutine.

This creates a thread with a start address not backed by a module on disk.

This will be caught by Sysmon from EventID 8 CreateRemoteThread, since SysmonDrv.sys will hook and enumerate the syscall even in Kernel-Land.
