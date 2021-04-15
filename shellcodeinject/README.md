# Shellcode Inject

Normal shellcode inject with commonly used win32 APIs for injection (VirtualAllocEx, CreateRemoteThread)


# Compile
`x86_64-w64-mingw32-gcc -c shellcodeinject.c -o shellcodeinject.o -masm=intel`

# Usage

NOTE: Currently only for x64

Load the CNA script in Cobalt Strike, then the following command will be included:

`shellcodeinject PID Listener` - Inject shellcode created for listener to target PID

# OPSEC Concern

This will be caught by Get-InjectedThread because in CreateRemoteThread it uses the allocated memory's base address "Alloc" as StartRoutine.

This creates a thread with a start address not backed by a module on disk.

This will be caught by Sysmon from EventID 8 CreateRemoteThread.
