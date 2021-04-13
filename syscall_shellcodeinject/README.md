# Syscall Shellcode Inject

Converted normal shellcode inject with win32 APIs to direct syscalls


# Compile
`x86_64-w64-mingw32-gcc -c syscall_shellcodeinject.c -o syscall_shellcodeinject.o -masm=intel`

# Usage

NOTE: Currently only for x64
Load the CNA script in Cobalt Strike, then the following command will be included:

`syscall_shellcodeinject PID Listener` - Inject shellcode created for listener to target PID
