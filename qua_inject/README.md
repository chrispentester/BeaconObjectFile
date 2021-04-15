# QueueUserAPC Inject

A Beacon Object File of QueueUserAPC injection used to bypass the Get-InjectedThread and Sysmon.

Note: Currently spawns a calc child process and injects shellcode into it.


# Compile
`x86_64-w64-mingw32-gcc -c qua_inject.c -o qua_inject.o`


# Credit
Based on https://sevrosecurity.com/2020/04/13/process-injection-part-2-queueuserapc/
