# QueueUserAPC Spawn

A Beacon Object File version of the method https://sevrosecurity.com/2020/04/13/process-injection-part-2-queueuserapc/ used to bypass Get-InjectedThread and Sysmon.

Spawn a path child process and injects shellcode into it.

# Compile
`x86_64-w64-mingw32-gcc -c qua_spawn.c -o qua_spawn.o`

# Usage

NOTE: Currently only for x64

Load the CNA script in Cobalt Strike, then the following command will be included:

`qua_spawn PATH Listener` - Inject shellcode created for listener to target PID

`qua_spawn C:\Windows\System32\calc.exe Test` - Example to spawn calc.exe with a listener named Test 
