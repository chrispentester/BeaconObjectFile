# BeaconObjectFile

Cobalt Strike's Beacon Object Files for direct access to win32 apis or direct syscalls

Syscall options will help to bypass userland EDR hooks


# Steps to use

1. Compile the .c source file with mingw to create a .o object file
3. Load the .cna aggressor script in Cobalt Strike with the .o object file in thne same folder
4. Run the command that's now loaded into the Cobalt Strike client
