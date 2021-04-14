# BeaconObjectFile

Cobalt Strike's Beacon Object Files for direct access to win32 apis or direct syscalls

Syscall options will help to bypass userland EDR hooks


# Steps to use

1. Compile the .c file with mingw to create a .o file
3. Load the .cna script in Cobalt Strike with the .o file in thne same folder
4. Run the command that's now loaded into the Cobalt Strike client
