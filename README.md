# BeaconObjectFile

Cobalt Strike's Beacon Object Files for direct access to win32 apis or direct syscalls

Syscall options will help to bypass userland EDR hooks


Make sure to have the .cna script in the same folder as the compiled .o file


# Steps to use

1. Compile the .c file with mingw to create a .o file
2. Load the .cna script in Cobalt Strike
3. Run the command that's now loaded into the Cobalt Strike client
