# SetThreadContext Injection

A Beacon Object File based on the method by XPN from https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/ used to bypass the Get-InjectedThread powershell script.

`x86_64-w64-mingw32-gcc -c stc_inject.c -o stc_inject.o -masm=intel`
