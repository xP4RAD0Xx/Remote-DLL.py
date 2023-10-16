# Remote-DLL.py
Python scripts to execute DLL injections either on currently running processes or by spawning new ones.

## DLL_Injection.py
- This Python script is aimed to inject given DLL into an already running process by using C Types and Win32 API. The process ID and DLL location has to be changed berfore execution.

## Shell_Code_Injection.py
- This script is an extention to the DLL_Injection.py, instead of using DLL files, we are now having shell files which can be hardcoded into the script, in order to execute the shell code, using the win32 API we create an Hidden process and inject the shell code into the process which is later executed by the script.
- The test shellcode is created using msfvenom, but we can use any shell code.
