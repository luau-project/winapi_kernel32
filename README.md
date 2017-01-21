# Overview

*winapi_kernel32* is a library to allow the Lua programmer
to interface with the underlying WINAPI Kernel32.lib. Also, this library
has been tested with Lua 5.1.5, 5.2.4 and 5.3.3.

**Note**: Due the huge amount of functions available in the Kernel32.lib,
this is going to take a considerable time of work to bind them all,
which is going to happen in a lot of releases.

# Functions

- [CloseHandle](#closehandle)
- [CreateToolhelp32Snapshot](#createtoolhelp32snapshot)
- [GetLastError](#getlasterror)
- [GetModuleHandleA](#getmodulehandlea)
- [GetProcAddress](#getprocaddress)
- [Module32First](#module32first)
- [Module32Next](#module32next)
- [OpenProcess](#openprocess)
- [ReadBytes](#readbytes)
- [ReadCString](#readcstring)
- [ReadInt16](#readint16)
- [ReadInt32](#readint32)
- [ReadInt64](#readint64)
- [ReadInt8](#readint8)
- [SetLastError](#setlasterror)
- [Sleep](#sleep)
- [VirtualAllocEx](#virtualallocex)
- [VirtualFreeEx](#virtualfreeex)
- [WriteBytes](#writebytes)
- [WriteInt16](#writeint16)
- [WriteInt32](#writeint32)
- [WriteInt64](#writeint64)
- [WriteInt8](#writeint8)

## CloseHandle

```lua
local kernel32 = require("winapi_kernel32")

local hHandle = -- previously acquired HANDLE

-- BOOL
local result = kernel32.CloseHandle(hHandle)
```

## CreateToolhelp32Snapshot

```lua
local kernel32 = require("winapi_kernel32")

local TH32CS_SNAPMODULE = 0x8

-- HANDLE
local hSnapshot = kernel32.CreateToolhelp32Snapshot(
    TH32CS_SNAPMODULE, -- DWORD dwFlags
    1234 -- DWORD th32ProcessID
)
```

## GetLastError

```lua
local kernel32 = require("winapi_kernel32")

-- DWORD dwErrCode
local error = kernel32.GetLastError()
```

## GetModuleHandleA

```lua
local kernel32 = require("winapi_kernel32")

-- HMODULE
local hModule = kernel32.GetModuleHandleA(
    "kernel32.dll" -- (can be nil) LPCTSTR lpModuleName
)
```

## GetProcAddress

```lua
local kernel32 = require("winapi_kernel32")

local hModule = -- previously acquired HMODULE

-- number
local FARPROC = kernel32.GetProcAddress(
    hModule, -- HMODULE hModule
    "LoadLibraryA" -- LPCSTR  lpProcName
)
```

## Module32First

```lua
local kernel32 = require("winapi_kernel32")

local hSnapshot = -- previously acquired HANDLE

local result, me32 = kernel32.Module32First(
    hSnapshot -- HANDLE hSnapshot
)

if (result) then
    print("module name: ", me32.szModule)
end
```

## Module32Next

```lua
local kernel32 = require("winapi_kernel32")

local hSnapshot = -- previously acquired HANDLE

local result, me32 = kernel32.Module32Next(
    hSnapshot -- HANDLE hSnapshot
)
if (result) then
    print("module name: ", me32.szModule)
end
```

## OpenProcess

```lua
local kernel32 = require("winapi_kernel32")

local PROCESS_ALL_ACCESS = 0x1F0FFF

-- HANDLE
local hProcess = kernel32.OpenProcess(
    PROCESS_ALL_ACCESS, -- DWORD dwDesiredAccess
    false, -- BOOL bInheritHandle
    1234 -- DWORD dwProcessId
)
```

## ReadBytes

This method is intended to supply a work around
ReadProcessMemory.

**Summary**: Reads n bytes from the process handle and returns
the data (exactly n bytes) as a Lua string

```lua
local kernel32 = require("winapi_kernel32")

local hProcess = -- previously acquired HANDLE

-- BOOL, string, SIZE_T
local result, data, numberOfBytesRead = kernel32.ReadBytes(
    hProcess, -- HANDLE hProcess
    0x40000000, -- number lpBaseAddress
    10 -- DWORD numberOfBytesToRead
)

if (result) then
    assert(#data == 10)
    
    local byte

    for i = 1, #data do
        -- data is a regular Lua string, so
        -- you can access i-th byte
        -- this way
        local byte = data:sub(i, i):byte()
    end
end
```

## ReadCString

This method is intended to supply a work around
ReadProcessMemory.

**Summary**: Reads n bytes from the process handle and returns
the data (up to the NULL-terminated character or n)
as a Lua string

```lua
local kernel32 = require("winapi_kernel32")

local hProcess = -- previously acquired HANDLE

-- BOOL, string, SIZE_T
local result, data, numberOfBytesRead = kernel32.ReadCString(
    hProcess, -- HANDLE hProcess
    0x40000000, -- number lpBaseAddress
    10 -- DWORD numberOfBytesToRead
)

if (result) then
    print(data)
end
```

## ReadInt16

This method is intended to supply a work around
ReadProcessMemory.

**Summary**: Reads 16 bits from the process

```lua
local kernel32 = require("winapi_kernel32")

local hProcess = -- previously acquired HANDLE

-- BOOL, INT16, SIZE_T
local result, data, numberOfBytesRead = kernel32.ReadInt16(
    hProcess, -- HANDLE hProcess
    0x40000000, -- number lpBaseAddress
)

if (result) then
    print(data)
end
```

## ReadInt32

This method is intended to supply a work around
ReadProcessMemory.

**Summary**: Reads 32 bits from the process

```lua
local kernel32 = require("winapi_kernel32")

local hProcess = -- previously acquired HANDLE

-- BOOL, INT32, SIZE_T
local result, data, numberOfBytesRead = kernel32.ReadInt32(
    hProcess, -- HANDLE hProcess
    0x40000000, -- number lpBaseAddress
)

if (result) then
    print(data)
end
```

## ReadInt64

This method is intended to supply a work around
ReadProcessMemory.

**Summary**: Reads 64 bits from the process

```lua
local kernel32 = require("winapi_kernel32")

local hProcess = -- previously acquired HANDLE

-- BOOL, INT64, SIZE_T
local result, data, numberOfBytesRead = kernel32.ReadInt64(
    hProcess, -- HANDLE hProcess
    0x40000000, -- number lpBaseAddress
)

if (result) then
    print(data)
end
```

## ReadInt8

This method is intended to supply a work around
ReadProcessMemory.

**Summary**: Reads 8 bits from the process

```lua
local kernel32 = require("winapi_kernel32")

local hProcess = -- previously acquired HANDLE

-- BOOL, INT8, SIZE_T
local result, data, numberOfBytesRead = kernel32.ReadInt8(
    hProcess, -- HANDLE hProcess
    0x40000000, -- number lpBaseAddress
)

if (result) then
    print(data)
end
```

## SetLastError

```lua
local kernel32 = require("winapi_kernel32")

kernel32.SetLastError(
    1234 -- DWORD dwErrCode
)
```

## Sleep

```lua
local kernel32 = require("winapi_kernel32")

kernel32.Sleep(
    1000 -- DWORD dwMilliseconds
)
```

## VirtualAllocEx

```lua
local kernel32 = require("winapi_kernel32")

local hProcess = -- previously acquired HANDLE
local MEM_RESERVE = 0x00002000
local PAGE_READWRITE = 0x4

local remoteMemory = kernel32.VirtualAllocEx(
    hProcess, -- HANDLE hProcess
    0x40000000, -- integer lpAddress
    0x100, -- SIZE_T dwSize
    MEM_RESERVE, -- DWORD flAllocationType
    PAGE_READWRITE -- DWORD flProtect 
)
```

## VirtualFreeEx

```lua
local kernel32 = require("winapi_kernel32")

local hProcess = -- previously acquired HANDLE
local MEM_RELEASE = 0x8000

local remoteMemory = kernel32.VirtualFreeEx(
    hProcess, -- HANDLE hProcess
    0x40000000, -- integer lpAddress
    0x100, -- SIZE_T dwSize
    MEM_RELEASE -- DWORD dwFreeType
)
```

## WriteBytes

This method is intended to supply a work around
WriteProcessMemory.

**Summary**: Writes bytes to the process through the data
passed as a Lua string

```lua
local kernel32 = require("winapi_kernel32")

local hProcess = -- previously acquired HANDLE

-- BOOL, integer
local result, bytesWritten = kernel32.WriteBytes(
    hProcess, -- HANDLE hProcess
    0x40000000, -- integer lpBaseAddress
    "\12\23\244\0\4" -- string data (will write these bytes { 12, 23, 244, 0, 4 })
)

if (result) then
    print("number of bytes written: ", bytesWritten)
end
```

## WriteInt16

This method is intended to supply a work around
WriteProcessMemory.

**Summary**: Writes 16 bits to the process

```lua
local kernel32 = require("winapi_kernel32")

local hProcess = -- previously acquired HANDLE

-- BOOL, integer
local result, bytesWritten = kernel32.WriteInt16(
    hProcess, -- HANDLE hProcess
    0x40000000, -- integer lpBaseAddress
    0xFFFF
)

if (result) then
    print("number of bytes written: ", bytesWritten)
end
```

## WriteInt32

This method is intended to supply a work around
WriteProcessMemory.

**Summary**: Writes 32 bits to the process

```lua
local kernel32 = require("winapi_kernel32")

local hProcess = -- previously acquired HANDLE

-- BOOL, integer
local result, bytesWritten = kernel32.WriteInt32(
    hProcess, -- HANDLE hProcess
    0x40000000, -- integer lpBaseAddress
    0xFFFFFFFF
)

if (result) then
    print("number of bytes written: ", bytesWritten)
end
```

## WriteInt64

This method is intended to supply a work around
WriteProcessMemory.

**Summary**: Writes 64 bits to the process

```lua
local kernel32 = require("winapi_kernel32")

local hProcess = -- previously acquired HANDLE

-- BOOL, integer
local result, bytesWritten = kernel32.WriteInt64(
    hProcess, -- HANDLE hProcess
    0x40000000, -- integer lpBaseAddress
    0xFFFFFFFFFF
)

if (result) then
    print("number of bytes written: ", bytesWritten)
end
```

## WriteInt8

This method is intended to supply a work around
WriteProcessMemory.

**Summary**: Writes 8 bits to the process

```lua
local kernel32 = require("winapi_kernel32")

local hProcess = -- previously acquired HANDLE

-- BOOL, integer
local result, bytesWritten = kernel32.WriteInt8(
    hProcess, -- HANDLE hProcess
    0x40000000, -- integer lpBaseAddress
    0xFF
)

if (result) then
    print("number of bytes written: ", bytesWritten)
end
```