#include <winapi_kernel32.h>
#include <winapi_shared.h>

#include <Windows.h>
#include <TlHelp32.h>

#include <lualib.h>
#include <luaconf.h>
#include <lauxlib.h>

#ifndef LUA_WINAPI_KERNEL32_VERSION
#define LUA_WINAPI_KERNEL32_VERSION "0.1.0-0"
#endif

#if LUA_VERSION_NUM < 502
#define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
#define luaL_checkinteger(L, n) (luaL_checkint(L, (n)))
#endif

static lua_Integer pointerToInteger(void *p)
{
    lua_Integer res;

    if (sizeof(void *) == 8)
    {
        res = (INT64)p;
    }
    else
    {
        res = (INT32)p;
    }

    return res;
}

static int lua_pushMODULEENTRY32(lua_State *L, PMODULEENTRY32 me)
{
    lua_newtable(L);

    lua_pushstring(L, "dwSize");
    lua_pushinteger(L, me->dwSize);
    lua_settable(L, -3);

    lua_pushstring(L, "th32ModuleID");
    lua_pushinteger(L, me->th32ModuleID);
    lua_settable(L, -3);

    lua_pushstring(L, "th32ProcessID");
    lua_pushinteger(L, me->th32ProcessID);
    lua_settable(L, -3);

    lua_pushstring(L, "GlblcntUsage");
    lua_pushinteger(L, me->GlblcntUsage);
    lua_settable(L, -3);

    lua_pushstring(L, "ProccntUsage");
    lua_pushinteger(L, me->ProccntUsage);
    lua_settable(L, -3);

    lua_pushstring(L, "modBaseAddr");
    lua_pushinteger(L, pointerToInteger((void *)(me->modBaseAddr)));
    lua_settable(L, -3);

    lua_pushstring(L, "modBaseSize");
    lua_pushinteger(L, me->modBaseSize);
    lua_settable(L, -3);

    lua_pushstring(L, "hModule");
    void *hmoduleUserData = lua_newuserdata(L, sizeof(HMODULE));
    *((HMODULE *)hmoduleUserData) = me->hModule;
    lua_settable(L, -3);

    lua_pushstring(L, "szModule");
    lua_pushstring(L, me->szModule);
    lua_settable(L, -3);        

    lua_pushstring(L, "szExePath");
    lua_pushstring(L, me->szExePath);
    lua_settable(L, -3);

    return 1;
}

static int lua_pushTHREADENTRY32(lua_State *L, PTHREADENTRY32 te)
{
    lua_newtable(L);

    lua_pushstring(L, "dwSize");
    lua_pushinteger(L, te->dwSize);
    lua_settable(L, -3);

    lua_pushstring(L, "cntUsage");
    lua_pushinteger(L, te->cntUsage);
    lua_settable(L, -3);

    lua_pushstring(L, "th32ThreadID");
    lua_pushinteger(L, te->th32ThreadID);
    lua_settable(L, -3);

    lua_pushstring(L, "th32OwnerProcessID");
    lua_pushinteger(L, te->th32OwnerProcessID);
    lua_settable(L, -3);

    lua_pushstring(L, "tpBasePri");
    lua_pushinteger(L, te->tpBasePri);
    lua_settable(L, -3);

    lua_pushstring(L, "tpDeltaPri");
    lua_pushinteger(L, te->tpDeltaPri);
    lua_settable(L, -3);

    lua_pushstring(L, "dwFlags");
    lua_pushinteger(L, te->dwFlags);
    lua_settable(L, -3);

    return 1;
}

static int lua_pushPROCESSENTRY32(lua_State *L, PPROCESSENTRY32 pe)
{
    lua_newtable(L);

    lua_pushstring(L, "dwSize");
    lua_pushinteger(L, pe->dwSize);
    lua_settable(L, -3);

    lua_pushstring(L, "cntUsage");
    lua_pushinteger(L, pe->cntUsage);
    lua_settable(L, -3);

    lua_pushstring(L, "th32ProcessID");
    lua_pushinteger(L, pe->th32ProcessID);
    lua_settable(L, -3);

    lua_pushstring(L, "th32DefaultHeapID");
    lua_pushinteger(L, pointerToInteger((void*)(pe->th32DefaultHeapID)));
    lua_settable(L, -3);

    lua_pushstring(L, "th32ModuleID");
    lua_pushinteger(L, pe->th32ModuleID);
    lua_settable(L, -3);

    lua_pushstring(L, "cntThreads");
    lua_pushinteger(L, pe->cntThreads);
    lua_settable(L, -3);

    lua_pushstring(L, "th32ParentProcessID");
    lua_pushinteger(L, pe->th32ParentProcessID);
    lua_settable(L, -3);

    lua_pushstring(L, "pcPriClassBase");
    lua_pushinteger(L, pe->pcPriClassBase);
    lua_settable(L, -3);

    lua_pushstring(L, "dwFlags");
    lua_pushinteger(L, pe->dwFlags);
    lua_settable(L, -3);

    lua_pushstring(L, "szExeFile");
    lua_pushstring(L, pe->szExeFile);
    lua_settable(L, -3);

    return 1;
}

static int lua_OpenProcess(lua_State *L)
{
    DWORD dwDesiredAccess = (DWORD)(luaL_checkinteger(L, 1));
    BOOL bInheritHandle = lua_toboolean(L, 2);
    DWORD dwProcessId = (DWORD)(luaL_checkinteger(L, 3));
    
    HANDLE process = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    void *userdata = lua_newuserdata(L, sizeof(HANDLE));
    *((HANDLE *)userdata) = process;
    return 1;
}

static int lua_CloseHandle(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_pushboolean(L, CloseHandle(handle));
    return 1;
}

static int lua_CreateToolhelp32Snapshot(lua_State *L)
{
    DWORD dwFlags = (DWORD)(luaL_checkinteger(L, 1));
    DWORD th32ProcessID = (DWORD)(luaL_checkinteger(L, 2));
    HANDLE handle = CreateToolhelp32Snapshot(dwFlags, th32ProcessID);
    void *userdata = lua_newuserdata(L, sizeof(HANDLE));
    *((HANDLE *)userdata) = handle;
    return 1;
}

static int lua_Module32First(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);
    BOOL result = Module32First(handle, &me);
    lua_pushboolean(L, result);
    
    if (result)
    {
        lua_pushMODULEENTRY32(L, &me);
    }
    else
    {
        lua_pushnil(L);
    }

    return 2;
}

static int lua_Module32Next(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);
    BOOL result = Module32Next(handle, &me);
    lua_pushboolean(L, result);
    
    if (result)
    {
        lua_pushMODULEENTRY32(L, &me);
    }
    else
    {
        lua_pushnil(L);
    }

    return 2;
}

static int lua_Thread32First(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    BOOL result = Thread32First(handle, &te);
    lua_pushboolean(L, result);
    
    if (result)
    {
        lua_pushTHREADENTRY32(L, &te);
    }
    else
    {
        lua_pushnil(L);
    }

    return 2;
}

static int lua_Thread32Next(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    BOOL result = Thread32Next(handle, &te);
    lua_pushboolean(L, result);
    
    if (result)
    {
        lua_pushTHREADENTRY32(L, &te);
    }
    else
    {
        lua_pushnil(L);
    }

    return 2;
}


static int lua_Process32First(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    BOOL result = Process32First(handle, &pe);
    lua_pushboolean(L, result);
    
    if (result)
    {
        lua_pushPROCESSENTRY32(L, &pe);
    }
    else
    {
        lua_pushnil(L);
    }

    return 2;
}

static int lua_Process32Next(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    BOOL result = Process32Next(handle, &pe);
    lua_pushboolean(L, result);
    
    if (result)
    {
        lua_pushPROCESSENTRY32(L, &pe);
    }
    else
    {
        lua_pushnil(L);
    }

    return 2;
}

static int lua_GetLastError(lua_State *L)
{
    lua_pushinteger(L, GetLastError());
    return 1;
}

static int lua_SetLastError(lua_State *L)
{
    DWORD dwErrCode = (DWORD)(luaL_checkinteger(L, 1));
    SetLastError(dwErrCode);
    return 0;
}

static int lua_Sleep(lua_State *L)
{
    DWORD dwMilliseconds = (DWORD)(luaL_checkinteger(L, 1));
    Sleep(dwMilliseconds);
    return 0;
}

static int lua_ReadBytes(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_Integer address = luaL_checkinteger(L, 2);
    lua_Integer count = luaL_checkinteger(L, 3);

    if (count < 0)
    {
        lua_pushboolean(L, FALSE);
        lua_pushnil(L);
        lua_pushinteger(L, 0);
    }
    else
    {
        SIZE_T size = (SIZE_T)(sizeof(BYTE) * count);

        BYTE *buffer = (BYTE *)(malloc(size));
        SIZE_T bytesRead;
        lua_pushboolean(L, ReadProcessMemory(handle, (LPCVOID)address, (LPVOID)buffer, size, &bytesRead));
        lua_pushlstring(L, buffer, size);
        free(buffer);
        lua_pushinteger(L, bytesRead);
    }
    
    return 3;
}

static int lua_ReadCString(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_Integer address = luaL_checkinteger(L, 2);
    lua_Integer count = luaL_checkinteger(L, 3);

    if (count < 0)
    {
        lua_pushboolean(L, FALSE);
        lua_pushnil(L);
        lua_pushinteger(L, 0);
    }
    else
    {
        SIZE_T size = (SIZE_T)(sizeof(BYTE) * count);

        BYTE *buffer = (BYTE *)(malloc(size));
        SIZE_T bytesRead;
        lua_pushboolean(L, ReadProcessMemory(handle, (LPCVOID)address, (LPVOID)buffer, size, &bytesRead));
        lua_pushstring(L, buffer);
        free(buffer);
        lua_pushinteger(L, bytesRead);
    }
    
    return 3;
}

static int lua_ReadInt8(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_Integer address = luaL_checkinteger(L, 2);
    SIZE_T size = sizeof(INT8);
    
    INT8 value;
    SIZE_T bytesRead;
    lua_pushboolean(L, ReadProcessMemory(handle, (LPCVOID)address, (LPVOID)&value, size, &bytesRead));
    lua_pushinteger(L, value);
    lua_pushinteger(L, bytesRead);

    return 3;
}

static int lua_ReadInt16(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_Integer address = luaL_checkinteger(L, 2);
    SIZE_T size = sizeof(INT16);
    
    INT16 value;
    SIZE_T bytesRead;
    lua_pushboolean(L, ReadProcessMemory(handle, (LPCVOID)address, (LPVOID)&value, size, &bytesRead));
    lua_pushinteger(L, value);
    lua_pushinteger(L, bytesRead);

    return 3;
}

static int lua_ReadInt32(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_Integer address = luaL_checkinteger(L, 2);
    SIZE_T size = sizeof(INT32);
    
    INT32 value;
    SIZE_T bytesRead;
    lua_pushboolean(L, ReadProcessMemory(handle, (LPCVOID)address, (LPVOID)&value, size, &bytesRead));
    lua_pushinteger(L, value);
    lua_pushinteger(L, bytesRead);

    return 3;
}

static int lua_ReadInt64(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_Integer address = luaL_checkinteger(L, 2);
    SIZE_T size = sizeof(INT64);
    
    INT64 value;
    SIZE_T bytesRead;
    lua_pushboolean(L, ReadProcessMemory(handle, (LPCVOID)address, (LPVOID)&value, size, &bytesRead));
    lua_pushinteger(L, (lua_Integer)value);
    lua_pushinteger(L, bytesRead);

    return 3;
}

static int lua_WriteBytes(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_Integer address = luaL_checkinteger(L, 2);
    SIZE_T length;
    const char *data = luaL_checklstring(L, 3, &length);

    SIZE_T bytesWritten;
    lua_pushboolean(L, WriteProcessMemory(handle, (LPVOID)address, (LPCVOID)data, length, &bytesWritten));
    lua_pushinteger(L, bytesWritten);
    
    return 2;
}

static int lua_WriteInt8(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_Integer address = luaL_checkinteger(L, 2);
    INT8 value = (INT8)(luaL_checkinteger(L, 3));

    SIZE_T bytesWritten;
    lua_pushboolean(L, WriteProcessMemory(handle, (LPVOID)address, (LPCVOID)&value, sizeof(INT8), &bytesWritten));
    lua_pushinteger(L, bytesWritten);
    
    return 2;
}

static int lua_WriteInt16(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_Integer address = luaL_checkinteger(L, 2);
    INT16 value = (INT16)(luaL_checkinteger(L, 3));

    SIZE_T bytesWritten;
    lua_pushboolean(L, WriteProcessMemory(handle, (LPVOID)address, (LPCVOID)&value, sizeof(INT16), &bytesWritten));
    lua_pushinteger(L, bytesWritten);
    
    return 2;
}

static int lua_WriteInt32(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_Integer address = luaL_checkinteger(L, 2);
    INT32 value = (INT32)(luaL_checkinteger(L, 3));

    SIZE_T bytesWritten;
    lua_pushboolean(L, WriteProcessMemory(handle, (LPVOID)address, (LPCVOID)&value, sizeof(INT32), &bytesWritten));
    lua_pushinteger(L, bytesWritten);
    
    return 2;
}

static int lua_WriteInt64(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_Integer address = luaL_checkinteger(L, 2);
    INT64 value = (INT64)(luaL_checkinteger(L, 3));

    SIZE_T bytesWritten;
    lua_pushboolean(L, WriteProcessMemory(handle, (LPVOID)address, (LPCVOID)&value, sizeof(INT64), &bytesWritten));
    lua_pushinteger(L, bytesWritten);
    
    return 2;
}

static int lua_VirtualAllocEx(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_Integer address = luaL_optinteger(L, 2, 0);
    lua_Integer size = luaL_checkinteger(L, 3);
    lua_Integer allocationType = luaL_checkinteger(L, 4);
    lua_Integer flProtect = luaL_checkinteger(L, 5);

    LPVOID result = VirtualAllocEx(handle, (LPVOID)address, (SIZE_T)size, (DWORD)allocationType, (DWORD)flProtect);
    lua_pushinteger(L, pointerToInteger(result));
    
    return 1;
}

static int lua_VirtualFreeEx(lua_State *L)
{
    HANDLE handle = lua_toHANDLE(L, 1);
    lua_Integer address = luaL_checkinteger(L, 2);
    lua_Integer size = luaL_checkinteger(L, 3);
    lua_Integer dwFreeType = luaL_checkinteger(L, 4);
    
    lua_pushboolean(L, VirtualFreeEx(handle, (LPVOID)address, (SIZE_T)size, (DWORD)dwFreeType));
    
    return 1;
}

static int lua_GetModuleHandleA(lua_State *L)
{
    const char *lpModuleName = luaL_optstring(L, 1, NULL);
    HMODULE hModule = GetModuleHandleA(lpModuleName);
    void *userdata = lua_newuserdata(L, sizeof(HMODULE));
    *((HMODULE *)userdata) = hModule;
    return 1;
}

static int lua_GetProcAddress(lua_State *L)
{
    HMODULE hModule = NULL;
    if (!lua_isnil(L, 1))
    {
        void *hModuleUserData = lua_touserdata(L, 1);
        hModule = *((HMODULE *)hModuleUserData);
    }
    const char *lpProcName = luaL_checkstring(L, 2);
    FARPROC result = GetProcAddress(hModule, lpProcName);
    lua_pushinteger(L, pointerToInteger((void *)result));
    return 1;
}

static int lua_LoadLibraryA(lua_State *L)
{
    const char *lpFileName = luaL_checkstring(L, 1);
    HMODULE hModule = LoadLibraryA(lpFileName);
    void *userdata = lua_newuserdata(L, sizeof(HMODULE));
    *((HMODULE *)userdata) = hModule;
    return 1;
}

static const struct luaL_Reg winapi_kernel32_f[] = {
    {"OpenProcess", lua_OpenProcess},
    {"CloseHandle", lua_CloseHandle},
    {"CreateToolhelp32Snapshot", lua_CreateToolhelp32Snapshot},
    {"Module32First", lua_Module32First},
    {"Module32Next", lua_Module32Next},
    {"Thread32First", lua_Thread32First},
    {"Thread32Next", lua_Thread32Next},
    {"Process32First", lua_Process32First},
    {"Process32Next", lua_Process32Next},
    {"GetLastError", lua_GetLastError},
    {"SetLastError", lua_SetLastError},
    {"Sleep", lua_Sleep},
    {"ReadBytes", lua_ReadBytes},
    {"ReadCString", lua_ReadCString},
    {"ReadInt8", lua_ReadInt8},
    {"ReadInt16", lua_ReadInt16},
    {"ReadInt32", lua_ReadInt32},
    {"ReadInt64", lua_ReadInt64},
    {"WriteBytes", lua_WriteBytes},
    {"WriteInt8", lua_WriteInt8},
    {"WriteInt16", lua_WriteInt16},
    {"WriteInt32", lua_WriteInt32},
    {"WriteInt64", lua_WriteInt64},
    {"VirtualAllocEx", lua_VirtualAllocEx},
    {"VirtualFreeEx", lua_VirtualFreeEx},
    {"GetModuleHandleA", lua_GetModuleHandleA},
    {"GetProcAddress", lua_GetProcAddress},
    {"LoadLibraryA", lua_LoadLibraryA},
    {NULL, NULL}
};

LUA_WINAPI_KERNEL32 int luaopen_winapi_kernel32(lua_State *L)
{
    luaL_newlib(L, winapi_kernel32_f);
    
    lua_pushstring(L, "NULL");
    void *nullUserdata = lua_newuserdata(L, sizeof(void *));
    memset(nullUserdata, 0, sizeof(void *));
    lua_settable(L, -3);

    lua_pushstring(L, "INVALID_HANDLE_VALUE");
    void *ihvUserData = lua_newuserdata(L, sizeof(HANDLE));
    *((HANDLE *)ihvUserData) = INVALID_HANDLE_VALUE;
    lua_settable(L, -3);
    
    lua_pushstring(L, "_VERSION");
    lua_pushstring(L, LUA_WINAPI_KERNEL32_VERSION);
    lua_settable(L, -3);

    return 1;
}