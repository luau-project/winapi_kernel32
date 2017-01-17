#include <winapi_kernel32.h>

#include <Windows.h>
#include <TlHelp32.h>

#include <lualib.h>
#include <luaconf.h>
#include <lauxlib.h>

#ifndef WINAPI_KERNEL32_VERSION
#define WINAPI_KERNEL32_VERSION "0.0.1-0"
#endif

#if LUA_VERSION_NUM < 502
#define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
#define luaL_checkinteger(L, n) (luaL_checkint(L, (n)))
#endif

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
    void *userdata = lua_touserdata(L, 1);
    HANDLE *handle = (HANDLE *)userdata;
    lua_pushboolean(L, CloseHandle(*handle));
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

static int lua_push_MODULEENTRY32(lua_State *L, MODULEENTRY32 *me)
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
    if (sizeof(void *) == 4)
    {
        lua_pushinteger(L, (DWORD)(me->modBaseAddr));
    }
    else
    {
        lua_pushinteger(L, (long long)(me->modBaseAddr));
    }
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

static int lua_Module32First(lua_State *L)
{
    void *userdata = lua_touserdata(L, 1);
    HANDLE *handle = (HANDLE *)userdata;
    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);
    BOOL result = Module32First(*handle, &me);
    lua_pushboolean(L, result);
    
    if (result)
    {
        lua_push_MODULEENTRY32(L, &me);
    }
    else
    {
        lua_pushnil(L);
    }

    return 2;
}

static int lua_Module32Next(lua_State *L)
{
    void *userdata = lua_touserdata(L, 1);
    HANDLE *handle = (HANDLE *)userdata;
    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);
    BOOL result = Module32Next(*handle, &me);
    lua_pushboolean(L, result);
    
    if (result)
    {
        lua_push_MODULEENTRY32(L, &me);
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
    void *userdata = lua_touserdata(L, 1);
    HANDLE *handle = (HANDLE *)userdata;
    lua_Integer address = luaL_checkinteger(L, 2);
    lua_Integer count = luaL_checkinteger(L, 3);

    if (count < 0)
    {
        lua_pushnil(L);
        lua_pushnil(L);
        lua_pushnil(L);
    }
    else
    {
        SIZE_T size = (SIZE_T)(sizeof(BYTE) * count);

        BYTE *buffer = malloc(size);
        SIZE_T bytesRead;
        lua_pushboolean(L, ReadProcessMemory(*handle, (LPCVOID)address, (LPVOID)buffer, size, &bytesRead));
        lua_pushlstring(L, buffer, size);
        free(buffer);
        lua_pushinteger(L, bytesRead);
    }
    
    return 3;
}

static int lua_ReadCString(lua_State *L)
{
    void *userdata = lua_touserdata(L, 1);
    HANDLE *handle = (HANDLE *)userdata;
    lua_Integer address = luaL_checkinteger(L, 2);
    lua_Integer count = luaL_checkinteger(L, 3);

    if (count < 0)
    {
        lua_pushnil(L);
        lua_pushnil(L);
        lua_pushnil(L);
    }
    else
    {
        SIZE_T size = (SIZE_T)(sizeof(BYTE) * count);

        BYTE *buffer = malloc(size);
        SIZE_T bytesRead;
        lua_pushboolean(L, ReadProcessMemory(*handle, (LPCVOID)address, (LPVOID)buffer, size, &bytesRead));
        lua_pushstring(L, buffer);
        free(buffer);
        lua_pushinteger(L, bytesRead);
    }
    
    return 3;
}

static int lua_ReadInt8(lua_State *L)
{
    void *userdata = lua_touserdata(L, 1);
    HANDLE *handle = (HANDLE *)userdata;
    lua_Integer address = luaL_checkinteger(L, 2);
    SIZE_T size = sizeof(INT8);
    
    INT8 value;
    SIZE_T bytesRead;
    lua_pushboolean(L, ReadProcessMemory(*handle, (LPCVOID)address, (LPVOID)&value, size, &bytesRead));
    lua_pushinteger(L, value);
    lua_pushinteger(L, bytesRead);

    return 3;
}

static int lua_ReadInt16(lua_State *L)
{
    void *userdata = lua_touserdata(L, 1);
    HANDLE *handle = (HANDLE *)userdata;
    lua_Integer address = luaL_checkinteger(L, 2);
    SIZE_T size = sizeof(INT16);
    
    INT16 value;
    SIZE_T bytesRead;
    lua_pushboolean(L, ReadProcessMemory(*handle, (LPCVOID)address, (LPVOID)&value, size, &bytesRead));
    lua_pushinteger(L, value);
    lua_pushinteger(L, bytesRead);

    return 3;
}

static int lua_ReadInt32(lua_State *L)
{
    void *userdata = lua_touserdata(L, 1);
    HANDLE *handle = (HANDLE *)userdata;
    lua_Integer address = luaL_checkinteger(L, 2);
    SIZE_T size = sizeof(INT32);
    
    INT32 value;
    SIZE_T bytesRead;
    lua_pushboolean(L, ReadProcessMemory(*handle, (LPCVOID)address, (LPVOID)&value, size, &bytesRead));
    lua_pushinteger(L, value);
    lua_pushinteger(L, bytesRead);

    return 3;
}

static int lua_ReadInt64(lua_State *L)
{
    void *userdata = lua_touserdata(L, 1);
    HANDLE *handle = (HANDLE *)userdata;
    lua_Integer address = luaL_checkinteger(L, 2);
    SIZE_T size = sizeof(INT64);
    
    INT64 value;
    SIZE_T bytesRead;
    lua_pushboolean(L, ReadProcessMemory(*handle, (LPCVOID)address, (LPVOID)&value, size, &bytesRead));
    lua_pushinteger(L, (lua_Integer)value);
    lua_pushinteger(L, bytesRead);

    return 3;
}

static const struct luaL_Reg winapi_kernel32_f[] = {
    {"OpenProcess", lua_OpenProcess},
    {"CloseHandle", lua_CloseHandle},
    {"CreateToolhelp32Snapshot", lua_CreateToolhelp32Snapshot},
    {"Module32First", lua_Module32First},
    {"Module32Next", lua_Module32Next},
    {"GetLastError", lua_GetLastError},
    {"SetLastError", lua_SetLastError},
    {"Sleep", lua_Sleep},
    {"ReadBytes", lua_ReadBytes},
    {"ReadCString", lua_ReadCString},
    {"ReadInt8", lua_ReadInt8},
    {"ReadInt16", lua_ReadInt16},
    {"ReadInt32", lua_ReadInt32},
    {"ReadInt64", lua_ReadInt64},
    {NULL, NULL}
};

LUA_WINAPI_KERNEL32 int luaopen_winapi_kernel32(lua_State *L)
{
    luaL_newlib(L, winapi_kernel32_f);
    
    lua_pushstring(L, "NULL");
    void *nullUserdata = lua_newuserdata(L, sizeof(void *));
    ZeroMemory(nullUserdata, sizeof(void *));
    lua_settable(L, -3);

    lua_pushstring(L, "INVALID_HANDLE_VALUE");
    void *ihvUserData = lua_newuserdata(L, sizeof(HANDLE));
    *(HANDLE *)ihvUserData = INVALID_HANDLE_VALUE;
    lua_settable(L, -3);
    
    lua_pushstring(L, "__VERSION");
    lua_pushstring(L, WINAPI_KERNEL32_VERSION);
    lua_settable(L, -3);

    return 1;
}