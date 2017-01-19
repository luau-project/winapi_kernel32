#ifndef WINAPI_SHARED_H
#define WINAPI_SHARED_H

#include <Windows.h>
#include <lua.h>

static HANDLE lua_toHANDLE(lua_State *L, int arg)
{
    HANDLE handle = NULL;
    if (!lua_isnil(L, arg))
    {
        void *userdata = lua_touserdata(L, arg);
        handle = *((HANDLE *)userdata);
    }
    return handle;
}

static HWND lua_toHWND(lua_State *L, int arg)
{
    HWND hWnd = NULL;
    if (!lua_isnil(L, arg))
    {
        void *userdata = lua_touserdata(L, arg);
        hWnd = *((HWND *)userdata);
    }
    return hWnd;
}

#endif