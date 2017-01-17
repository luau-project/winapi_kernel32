#ifndef WINAPI_KERNEL32_H
#define WINAPI_KERNEL32_H

#ifdef __cplusplus
extern "C" {
#endif

#define LUA_WINAPI_KERNEL32 __declspec(dllexport)

#include <lua.h>

LUA_WINAPI_KERNEL32 int luaopen_winapi_kernel32(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif