package = "winapi_kernel32"
version = "0.0.1-0"
source = {
   url = "git://github.com/luau-project/winapi_kernel32",
   tag = "v_0_0_1_0",
}
description = {
   summary = "Windows API Kernel32.lib binding for Lua",
   detailed = [[
       winapi_kernel32 is a library to allow the Lua programmer
       to interface with the underlying WINAPI Kernel32.lib
   ]],
   license = "MIT/X11",
}
dependencies = {
   "lua >= 5.1"
}
build = {
   type = "builtin",
   modules = {
      winapi_kernel32 = {
          sources = { "src/winapi_kernel32.c" },
          incdirs = { "src/" }
      }
   }
}