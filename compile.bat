@echo off
cl.exe /nologo /W0 /MT /O2 /GS- /DNDEBUG /D_USRDLL /D_WINDLL /I../../Common implantDLL.c /link advapi32.lib user32.lib kernel32.lib /DLL /subsystem:console /out:implantDLL.dll
cl.exe /nologo /W0 /Ox /MT /GS- /DNDEBUG /DWIN32_LEAN_AND_MEAN /I../../Common/ inject.c /link /subsystem:console /out:inject.exe
del *.obj *.exp *.lib