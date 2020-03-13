.386
.model flat, stdcall
option casemap:none

include /masm32/include/windows.inc
include /masm32/include/user32.inc
include /masm32/include/kernel32.inc
includelib /masm32/lib/user32.lib
includelib /masm32/lib/kernel32.lib

.data
szCaption1 db "System Information", 0
szCaption2 db "System Information", 0
szText1    db "Hello, World!", 0
szText2    db "Destroy!", 0
.code
start:
	invoke MessageBox, NULL, offset szText1, offset szCaption1, MB_OK
	invoke MessageBox, NULL, offset szText2, offset szCaption2, MB_OK
	invoke ExitProcess, NULL
end start

