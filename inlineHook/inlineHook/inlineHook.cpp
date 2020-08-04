// inlineHook.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
//#define _CRT_SECURE_NO_WARNINGS
#pragma warning( disable : 4996)
#include <iostream>
#include <Windows.h>
/*
MessageBoxW
75561490  89 FF 		mov         edi,edi
75561492  55			push        ebp
75561493  89 E5			mov         ebp,esp
*/

BYTE __NewCode[5] = { 0xe9,0x00,0x00,0x00,0x00 };
BYTE __OldCode[5] = { 0 };
FARPROC __MessageBoxAddress;
int WINAPI MyMessageBox(
	HWND hWnd, // handle to owner window
	LPCTSTR lpText, // text in message box
	LPCTSTR lpCaption, // message box title
	UINT uType // message box style
);
void InlineHook();

int main()
{
	InlineHook();
	MessageBoxW(NULL, L"正常调用MessageBox", L"未Hook", MB_OK);
}

void InlineHook()
{
	//获得MessageBoxW的地址
	HMODULE hModule_User32 = LoadLibrary(L"user32.dll");
	__MessageBoxAddress = GetProcAddress(hModule_User32, "MessageBoxW");
	//计算偏移=MyMessage - MessageBoxW - 5 
	DWORD JmpCode = (DWORD)MyMessageBox - (DWORD)__MessageBoxAddress - 5;
	//读取前5个字节到__OldCode中
	if (ReadProcessMemory(INVALID_HANDLE_VALUE, __MessageBoxAddress, __OldCode, 5, NULL)==0)
	{
		printf("ReadProcessMemory error\n");
		return;
	}
	//将NewCode写入到MessageBoxW的开头
	*(DWORD*)(__NewCode + 1) = JmpCode;
	DWORD dwOldProtect;
	VirtualProtect(__MessageBoxAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	WriteProcessMemory(INVALID_HANDLE_VALUE, __MessageBoxAddress, __NewCode, 5,NULL);
}
int WINAPI MyMessageBox(HWND hWnd,LPCTSTR lpText,LPCTSTR lpCaption,UINT uType)
{
	printf("MessageBoxW 已经被Hook\n");
	WriteProcessMemory(INVALID_HANDLE_VALUE, __MessageBoxAddress, __OldCode, 5, NULL);
	int ret = MessageBoxW(NULL, L"已经被Hook", L"inlineHook", MB_OK);
	return ret;
}

