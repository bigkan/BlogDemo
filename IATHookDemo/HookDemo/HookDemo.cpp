// HookDemo.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include<stdio.h>
#include <Windows.h>
#include<wchar.h>
DWORD g_OldFuncAddr = (DWORD)GetProcAddress(LoadLibrary(L"USER32.dll"),"MessageBoxW");


int WINAPI MyMessageBox(HWND hWnd, LPCWSTR lpText,LPCWSTR lpCaption,UINT uType)
{
    typedef int (WINAPI *OldMessageBox)(HWND, LPCWSTR, LPCWSTR, UINT);
	wprintf(L"Hello\n");
	wprintf(L"%x\t", hWnd);
	wprintf(L"%ls\t", L"中文无法输出吗");
	wprintf(L"%ls\t", lpCaption);
	wprintf(L"%d\n", uType);

    int ret = ((OldMessageBox)g_OldFuncAddr)(hWnd,lpText,lpCaption,uType);
    wprintf(L"返回值：%d\n", ret);
    return ret;
}

void SetIATHook()
{
    HMODULE hMod = GetModuleHandle(NULL);
	PBYTE pData = (PBYTE)hMod;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNTHeader->OptionalHeader;

    PIMAGE_IMPORT_DESCRIPTOR impTable = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDosHeader+pOptHeader->DataDirectory[1].VirtualAddress);
	const char* DLLName = "USER32.dll";
	const char* Message = "MessageBoxW";
	if (impTable->TimeDateStamp == 0)
	{
		if (impTable->OriginalFirstThunk == 0)
		{
			MessageBox(NULL, L"没有导入表", L"信息提示", MB_OK);
			return;
		}
		//循环导出表结构体，遍历所要调用的所有PE模块 判断结构标记
		while (impTable->OriginalFirstThunk != 0)
		{
			if (!strcmp((char*)(pData + impTable->Name), DLLName))
			{
				_IMAGE_THUNK_DATA32* IntThunkData = (_IMAGE_THUNK_DATA32*)(pData + impTable->OriginalFirstThunk);
				_IMAGE_THUNK_DATA32* IatThunkData = (_IMAGE_THUNK_DATA32*)(pData + impTable->FirstThunk);

				//判断INT表结束标记
				while (IntThunkData->u1.Ordinal != 0)
				{
					if (!strcmp((char*)(pData + IntThunkData->u1.Ordinal+2), Message))
					{
						PDWORD addTemp = (PDWORD)IatThunkData;
						DWORD dwOldProtect;
						VirtualProtect((LPVOID)&IatThunkData->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
						*addTemp = (DWORD)MyMessageBox;
					}
					IntThunkData++;
					IatThunkData++;
				}
			}
			//指向下一个导入表 结构体
			impTable++;
		}
	}
	else {
		MessageBox(NULL, L"使用绑定导入表", L"信息提示", MB_OK);
	}
}

void UnIATHook()
{
	HMODULE hMod = GetModuleHandle(NULL);
	PBYTE pData = (PBYTE)hMod;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptHeader = &pNTHeader->OptionalHeader;

	PIMAGE_IMPORT_DESCRIPTOR impTable = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDosHeader + pOptHeader->DataDirectory[1].VirtualAddress);
	const char* DLLName = "USER32.dll";
	const char* Message = "MessageBoxW";
	if (impTable->TimeDateStamp == 0)
	{
		if (impTable->OriginalFirstThunk == 0)
		{
			MessageBox(NULL, L"没有导入表", L"信息提示", MB_OK);
			return;
		}
		//循环导出表结构体，遍历所要调用的所有PE模块 判断结构标记
		while (impTable->OriginalFirstThunk != 0)
		{
			if (!strcmp((char*)(pData + impTable->Name), DLLName))
			{
				_IMAGE_THUNK_DATA32* IntThunkData = (_IMAGE_THUNK_DATA32*)(pData + impTable->OriginalFirstThunk);
				_IMAGE_THUNK_DATA32* IatThunkData = (_IMAGE_THUNK_DATA32*)(pData + impTable->FirstThunk);

				//判断INT表结束标记
				while (IntThunkData->u1.Ordinal != 0)
				{
					if (!strcmp((char*)(pData + IntThunkData->u1.Ordinal + 2), Message))
					{
						PDWORD addTemp = (PDWORD)IatThunkData;
						DWORD dwOldProtect;
						VirtualProtect((LPVOID)&IatThunkData->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
						*addTemp = (DWORD)MyMessageBox;
					}
					IntThunkData++;
					IatThunkData++;
				}
			}
			//指向下一个导入表 结构体
			impTable++;
		}
	}
	else {
		MessageBox(NULL, L"使用绑定导入表", L"信息提示", MB_OK);
	}
}

void TestIATHook()
{
    SetIATHook();
    MessageBox(NULL, TEXT("测试IAT HOOK"), TEXT("IAT HOOK"), MB_OK);
    UnIATHook();
}
int main()
{
	TestIATHook();
}
