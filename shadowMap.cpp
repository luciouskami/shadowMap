
#include <windows.h>
#include <vector>
#include <assert.h>

#include "shadowMap.h"



PVOID							g_mapAddress;
std::vector<SHADOW_MAP_TABLE>	g_mapTable;


/**
 * VEH
 */
LONG WINAPI VEH(PEXCEPTION_POINTERS ExceptionInfo)
{
	PVOID	crashAddr = ExceptionInfo->ExceptionRecord->ExceptionAddress;

	for (auto secinfo : g_mapTable)
	{
		if (secinfo.realAddress <= (ULONG_PTR)crashAddr &&
			(secinfo.realAddress + secinfo.realSize) >= (ULONG_PTR)crashAddr)
		{

#ifdef _WIN64
			ExceptionInfo->ContextRecord->Rip = \
				(ULONG_PTR)crashAddr - secinfo.realAddress + secinfo.mapAddress;
#else
			ExceptionInfo->ContextRecord->Eip = \
				(ULONG_PTR)crashAddr - secinfo.realAddress + secinfo.mapAddress;
#endif
			
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		
		if (secinfo.mapAddress <= (ULONG_PTR)crashAddr &&
			(secinfo.mapAddress + secinfo.mapSize) >= (ULONG_PTR)crashAddr)
		{

#ifdef _WIN64
			ExceptionInfo->ContextRecord->Rip = \
				(ULONG_PTR)crashAddr - secinfo.mapAddress + secinfo.realAddress;
			ExceptionInfo->ExceptionRecord->ExceptionAddress = (PVOID) \
				((ULONG_PTR)crashAddr - secinfo.mapAddress + secinfo.realAddress);

#else
			ExceptionInfo->ContextRecord->Eip = \
				(ULONG_PTR)crashAddr - secinfo.mapAddress + secinfo.realAddress;
			ExceptionInfo->ExceptionRecord->ExceptionAddress = (PVOID) \
				((ULONG_PTR)crashAddr - secinfo.mapAddress + secinfo.realAddress);
#endif

			return EXCEPTION_CONTINUE_EXECUTION;
		}
		
	}

	return EXCEPTION_CONTINUE_SEARCH;
}


/**
* 安装hook
*/
BOOL WINAPI shadowMap_InstallHook(HMODULE hModule)
{
	assert(hModule);

	PIMAGE_DOS_HEADER		doshead_ptr;
	PIMAGE_NT_HEADERS		nthead_ptr;
	PIMAGE_SECTION_HEADER	sec_ptr;
	SHADOW_MAP_TABLE		shadow_section;
	HANDLE					hProcess;

	doshead_ptr = (PIMAGE_DOS_HEADER)hModule;
	if (doshead_ptr->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	nthead_ptr = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + doshead_ptr->e_lfanew);
	if (nthead_ptr->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	g_mapAddress = VirtualAlloc(NULL, nthead_ptr->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (g_mapAddress == NULL)
	{
		return FALSE;
	}

	sec_ptr = IMAGE_FIRST_SECTION(nthead_ptr);

	g_mapTable.clear();
	AddVectoredExceptionHandler(0, VEH);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

	for (int i = 0; i < nthead_ptr->FileHeader.NumberOfSections; i++)
	{
		if (sec_ptr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			shadow_section.mapAddress = (ULONG_PTR)g_mapAddress + sec_ptr->VirtualAddress;
			shadow_section.mapSize = sec_ptr->Misc.VirtualSize;
			shadow_section.realAddress = (ULONG_PTR)hModule + sec_ptr->VirtualAddress;
			shadow_section.realSize = sec_ptr->Misc.VirtualSize;
			shadow_section.oldProtect = sec_ptr->Characteristics;

			memcpy((void*)shadow_section.mapAddress,
				   (void*)shadow_section.realAddress,
				   sec_ptr->Misc.VirtualSize);



			g_mapTable.push_back(shadow_section);
		}
		sec_ptr++;
	}


	for (auto secinfo:g_mapTable)
	{
		VirtualProtectEx(hProcess, (LPVOID)secinfo.realAddress,
						 secinfo.realSize,
						 PAGE_READONLY,
						 &secinfo.oldProtect);
	}

	CloseHandle(hProcess);

	return TRUE;
}

/**
* 卸载Hook
*/
BOOL WINAPI shadowMap_UnloadHook()
{
	return TRUE;
}

/**
* 读shadowMap内存
*/
BOOL WINAPI shadowMap_ReadMem(PVOID addr, UCHAR *buf, ULONG size)
{
	return TRUE;
}

/**
* 写shadowMap内存
*/
BOOL WINAPI shadowMap_WriteMem(PVOID addr, UCHAR *buf, ULONG size)
{
	return TRUE;
}