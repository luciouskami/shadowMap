
#include <windows.h>
#include "shadowMap.h"


void Test()
{
	MessageBox(0, 0, 0, 0);
	shadowMap_InstallHook(GetModuleHandle(NULL));

}

BOOL APIENTRY DllMain(HMODULE  hDllHandle,
					  DWORD   dwReason,
					  LPVOID  lpreserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		Test();
	}


	return TRUE;
}