#pragma comment(lib,"advapi32.lib")
#include "MyHyperDrvCtrl.h"

#define LOG_LAST_ERROR()
//--------------------------------------------------------------------------------//
BOOL WINAPI InstallService(
	_In_ LPCSTR ServiceName,
	_In_ LPCSTR DisplayName,
	_In_ LPCSTR szPath)
{
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager)
	{
		LOG_LAST_ERROR();
		return FALSE;
	}

	SC_HANDLE hService = CreateServiceA(
		hSCManager,
		ServiceName,
		DisplayName,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		szPath, NULL, NULL, NULL, NULL, NULL
	);

	if (!hService)
	{
		LOG_LAST_ERROR();
		return FALSE;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	return TRUE;
}
//--------------------------------------------------------------------------------//
BOOL WINAPI RemoveService(
	_In_ LPCSTR ServiceName
)
{
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (!hSCManager)
	{
		LOG_LAST_ERROR();
		return FALSE;
	}

	SC_HANDLE hService = OpenServiceA(hSCManager, ServiceName, DELETE);
	if (!hService)
	{
		LOG_LAST_ERROR();
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	if (!DeleteService(hService))
	{
		LOG_LAST_ERROR();
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return TRUE;
}
//--------------------------------------------------------------------------------//
BOOL WINAPI StartDrvService(LPCSTR ServiceName)
{
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager)
	{
		LOG_LAST_ERROR();
		return FALSE;
	}
	SC_HANDLE hService = OpenServiceA(hSCManager, ServiceName, SERVICE_START);
	if (!hService)
	{
		LOG_LAST_ERROR();
		CloseServiceHandle(hSCManager);
	}
	if (!StartService(hService, 0, NULL))
	{
		LOG_LAST_ERROR();
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return FALSE;
	}
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return TRUE;
}
//---------------------------------------------------------------------------------//
BOOL WINAPI StopService(LPCSTR ServiceName)
{
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	SERVICE_STATUS svcsta = { 0 };
	if (!hSCManager)
	{
		LOG_LAST_ERROR();
		return FALSE;
	}

	SC_HANDLE hService = OpenServiceA(hSCManager, ServiceName, SERVICE_STOP);
	if (!hService)
	{
		LOG_LAST_ERROR();
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	if (!ControlService(hService, SERVICE_CONTROL_STOP, &svcsta))
	{
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return TRUE;
}
//----------------------------------------------------------------------------------//
BOOL MyHyperDrvCtrl::Install(
	_In_ PCHAR pSysPath,
	_In_ PCHAR pServiceName,
	_In_ PCHAR pDisplayName)
{
	if (!InstallService(pServiceName, pDisplayName, pSysPath))
	{
		LOG_LAST_ERROR();
		return FALSE;
	}
	return TRUE;
}

//----------------------------------------------------------------------------------//
BOOL MyHyperDrvCtrl::Start(
	_In_ PCHAR pServiceName)
{
	if (!StartDrvService(pServiceName))
	{
		LOG_LAST_ERROR();
		return FALSE;
	}
	return TRUE;
}

//----------------------------------------------------------------------------------//
BOOL MyHyperDrvCtrl::Stop(
	_In_ PCHAR pServiceName)
{
	if (!StopService(pServiceName))
	{
		LOG_LAST_ERROR();
		return FALSE;
	}
	return TRUE;
}

//----------------------------------------------------------------------------------//
BOOL MyHyperDrvCtrl::Remove(
	_In_ PCHAR pServiceName)
{
	if (!RemoveService(pServiceName))
	{
		LOG_LAST_ERROR();
		return FALSE;
	}
	return TRUE;
}

//----------------------------------------------------------------------------------//
BOOL MyHyperDrvCtrl::IoControl(PCHAR SymbolicNames,
	DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen,
	PVOID OutBuff, DWORD OutBuffLen, DWORD* RealRetBytes
)
{
	DWORD dw;
	BOOL   b;
	HANDLE hDriver = CreateFileA(SymbolicNames, GENERIC_READ | GENERIC_WRITE, 0, 0,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (!hDriver)
	{
		return FALSE;
	}

	b = DeviceIoControl(hDriver, dwIoCode, InBuff, InBuffLen, OutBuff, OutBuffLen, &dw, NULL);

	if (RealRetBytes)
		*RealRetBytes = dw;

	CloseHandle(hDriver);
	return b;
}

DWORD MyHyperDrvCtrl::CTL_CODE_GEN(DWORD lngFunction)
{
	return (FILE_DEVICE_UNKNOWN * 65536) | (FILE_ANY_ACCESS * 16384) | (lngFunction * 4) | METHOD_BUFFERED;
}