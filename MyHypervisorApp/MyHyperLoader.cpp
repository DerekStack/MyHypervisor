#include <stdio.h>
#include "MyHyperDrvCtrl.h"  
#include "..\MyHypervisor\MyHyperIOCT.h"
#include "Log.h"

MyHyperDrvCtrl myHyperDrvCtrl;

#define DRIVER_PATH		"C:\\MyHypervisor.sys"
#define SERVICE_NAME	"MyHypervisor"
#define NT_SYMBOLICLINK "\\\\.\\MyHypervisor"
#define DISPLAY_NAME	SERVICE_NAME

#define DRIVER_REQUEST(a,b,c,d,e,f) myHyperDrvCtrl.IoControl(NT_SYMBOLICLINK, a,b,c,d,e,f);


//using namespace std;

EXTERN_C_START



EXTERN_C_END

void Unload(char* ServiceName)
{
	DbgPrint("[+] Uninstalling Driver Service ... \r\n");
	if (!myHyperDrvCtrl.Stop(ServiceName)) {
		LOG_LAST_ERROR(L"[-] UnLoading Driver Failed \r\n");
		return;
	}
	if (!myHyperDrvCtrl.Remove(ServiceName)) {
		LOG_LAST_ERROR(L"[-] Removing Driver Failed \r\n");
		return;
	}
	DbgPrint("[+] Uninstall Driver Service Successfully ServiceName= %s \r\n", ServiceName);
}

void Load(char* DrvPath, char* ServiceName)
{
	DbgPrint("[+] Installing Driver Service ...  \r\n");
	myHyperDrvCtrl.Install(DrvPath, ServiceName, DISPLAY_NAME);
	if (!myHyperDrvCtrl.Start(ServiceName))
	{
		LOG_LAST_ERROR(L"[-] Install Driver Failure \r\n");
		myHyperDrvCtrl.Remove(ServiceName);
		return;
	}
	DbgPrint("[+] Install Driver Successfully DrvPath= %s ServiceName= %s \r\n", DrvPath, ServiceName);
}

void Unload()
{
	Unload(SERVICE_NAME);
}

void Load()
{
	CHAR Dir[512] = { 0 };
	CHAR DriverName[] = "\\MyHypervisor.sys";
	int Index = GetCurrentDirectoryA(512, Dir);
	strcpy_s(&Dir[Index], sizeof(DriverName), DriverName);
	DbgPrint("DriverPath= %s \r\n SerivceName= MyHypervisor\r\n", Dir);
	Load(Dir, SERVICE_NAME);
}

void PrintMenu()
{
	DbgPrint("---------------------------------------------------------------------------------------------------------------- \r\n");
	DbgPrint("| Mini Tools                                                                                                   | \r\n");
	DbgPrint("|                                                                                                              | \r\n");
	DbgPrint("|--------------------------------------------------------------------------------------------------------------| \r\n");
	DbgPrint("| Option | Parameters                           | Description                                                  | \r\n");
	DbgPrint("---------------------------------------------------------------------------------------------------------------| \r\n");
	DbgPrint("|  -h                                                              Show This Menu                              | \r\n");
	DbgPrint("|  -l                                                              Load MiniTool                               | \r\n");
	DbgPrint("|  -l      <DriverPath> <SerciceName>                              Load Kernel Driver                          | \r\n");
	DbgPrint("|  -u      <ServiceName>                                           Unload Driver                               | \r\n");
	DbgPrint("|  -q                                                              Quit  Application                           | \r\n");
	DbgPrint("---------------------------------------------------------------------------------------------------------------- \r\n");

}

int ParseParam(char* param, char** ret)
{
	int i = 0;
	char* next = nullptr;
	char* ptr = strtok_s(param, " ", &next);
	while (ptr != NULL)
	{
		///DbgPrint("'%s'\n", ptr);
		strcpy_s(ret[i], 256, ptr);
		ptr = strtok_s(NULL, " ", &next);
		i++;
	}
	return i;
}

char** GetParameter(char* param, int* _count)
{
	char** x = (char**)(malloc(sizeof(ULONG_PTR) * 128));
	if (!x) {
		return x;
	}

	for (int i = 0; i < 128; i++) {
		x[i] = (char*)malloc(256);
	}

	int count = ParseParam(param, x);

#ifdef DBGSTRING
	for (int i = 0; i < count; i++) {
		DbgPrint("str= %s \r\n", x[i]);
	}
#endif

	* _count = count;
	return x;
}

void FreeParameter(char** x) {
	for (int i = 0; i < 60; i++)
	{
		free(x[i]);
		x[i] = nullptr;
	}
	free(x);
}

int main()
{
	int count = 0;
	UCHAR Buffer[4096] = { 0 };

	PrintMenu();
	Load();
	while (1)
	{
		DbgPrint("\nInput Command [-q to quit] : \r\n");
		char param[4096] = { 0 };
		fgets(param, 4096, stdin);
		size_t len = strlen(param);
		if (len > 0 && param[len - 1] == '\n')
		{
			param[--len] = '\0';
		}
		if (!strncmp(param, "-l", 2))
		{
			char** x = GetParameter(param, &count);
			if (count < 0)
			{
				continue;
			}

			if (count == 1)
			{
				Load();
				continue;
			}

			if (!strlen(x[1]))
			{
				DbgPrint("Please Input Driver Path to be loaded \r\n");
				continue;
			}
			if (!strlen(x[2]))
			{
				DbgPrint("Please Input Service Name to be started \r\n");
				continue;
			}

			Load(x[1], x[2]);
			FreeParameter(x);
			x = nullptr;
		}
		else if (!strncmp(param, "-u", 2))
		{
			char** x = GetParameter(param, &count);
			if (count <= 0) {
				DbgPrint("Please Input Service Name to be started \r\n");
				continue;
			}
			if (count == 1) {
				Unload();
				continue;
			}

			Unload(x[1]);
			FreeParameter(x);
			x = nullptr;
		}
		else if (!strncmp(param, "-q", 2))
		{
			Unload();
			TerminateProcess(GetCurrentProcess(), 0);
		}
		else if (!strncmp(param, "-h", 2))
		{
			PrintMenu();
		}
		else if (!strncmp(param, "-r", 2))
		{
			char** x = GetParameter(param, &count);
			if (count <= 0)
			{
				DbgPrint("Please Input Service Name to be started \r\n");
				continue;
			}

			//if (!strcmp(x[1], "-rdmsr"))
			//{
			//	ULONGLONG index = strtoull(x[2], NULL, 0);
			//	ReadMsr(index);
			//}

			FreeParameter(x);
		}
		else if (!strncmp(param, "-w", 2))
		{

		}


	}
	return 0;
}
