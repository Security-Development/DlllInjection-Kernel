#include <stdio.h>
#include <windows.h>

HMODULE ntdll = GetModuleHandleA("ntdll.dll");

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _VM_COUNTERS {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;
  
typedef LONG KPRIORITY;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG PageDirectoryBase;
    VM_COUNTERS VirtualMemoryCounters;
    SIZE_T PrivatePageCount;
    IO_COUNTERS IoCounters;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecutiryDescriptor;
	PVOID SecutiryQualityService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _INITIAL_TEB
{
    struct
    {
        PVOID OldStackBase;
        PVOID OldStackLimit;
    } OldInitialTeb;
    
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _SYSTEM_INFORMATION_CLASS 
{
    SystemProcessInformation = 0x00000005,
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS (WINAPI *Query)(
  	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
  	_Inout_   PVOID                    SystemInformation,
  	_In_      ULONG                    SystemInformationLength,
  	_Out_opt_ PULONG                   ReturnLength
);

typedef NTSTATUS (WINAPI *NewAlloc)(
	_In_      HANDLE 				   ProcessHandle,
	_Inout_   PVOID 				   *BaseAddress,
	_In_      ULONG_PTR 			   ZeroBits,
	_Inout_   PSIZE_T 				   RegionSize,
	_In_      ULONG 				   AllocationType,
	_In_      ULONG 				   Protect
);

typedef NTSTATUS (WINAPI *NewOpenProcess)(
	OUT 	PHANDLE					 ProcessHandle,
	IN		ACCESS_MASK				 DesiredAccess,
	IN 		POBJECT_ATTRIBUTES		 ObjectAttributes,
	IN		PCLIENT_ID  			 ClientId
);

typedef NTSTATUS (WINAPI *NewWriteMem)(
  	IN  	HANDLE 					 ProcessHandle,
  	OUT 	PVOID 					 BaseAddress,
  	IN  	PVOID 					 Buffer,
  	IN  	ULONG 					 BufferSize,
  	OUT 	PULONG 					 NumberOfBytesWritten
);

typedef NTSTATUS (WINAPI *NewCreateThread)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN ULONG StackZeroBits,
	IN ULONG SizeOfStackCommit,
	IN ULONG SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
);

DWORD GetProcessPID(wchar_t *ProcessName) {
	DWORD pid;
	HANDLE cmpPid = NULL;
	Query qsi = (Query) GetProcAddress(ntdll, "ZwQuerySystemInformation");
	ULONG length = 0x00000000;
	NTSTATUS ntStat = qsi(SystemProcessInformation, NULL, NULL, &length);
	BYTE *buff = (BYTE *) VirtualAlloc(NULL, length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	BYTE *addr = buff;
	ntStat = qsi(SystemProcessInformation, buff, length, &length);
	
	PSYSTEM_PROCESS_INFORMATION SPI = (PSYSTEM_PROCESS_INFORMATION) buff;
	buff += ((PSYSTEM_PROCESS_INFORMATION)SPI)->NextEntryOffset;
	BOOLEAN check = FALSE;
	printf("[*] Getting Process..\n");
	
	
	while(true) {
		SPI = (PSYSTEM_PROCESS_INFORMATION) buff;
		
		buff += ((PSYSTEM_PROCESS_INFORMATION)SPI)->NextEntryOffset;
		printf("[%ws] target Process : %ws\n", SPI->ImageName.Buffer, ProcessName);
		
		if( wcsicmp(SPI->ImageName.Buffer, ProcessName) == 0 ){
			printf("- Find Target Process\n");
			pid = (DWORD_PTR) SPI->UniqueProcessId;
			check = TRUE;
			break;
		} 
		
		
		if( SPI->UniqueProcessId == cmpPid)
			break;
		cmpPid = SPI->UniqueProcessId;
		
	}
	
	if( !check) {
		printf("- Not Found TargetProcess...\n");	
		return 0x00000000;
	} else {
		return pid;
	}
}	

 
HANDLE GetProcessHandle(DWORD ResponsePid) {
	NewOpenProcess Open = (NewOpenProcess) GetProcAddress(ntdll, "NtOpenProcess");
	OBJECT_ATTRIBUTES ObjectAttributes = {sizeof(OBJECT_ATTRIBUTES)};
	HANDLE hProc;
	CLIENT_ID pid = {(HANDLE)ResponsePid, NULL};
	NTSTATUS ntStat = Open(&hProc, PROCESS_ALL_ACCESS, &ObjectAttributes, &pid);
	printf("Kernel Handle : 0x%x\n", hProc);
	return hProc;
}

BOOLEAN Kernel32Injecttion(DWORD pid) {
	HANDLE hProc = GetProcessHandle(pid), hThread;
	
	char DllName[128] = "C:\\Users\\dltmd\\Desktop\\coding\\message.dll";
	
	NewAlloc NtAllocFunc = (NewAlloc) GetProcAddress(ntdll, "NtAllocateVirtualMemory");
	NewWriteMem NtWriteFunc = (NewWriteMem) GetProcAddress(ntdll, "NtWriteVirtualMemory");
	NewCreateThread NtCreateFunc = (NewCreateThread) GetProcAddress(ntdll, "NtCreateThreadEx");
	
	PVOID VirtualMemory = NULL;
	SIZE_T size = (SIZE_T) strlen(DllName) + 1;
	NTSTATUS ntAlloc = NtAllocFunc(hProc, &VirtualMemory, NULL, &size, MEM_COMMIT, PAGE_READWRITE);
	
	
	NTSTATUS ntWrite = NtWriteFunc(hProc, VirtualMemory, (PVOID)DllName, size, NULL);

	NTSTATUS ntCreate = NtCreateFunc(&hThread, GENERIC_EXECUTE, NULL, hProc, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"), VirtualMemory, FALSE, NULL, NULL, NULL, nullptr);
	WaitForSingleObject(hThread, INFINITE);
	printf("Injection!");
	
	CloseHandle(hProc);
	CloseHandle(hThread);
} 


//bool Inject(DWORD pid) {
//	HANDLE hProc, hMod, hTred;
//	LPVOID buff, addr;
//	char dName[128] = "C:\\Users\\dltmd\\Desktop\\coding\\message.dll";
//	if( !(hProc = GetProcessHandle(pid)) ) 
//		return false;
//	
//	if( !(buff = VirtualAllocEx(hProc, NULL, lstrlen(dName) +1, MEM_COMMIT, PAGE_READWRITE )) )
//		return false;
//	
//	if(	!(WriteProcessMemory(hProc, buff, (LPVOID)dName, lstrlen(dName) +1, NULL))	)
//		return false;
//	
//	hMod = GetModuleHandle("kernel32.dll");
//	addr = (void (*))GetProcAddress((HMODULE)hMod, "LoadLibraryA");
//	hTred = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)addr, buff, 0, NULL);
//	
//	WaitForSingleObject(hTred, INFINITE);
//	
//	printf("Injection!");
//	CloseHandle(hProc); 
//	CloseHandle(hMod);
//	CloseHandle(hTred);
//	return true;
//}

void NewGetProcessHandle(DWORD ResponsePid) {
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ResponsePid);
	printf("User Handle : 0x%x\n", hProc);
}



int main() {
	wchar_t input[32];
	printf("[*] Input the Target Process Name\n");
	printf("- INPUT : ");
	wscanf(L"%s", input);
	DWORD pid = GetProcessPID(input);
	printf("- pid : %d\n", pid);
	GetProcessHandle(pid);
	NewGetProcessHandle(pid);
	Kernel32Injecttion(pid);
	return 0;
}
