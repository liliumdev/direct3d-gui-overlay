#define _CRT_SECURE_NO_WARNINGS
#include "common.h"
#include <sstream>
#include <fstream>
#include <shlwapi.h>
#include <shlobj.h>
#include <basetsd.h>

#pragma comment(lib, "ws2_32.lib")

// by Drew Benton
namespace edx
{
	// Injects a DLL into a process at the specified address
	BOOL InjectDLL(HANDLE hProcess, const char * dllNameToLoad, const char * funcNameToLoad, DWORD injectAddress, bool bDebugAttach)
	{
		// # of bytes to replace
		DWORD byteCountToReplace = 6;

		// Read in the original bytes that we will restore from the injected dll
		BYTE userPatch[6] = {0};
		memset(userPatch, 0x90, 6);
		DWORD read = 0;
		ReadProcessMemory(hProcess, ULongToPtr(injectAddress), userPatch, 6, &read);

		// We want clear and byteRer to be local here
		{
			BYTE * clear = 0;

			// Allocate a patch of NOPs to write over existing code
			clear = (BYTE*)malloc(byteCountToReplace * sizeof(BYTE));
			memset(clear, 0x90, byteCountToReplace* sizeof(BYTE));

			// Clear out the original memory for a clean injection JMP to codecave
			WriteProcessBytes(hProcess, injectAddress, clear, byteCountToReplace);

			// Free the memory since we do not need it anymore
			free(clear);
		}

		//------------------------------------------//
		// Function variables.						//
		//------------------------------------------//

		// Main DLL we will need to load
		HMODULE kernel32	= NULL;

		// Main functions we will need to import
		FARPROC loadlibrary		= NULL;
		FARPROC getprocaddress	= NULL;
		FARPROC exitprocess		= NULL;

		// The workspace we will build the codecave on locally
		LPBYTE workspace		= NULL;
		DWORD workspaceIndex	= 0;

		// The memory in the process we write to
		LPVOID codecaveAddress	= NULL;
		DWORD dwCodecaveAddress = 0;

		// Strings we have to write into the process
		CHAR injectDllName[MAX_PATH + 1]	= {0};
		CHAR injectFuncName[MAX_PATH + 1]	= {0};
		CHAR injectError0[MAX_PATH + 1]		= {0};
		CHAR injectError1[MAX_PATH + 1]		= {0};
		CHAR injectError2[MAX_PATH + 1]		= {0};
		CHAR user32Name[MAX_PATH + 1]		= {0};
		CHAR msgboxName[MAX_PATH + 1]		= {0};

		// Placeholder addresses to use the strings
		DWORD user32NameAddr	= 0;
		DWORD user32Addr		= 0;
		DWORD msgboxNameAddr	= 0;
		DWORD msgboxAddr		= 0;
		DWORD dllAddr			= 0;
		DWORD dllNameAddr		= 0;
		DWORD funcNameAddr		= 0;
		DWORD error0Addr		= 0;
		DWORD error1Addr		= 0;
		DWORD error2Addr		= 0;

		DWORD offsetOrigBytes = 0;
		DWORD userVar = 0;

		// Temp variables
		DWORD dwTmpSize = 0;

		// Where the codecave execution should begin at
		DWORD codecaveExecAddr = 0;

		//------------------------------------------//
		// Variable initialization.					//
		//------------------------------------------//

		// Get the address of the main DLL
		kernel32	= LoadLibraryA("kernel32.dll");

		// Get our functions
		loadlibrary		= GetProcAddress(kernel32,	"LoadLibraryA");
		getprocaddress	= GetProcAddress(kernel32,	"GetProcAddress");
		exitprocess		= GetProcAddress(kernel32,	"ExitProcess");

		// This section will cause compiler warnings on VS8, 
		// you can upgrade the functions or ignore them

		// Build names
		_snprintf(injectDllName, MAX_PATH, "%s", dllNameToLoad);
		_snprintf(injectFuncName, MAX_PATH, "%s", funcNameToLoad);
		_snprintf(user32Name, MAX_PATH, "user32.dll");
		_snprintf(msgboxName, MAX_PATH, "MessageBoxA");

		// Build error messages
		_snprintf(injectError0, MAX_PATH, "Error");
		_snprintf(injectError1, MAX_PATH, "Could not find the DLL \"%s\"", injectDllName);
		_snprintf(injectError2, MAX_PATH, "Could not load the function \"%s\"", injectFuncName);

		// Create the workspace
		workspace = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);

		// Allocate space for the codecave in the process
		codecaveAddress = VirtualAllocEx(hProcess, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		dwCodecaveAddress = PtrToUlong(codecaveAddress);

		//------------------------------------------//
		// Data and string writing.					//
		//------------------------------------------//

		// Write out the address for the user32 dll address
		user32Addr = workspaceIndex + dwCodecaveAddress;
		dwTmpSize = 0;
		memcpy(workspace + workspaceIndex, &dwTmpSize, 4);
		workspaceIndex += 4;

		// Write out the address for the MessageBoxA address
		msgboxAddr = workspaceIndex + dwCodecaveAddress;
		dwTmpSize = 0;
		memcpy(workspace + workspaceIndex, &dwTmpSize, 4);
		workspaceIndex += 4;

		// Write out the address for the injected DLL's module
		dllAddr = workspaceIndex + dwCodecaveAddress;
		dwTmpSize = 0;
		memcpy(workspace + workspaceIndex, &dwTmpSize, 4);
		workspaceIndex += 4;

		// Write out the original bytes to be restored
		offsetOrigBytes = workspaceIndex + dwCodecaveAddress;
		memcpy(workspace + workspaceIndex, userPatch, 6);
		workspaceIndex += 6;

		// Write out the address for the injected DLL's module
		userVar = workspaceIndex + dwCodecaveAddress;
		dwTmpSize = 0;
		memcpy(workspace + workspaceIndex, &dwTmpSize, 4);
		workspaceIndex += 4;

		// User32 Dll Name
		user32NameAddr = workspaceIndex + dwCodecaveAddress;
		dwTmpSize = (DWORD)strlen(user32Name) + 1;
		memcpy(workspace + workspaceIndex, user32Name, dwTmpSize);
		workspaceIndex += dwTmpSize;

		// MessageBoxA name
		msgboxNameAddr = workspaceIndex + dwCodecaveAddress;
		dwTmpSize = (DWORD)strlen(msgboxName) + 1;
		memcpy(workspace + workspaceIndex, msgboxName, dwTmpSize);
		workspaceIndex += dwTmpSize;

		// Dll Name
		dllNameAddr = workspaceIndex + dwCodecaveAddress;
		dwTmpSize = (DWORD)strlen(injectDllName) + 1;
		memcpy(workspace + workspaceIndex, injectDllName, dwTmpSize);
		workspaceIndex += dwTmpSize;

		// Function Name
		funcNameAddr = workspaceIndex + dwCodecaveAddress;
		dwTmpSize = (DWORD)strlen(injectFuncName) + 1;
		memcpy(workspace + workspaceIndex, injectFuncName, dwTmpSize);
		workspaceIndex += dwTmpSize;

		// Error Message 1
		error0Addr = workspaceIndex + dwCodecaveAddress;
		dwTmpSize = (DWORD)strlen(injectError0) + 1;
		memcpy(workspace + workspaceIndex, injectError0, dwTmpSize);
		workspaceIndex += dwTmpSize;

		// Error Message 2
		error1Addr = workspaceIndex + dwCodecaveAddress;
		dwTmpSize = (DWORD)strlen(injectError1) + 1;
		memcpy(workspace + workspaceIndex, injectError1, dwTmpSize);
		workspaceIndex += dwTmpSize;

		// Error Message 3
		error2Addr = workspaceIndex + dwCodecaveAddress;
		dwTmpSize = (DWORD)strlen(injectError2) + 1;
		memcpy(workspace + workspaceIndex, injectError2, dwTmpSize);
		workspaceIndex += dwTmpSize;

		// Pad a few INT3s after string data is written for separation
		workspace[workspaceIndex++] = 0xCC;
		workspace[workspaceIndex++] = 0xCC;
		workspace[workspaceIndex++] = 0xCC;

		// Store where the codecave execution should begin
		codecaveExecAddr = workspaceIndex + dwCodecaveAddress;

		if(bDebugAttach)
		{
			// For debugging - infinite loop, attach onto process and step over
			workspace[workspaceIndex++] = 0xEB;
			workspace[workspaceIndex++] = 0xFE;
		}

		// PUSHAD
		workspace[workspaceIndex++] = 0x60;

		//------------------------------------------//
		// User32.dll loading.						//
		//------------------------------------------//

		// User32 DLL Loading
		// PUSH 0x00000000 - Push the address of the DLL name to use in LoadLibraryA
		workspace[workspaceIndex++] = 0x68;
		memcpy(workspace + workspaceIndex, &user32NameAddr, 4);
		workspaceIndex += 4;

		// MOV EAX, ADDRESS - Move the address of LoadLibraryA into EAX
		workspace[workspaceIndex++] = 0xB8;
		memcpy(workspace + workspaceIndex, &loadlibrary, 4);
		workspaceIndex += 4;

		// CALL EAX - Call LoadLibraryA
		workspace[workspaceIndex++] = 0xFF;
		workspace[workspaceIndex++] = 0xD0;

		// MessageBoxA Loading
		// PUSH 0x000000 - Push the address of the function name to load
		workspace[workspaceIndex++] = 0x68;
		memcpy(workspace + workspaceIndex, &msgboxNameAddr, 4);
		workspaceIndex += 4;

		// Push EAX, module to use in GetProcAddress
		workspace[workspaceIndex++] = 0x50;

		// MOV EAX, ADDRESS - Move the address of GetProcAddress into EAX
		workspace[workspaceIndex++] = 0xB8;
		memcpy(workspace + workspaceIndex, &getprocaddress, 4);
		workspaceIndex += 4;

		// CALL EAX - Call GetProcAddress
		workspace[workspaceIndex++] = 0xFF;
		workspace[workspaceIndex++] = 0xD0;

		// MOV [ADDRESS], EAX - Save the address to our variable
		workspace[workspaceIndex++] = 0xA3;
		memcpy(workspace + workspaceIndex, &msgboxAddr, 4);
		workspaceIndex += 4;

		//------------------------------------------//
		// Injected dll loading.					//
		//------------------------------------------//

		// DLL Loading
		// PUSH 0x00000000 - Push the address of the DLL name to use in LoadLibraryA
		workspace[workspaceIndex++] = 0x68;
		memcpy(workspace + workspaceIndex, &dllNameAddr, 4);
		workspaceIndex += 4;

		// MOV EAX, ADDRESS - Move the address of LoadLibraryA into EAX
		workspace[workspaceIndex++] = 0xB8;
		memcpy(workspace + workspaceIndex, &loadlibrary, 4);
		workspaceIndex += 4;

		// CALL EAX - Call LoadLibraryA
		workspace[workspaceIndex++] = 0xFF;
		workspace[workspaceIndex++] = 0xD0;

		// Error Checking
		// CMP EAX, 0
		workspace[workspaceIndex++] = 0x83;
		workspace[workspaceIndex++] = 0xF8;
		workspace[workspaceIndex++] = 0x00;

		// JNZ EIP + 0x24 to skip over error code
		workspace[workspaceIndex++] = 0x75;
		workspace[workspaceIndex++] = 0x24;

		// Error Code 1
		// MessageBox
		// PUSH 0x10 (MB_ICONHAND)
		workspace[workspaceIndex++] = 0x6A;
		workspace[workspaceIndex++] = 0x10;

		// PUSH 0x000000 - Push the address of the MessageBox title
		workspace[workspaceIndex++] = 0x68;
		memcpy(workspace + workspaceIndex, &error0Addr, 4);
		workspaceIndex += 4;

		// PUSH 0x000000 - Push the address of the MessageBox message
		workspace[workspaceIndex++] = 0x68;
		memcpy(workspace + workspaceIndex, &error1Addr, 4);
		workspaceIndex += 4;

		// Push 0
		workspace[workspaceIndex++] = 0x6A;
		workspace[workspaceIndex++] = 0x00;

		// MOV EAX, [ADDRESS] - Move the address of MessageBoxA into EAX
		workspace[workspaceIndex++] = 0xA1;
		memcpy(workspace + workspaceIndex, &msgboxAddr, 4);
		workspaceIndex += 4;

		// CALL EAX - Call MessageBoxA
		workspace[workspaceIndex++] = 0xFF;
		workspace[workspaceIndex++] = 0xD0;

		// FreeLibraryAndExitThread
		// Push 0 (exit code)
		workspace[workspaceIndex++] = 0x6A;
		workspace[workspaceIndex++] = 0x00;

		// PUSH [0x000000] - Push the address of the DLL module to unload
		workspace[workspaceIndex++] = 0xFF;
		workspace[workspaceIndex++] = 0x35;
		memcpy(workspace + workspaceIndex, &dllAddr, 4);
		workspaceIndex += 4;

		// MOV EAX, ADDRESS - Move the address of ExitProcess into EAX
		workspace[workspaceIndex++] = 0xB8;
		memcpy(workspace + workspaceIndex, &exitprocess, 4);
		workspaceIndex += 4;

		// CALL EAX - Call ExitProcess
		workspace[workspaceIndex++] = 0xFF;
		workspace[workspaceIndex++] = 0xD0;

		//	Now we have the address of the injected DLL, so save the handle

		// MOV [ADDRESS], EAX - Save the address to our variable
		workspace[workspaceIndex++] = 0xA3;
		memcpy(workspace + workspaceIndex, &dllAddr, 4);
		workspaceIndex += 4;

		// Load the initialize function from it

		// PUSH 0x000000 - Push the address of the function name to load
		workspace[workspaceIndex++] = 0x68;
		memcpy(workspace + workspaceIndex, &funcNameAddr, 4);
		workspaceIndex += 4;

		// Push EAX, module to use in GetProcAddress
		workspace[workspaceIndex++] = 0x50;

		// MOV EAX, ADDRESS - Move the address of GetProcAddress into EAX
		workspace[workspaceIndex++] = 0xB8;
		memcpy(workspace + workspaceIndex, &getprocaddress, 4);
		workspaceIndex += 4;

		// CALL EAX - Call GetProcAddress
		workspace[workspaceIndex++] = 0xFF;
		workspace[workspaceIndex++] = 0xD0;

		// Error Checking
		// CMP EAX, 0
		workspace[workspaceIndex++] = 0x83;
		workspace[workspaceIndex++] = 0xF8;
		workspace[workspaceIndex++] = 0x00;

		// JNZ EIP + 0x24 to skip error code
		workspace[workspaceIndex++] = 0x75;
		workspace[workspaceIndex++] = 0x1E;

		// Error Code 2
		// MessageBox
		// PUSH 0x10 (MB_ICONHAND)
		workspace[workspaceIndex++] = 0x6A;
		workspace[workspaceIndex++] = 0x10;

		// PUSH 0x000000 - Push the address of the MessageBox title
		workspace[workspaceIndex++] = 0x68;
		memcpy(workspace + workspaceIndex, &error0Addr, 4);
		workspaceIndex += 4;

		// PUSH 0x000000 - Push the address of the MessageBox message
		workspace[workspaceIndex++] = 0x68;
		memcpy(workspace + workspaceIndex, &error2Addr, 4);
		workspaceIndex += 4;

		// Push 0
		workspace[workspaceIndex++] = 0x6A;
		workspace[workspaceIndex++] = 0x00;

		// MOV EAX, ADDRESS - Move the address of MessageBoxA into EAX
		workspace[workspaceIndex++] = 0xA1;
		memcpy(workspace + workspaceIndex, &msgboxAddr, 4);
		workspaceIndex += 4;

		// CALL EAX - Call MessageBoxA
		workspace[workspaceIndex++] = 0xFF;
		workspace[workspaceIndex++] = 0xD0;

		// ExitProcess
		// Push 0 (exit code)
		workspace[workspaceIndex++] = 0x6A;
		workspace[workspaceIndex++] = 0x00;

		// MOV EAX, ADDRESS - Move the address of ExitProcess into EAX
		workspace[workspaceIndex++] = 0xB8;
		memcpy(workspace + workspaceIndex, &exitprocess, 4);
		workspaceIndex += 4;

		// CALL EAX - Call ExitProcess
		workspace[workspaceIndex++] = 0xFF;
		workspace[workspaceIndex++] = 0xD0;

		//	Now that we have the address of the function, we cam call it, 
		// if there was an error, the messagebox would be called as well.

		// Push orig bytes address
		workspace[workspaceIndex++] = 0x68;
		memcpy(workspace + workspaceIndex, &offsetOrigBytes, sizeof(offsetOrigBytes));
		workspaceIndex += 4;

		// Push the address to restore bytes to
		workspace[workspaceIndex++] = 0x68;
		memcpy(workspace + workspaceIndex, &injectAddress, sizeof(injectAddress));
		workspaceIndex += 4;

		// CALL EAX - Call Initialize
		workspace[workspaceIndex++] = 0xFF;
		workspace[workspaceIndex++] = 0xD0;

		// Add ESP, 8 2 parameters
		workspace[workspaceIndex++] = 0x83;
		workspace[workspaceIndex++] = 0xC4;
		workspace[workspaceIndex++] = 0x08;
		workspace[workspaceIndex++] = 0x90;

		// Restore registers with POPAD
		workspace[workspaceIndex++] = 0x61;

		// Pad a few NOPS before user code
		workspace[workspaceIndex++] = 0x90;
		workspace[workspaceIndex++] = 0x90;

		// Pop off into local variable
		workspace[workspaceIndex++] = 0x8F;
		workspace[workspaceIndex++] = 0x05;
		memcpy(workspace + workspaceIndex, &userVar, sizeof(userVar));
		workspaceIndex += 4;

		// Subtract 5 from local var
		workspace[workspaceIndex++] = 0x83;
		workspace[workspaceIndex++] = 0x2D;
		memcpy(workspace + workspaceIndex, &userVar, sizeof(userVar));
		workspaceIndex += 4;
		workspace[workspaceIndex++] = 0x05;

		// Pop off into local variable
		workspace[workspaceIndex++] = 0xFF;
		workspace[workspaceIndex++] = 0x35;
		memcpy(workspace + workspaceIndex, &userVar, sizeof(userVar));
		workspaceIndex += 4;

		// Return back to where we should be
		workspace[workspaceIndex++] = 0xC3;

		// Try to write the final codecave patch to the process first.
		// By doing this, worst case event is we add code to the process that is not used
		if(!WriteProcessBytes(hProcess, PtrToUlong(codecaveAddress), workspace, workspaceIndex))
		{
			HeapFree(GetProcessHeap(), 0, workspace);
			return FALSE;
		}

		// Now that the patch is written into the process, we need to make the process call it
		{
			// Make the program patch the starting address to inject the DLL
			BYTE patch2[5] = {0xE8, 0x00, 0x00, 0x00, 0x00};

			// Calculate the JMP offset ( + 5 for the FAR JMP we are adding)
			DWORD toCC = codecaveExecAddr - (injectAddress + 5);

			// Free the workspace memory
			HeapFree(GetProcessHeap(), 0, workspace);

			// Write the offset to the patch
			memcpy(patch2 + 1, &toCC, sizeof(toCC));

			// Make the patch that will JMP to the codecave
			if(!WriteProcessBytes(hProcess, injectAddress, patch2, 5))
			{
				return FALSE;
			}
		}

		// Success!
		return TRUE;
	}

	// Returns the entry point of an EXE
	ULONGLONG GetEntryPoint(const char * filename)
	{
		// Macro for adding pointers/DWORDs together without C arithmetic interfering 
		#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD)(ptr)+(DWORD)(addValue))

		ULONGLONG OEP = 0;
		HANDLE hFile = NULL;
		HANDLE hFileMapping = NULL;
		PIMAGE_DOS_HEADER dosHeader = {0};
		PBYTE g_pMappedFileBase = NULL;
		PIMAGE_FILE_HEADER pImgFileHdr = NULL;

		hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if(hFile == INVALID_HANDLE_VALUE)
			return 0;

		hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if(hFileMapping == 0)
		{
			CloseHandle(hFile);
			return 0;
		}

		g_pMappedFileBase = (PBYTE)MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
		if(g_pMappedFileBase == 0)
		{
			CloseHandle(hFileMapping);
			CloseHandle(hFile);
			return 0;
		}

		dosHeader = (PIMAGE_DOS_HEADER)g_pMappedFileBase;
		pImgFileHdr = (PIMAGE_FILE_HEADER)g_pMappedFileBase;
		if(dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
		{
			PIMAGE_NT_HEADERS pNTHeader = MakePtr( PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
			PIMAGE_NT_HEADERS64 pNTHeader64 = (PIMAGE_NT_HEADERS64)pNTHeader;

			// First, verify that the e_lfanew field gave us a reasonable pointer, then verify the PE signature.
			if(IsBadReadPtr(pNTHeader, sizeof(pNTHeader->Signature)) || pNTHeader->Signature != IMAGE_NT_SIGNATURE)
			{
				UnmapViewOfFile(g_pMappedFileBase);
				CloseHandle(hFileMapping);
				CloseHandle(hFile);
				return 0;
			}

			if(pNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				OEP = pNTHeader64->OptionalHeader.AddressOfEntryPoint + pNTHeader64->OptionalHeader.ImageBase;
			else
				OEP = pNTHeader->OptionalHeader.AddressOfEntryPoint + pNTHeader->OptionalHeader.ImageBase;
		}
		UnmapViewOfFile(g_pMappedFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return OEP;
		#undef MakePtr
	}

	// Returns a pointer to a hostent object for the specified address
	hostent * GetHost(const char * address)
	{
		if(inet_addr(address) == INADDR_NONE)
		{
			return gethostbyname(address);
		}
		else
		{
			unsigned long addr = 0;
			addr = inet_addr(address);
			return gethostbyaddr((char *)&addr, sizeof(addr), AF_INET);
		}
	}

	// Returns the absolute directory path of the executable
	std::string GetAbsoluteDirectoryPath()
	{
		char tmpDirectory1[MAX_PATH + 1] = {0};
		char tmpDirectory2[MAX_PATH + 1] = {0};
		GetCurrentDirectoryA(MAX_PATH, tmpDirectory1);
		GetFullPathNameA(tmpDirectory1, MAX_PATH, tmpDirectory2, 0);
		return (std::string(tmpDirectory2) + std::string("\\"));
	}

	// Creates a suspended process
	bool CreateSuspendedProcess(const std::string & filename, const std::string & fileargs, STARTUPINFOA & si, PROCESS_INFORMATION & pi)
	{
		si.cb = sizeof(STARTUPINFOA);

		std::stringstream cmdLine;
		cmdLine << "\"" << filename << "\" " << fileargs;

		BOOL result = CreateProcessA(0, (LPSTR)cmdLine.str().c_str(), 0, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
		return (result != 0);
	}

	// Returns true if the host is accessible
	bool CanGetHostFromAddress(const std::string & address)
	{
		return (GetHost(address.c_str()) != NULL);
	}

	// Returns the writable directory for this framework.
	// Type in "%appdata%/edxLabs" to access the directory.
	std::string GetWriteableDirectory(std::string baseDir)
	{
		std::stringstream ss;
		char strPath[MAX_PATH + 1] = {0};
		if(SHGetSpecialFolderPathA(0, strPath, CSIDL_APPDATA, FALSE) == FALSE)
		{
			MessageBoxA(0, "Unable to retrieve the path to the special folder AppData", "Error", MB_ICONERROR);
			throw 0;
		}
		else
		{
			ss << strPath << "\\edxLabs";
			CreateDirectoryA(ss.str().c_str(), 0);
			ss << "\\" << baseDir;
			CreateDirectoryA(ss.str().c_str(), 0);
			ss << "\\";
		}
		return ss.str();
	}

	//--------------------------------------------------------------------------------

	// Private data for the FileChooser class
	struct tFileChooserData
	{
		// File chooser struct
		OPENFILENAMEA fn;

		// Buffers for the file chooser 
		char setDirectory[2048];
		char setDialogTitle[2048];
		char setDefFileName[2048];
		char setFilter[2048];

		// User buffers to store data
		char filepath[2048];
		char filetitle[2048];
		char filename[2048];
		char fileext[2048];
		char filedir[2048];

		// Index in the filter string since we have to manually create it
		int filterIndex;

		// Can we use the ShowChooseFile function?
		bool canShow;
	};

	// Constructor
	FileChooser::FileChooser()
	{
		data = new tFileChooserData;
		memset(data, 0, sizeof(tFileChooserData));

		// Have to set this for the struct
		data->fn.lStructSize = sizeof(OPENFILENAME);

		// We can select a file
		data->canShow = true;
	}

	// Destructor
	FileChooser::~FileChooser()
	{
		delete data;
	}

	// Sets the initial directory the file chooser looks in
	void FileChooser::SetInitialDirectory(const char * pDir)
	{
		_snprintf(data->setDirectory, 2047, "%s", pDir);
	}

	// Sets the default dialog title of the file chooser
	void FileChooser::SetDialogTitle(const char * pTitle)
	{
		_snprintf(data->setDialogTitle, 2047, "%s", pTitle);
	}

	// Sets the default data->filename in the file choose dialog
	void FileChooser::SetDefaultFileName(const char * pFileName)
	{
		_snprintf(data->setDefFileName, 2047, "%s", pFileName);
	}

	// Adds a file browsing filter
	// pFilterName - Name of the extension to display, i.e. "Executable Files"
	// pFilterExt - Extension of the filter, i.e. "*.exe"
	void FileChooser::AddFilter(const char * pFilterName, const char * pFilterExt)
	{
		// First part is the name of the filter
		_snprintf(data->setFilter + data->filterIndex, 2047 - data->filterIndex, "%s", pFilterName);
		data->filterIndex += (int)strlen(pFilterName);

		// Separate with a NULL terminator
		data->setFilter[data->filterIndex++] = '\0';

		// Second part is the extension of the filter, *.EXTENSION
		_snprintf(data->setFilter + data->filterIndex, 2047 - data->filterIndex, "%s", pFilterExt);
		data->filterIndex += (int)strlen(pFilterExt);

		// Separate with a NULL terminator
		data->setFilter[data->filterIndex++] = '\0';
	}

	// Will return a string in this format: "Filename"
	const char * FileChooser::GetSelectedFileTitle()
	{
		return data->filetitle;
	}

	// Will return a string in this format: "Filename.Extension"
	const char * FileChooser::GetSelectedFileName()
	{
		return data->filename;
	}

	// Will return a string in this format: "Drive:\Path\To\File\Filename.Extension"
	const char * FileChooser::GetSelectedFilePath()
	{
		return data->filepath;
	}

	// Will return a string in this format: "Drive:\Path\To\File\"
	const char * FileChooser::GetSelectedFileDirectory()
	{
		return data->filedir;
	}

	// Will return a string in this format: "Extension"
	const char * FileChooser::GetSelectedFileExtension()
	{
		return data->fileext;
	}

	// Allow the user to select a file, returns true on success and false on failure
	bool FileChooser::ShowChooseFile(bool open)
	{
		// If we cannot show the file dialog, return failure
		if(!data->canShow)
			return false;

		// Store the current directory before we change it
		char curDir[256] = {0};
		GetCurrentDirectoryA(255, curDir);

		// Have to set this for the struct
		data->fn.lStructSize = sizeof(OPENFILENAME);

		// Default directory
		data->fn.lpstrInitialDir = data->setDirectory;

		// Finish the file filter with the two NULLS it needs at the end
		data->setFilter[data->filterIndex++] = '\0';
		data->setFilter[data->filterIndex++] = '\0';
		data->fn.lpstrFilter = data->setFilter;

		// Tell the chooser to use our buffer
		data->fn.lpstrFile = data->setDefFileName;

		// Max size of buffer
		data->fn.nMaxFile = 2047;

		// Tell the chooser to use our buffer
		data->fn.lpstrFileTitle = data->filename;

		// Max size of buffer
		data->fn.nMaxFileTitle = 2047;

		// Title we wish to display
		data->fn.lpstrTitle = data->setDialogTitle;

		// Display the chooser!
		if(open)
		{
			// Flags for selecting a file
			data->fn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

			if(!GetOpenFileNameA(&data->fn))
			{
				// Restore the old directory
				SetCurrentDirectoryA(curDir);

				// Error or the user canceled
				return FALSE;
			}
		}
		else
		{
			if(!GetSaveFileNameA(&data->fn))
			{
				// Restore the old directory
				SetCurrentDirectoryA(curDir);

				// Error or the user canceled
				return FALSE;
			}
		}

		// Restore the old directory
		SetCurrentDirectoryA(curDir);

		// Copy the file path from the struct into the buffer
		_snprintf(data->filepath, 2047, data->fn.lpstrFile);

		// Store the file directory
		_snprintf(data->filedir, 2047, "%s", data->fn.lpstrFile);

		// Loop though the string backwards
		for(int x = (int)strlen(data->filedir) - 1; x >= 0; --x)
		{
			// Stop at the first directory separator
			if(data->filedir[x] == '\\')
			{
				// Remove everything after it by setting a NULL terminator in the string
				data->filedir[x + 1] = 0;
				break;
			}
		}

		// Store the filetitle
		_snprintf(data->filetitle, 2047, "%s", data->filename);

		// Loop though the string forwards
		for(int y = (int)strlen(data->filetitle) - 1; y > 0; --y)
		{
			// Stop at the last extension separator
			if(data->filetitle[y] == '.')
			{
				// Remove it and everything past it
				data->filetitle[y] = 0;
				break;
			}
		}

		// Temp buffer to store the filename with extension
		char temp[2048] = {0};
		_snprintf(temp, 2047, "%s", GetSelectedFileName());
		strcpy(data->fileext, temp + strlen(data->filetitle) + 1);

		// We can no longer use this function again
		data->canShow = false;

		// Success
		return TRUE;
	}

	//--------------------------------------------------------------------------------

	ConfigFile::ConfigFile()
	{
		// Set a default section name
		mSection = "Default";
	}

	ConfigFile::~ConfigFile()
	{
	}

	// Opens a file to work with
	void ConfigFile::Open(std::string filename, bool useCurrentPath, bool & fileExists)
	{
		// If we do not need to get the current file path, simply assign the path
		if(!useCurrentPath)
		{
			mFileName = filename;
		}
		// Otherwise build the path
		else
		{
			// Holds the current directory
			char curDir[MAX_PATH + 1] = {0};
			char fullDir[MAX_PATH + 1] = {0};

			// Store the current directory
			GetCurrentDirectoryA(MAX_PATH, curDir);

			// Store the full path to the current directory
			GetFullPathNameA(curDir, MAX_PATH, fullDir, 0);

			// Build the filename now
			mFileName = fullDir;
			mFileName.append("\\");
			mFileName.append(filename);
		}

		// If there is no filename, the file does not exist
		if(!mFileName.size())
		{
			fileExists = false;
		}
		else
		{
			// File handle
			std::ifstream inFile;

			// Try to open the file
			inFile.open(filename.c_str());

			// Check to see if it is open or not
			fileExists = inFile.is_open();

			// Close the file
			inFile.close();
		}

		// Force the system to read the mapping into shared memory, so that future invocations of the application will see it without the user having to reboot the system 
		WritePrivateProfileStringA(NULL, NULL, NULL, filename.c_str());
	}

	// Set the section that the 'Write' and 'Read' functions use
	void ConfigFile::SetSection(const std::string& section)
	{
		mSection = section;
	}

	// Get the section that the 'Write' and 'Read' functions use
	std::string ConfigFile::GetSection() const
	{
		return mSection;
	}

	// Writes to the current section
	void ConfigFile::Write(const std::string& key, const std::string& data)
	{
		WritePrivateProfileStringA(mSection.c_str(), key.c_str(), data.c_str(), mFileName.c_str());
	}

	// Writes to any section
	void ConfigFile::WriteTo(const std::string& section, const std::string& key, const std::string& data)
	{
		WritePrivateProfileStringA(section.c_str(), key.c_str(), data.c_str(), mFileName.c_str());
	}

	// Read from the current section
	std::string ConfigFile::Read(const std::string& key)
	{
		static char buffer[131072] = {0};
	    ZeroMemory(buffer, 131072);
		GetPrivateProfileStringA(mSection.c_str(), key.c_str(), NULL, buffer, 131071, mFileName.c_str());
		return std::string(buffer);
	}

	// Read from any section
	std::string ConfigFile::ReadFrom(const std::string& section, const std::string& key)
	{
		static char buffer[131072] = {0};
		ZeroMemory(buffer, 131072);
		GetPrivateProfileStringA(section.c_str(), key.c_str(), NULL, buffer, 131071, mFileName.c_str());
		return std::string(buffer);
	}

	//--------------------------------------------------------------------------------

	// Writes bytes to a process
	BOOL WriteProcessBytes(HANDLE hProcess, DWORD destAddress, LPVOID patch, DWORD numBytes)
	{
		DWORD oldProtect = 0;	// Old protection on page we are writing to
		DWORD bytesRet = 0;		// # of bytes written
		BOOL status = TRUE;		// Status of the function

		// Change page protection so we can write executable code
		if(!VirtualProtectEx(hProcess, UlongToPtr(destAddress), numBytes, PAGE_EXECUTE_READWRITE, &oldProtect))
			return FALSE;

		// Write out the data
		if(!WriteProcessMemory(hProcess, UlongToPtr(destAddress), patch, numBytes, &bytesRet))
			status = FALSE;

		// Compare written bytes to the size of the patch
		if(bytesRet != numBytes)
			status = FALSE;

		// Restore the old page protection
		if(!VirtualProtectEx(hProcess, UlongToPtr(destAddress), numBytes, oldProtect, &oldProtect))
			status = FALSE;

		// Make sure changes are made!
		if(!FlushInstructionCache(hProcess, UlongToPtr(destAddress), numBytes))
			status = FALSE;

		// Return the final status, note once we set page protection, we don't want to prematurely return
		return status;
	}

	// Reads bytes of a process
	BOOL ReadProcessBytes(HANDLE hProcess, DWORD destAddress, LPVOID buffer, DWORD numBytes)
	{
		DWORD oldProtect = 0;	// Old protection on page we are writing to
		DWORD bytesRet = 0;		// # of bytes written
		BOOL status = TRUE;		// Status of the function

		// Change page protection so we can read bytes
		if(!VirtualProtectEx(hProcess, UlongToPtr(destAddress), numBytes, PAGE_READONLY, &oldProtect))
			return FALSE;

		// Read in the data
		if(!ReadProcessMemory(hProcess, UlongToPtr(destAddress), buffer, numBytes, &bytesRet))
			status = FALSE;

		// Compare written bytes to the size of the patch
		if(bytesRet != numBytes)
			status = FALSE;

		// Restore the old page protection
		if(!VirtualProtectEx(hProcess, UlongToPtr(destAddress), numBytes, oldProtect, &oldProtect))
			status = FALSE;

		// Return the final status, note once we set page protection, we don't want to prematurely return
		return status;
	}

	// Patches bytes in the current process
	BOOL WriteBytes(DWORD destAddress, LPVOID patch, DWORD numBytes)
	{
		// Store old protection of the memory page
		DWORD oldProtect = 0;

		// Store the source address
		DWORD srcAddress = PtrToUlong(patch);

		// Result of the function
		BOOL result = TRUE;

		// Make sure page is writable
		result = result && VirtualProtect(UlongToPtr(destAddress), numBytes, PAGE_EXECUTE_READWRITE, &oldProtect);

		// Copy over the patch
		memcpy(UlongToPtr(destAddress), patch, numBytes);

		// Restore old page protection
		result = result && VirtualProtect(UlongToPtr(destAddress), numBytes, oldProtect, &oldProtect);

		// Make sure changes are made
		result = result && FlushInstructionCache(GetCurrentProcess(), UlongToPtr(destAddress), numBytes); 

		// Return the result
		return result;
	}

	// Reads bytes in the current process
	BOOL ReadBytes(DWORD sourceAddress, LPVOID buffer, DWORD numBytes)
	{
		// Store old protection of the memory page
		DWORD oldProtect = 0;

		// Store the source address
		DWORD dstAddress = PtrToUlong(buffer);

		// Result of the function
		BOOL result = TRUE;

		// Make sure page is writable
		result = result && VirtualProtect(UlongToPtr(sourceAddress), numBytes, PAGE_EXECUTE_READWRITE, &oldProtect);

		// Copy over the patch
		memcpy(buffer, UlongToPtr(sourceAddress), numBytes);

		// Restore old page protection
		result = result && VirtualProtect(UlongToPtr(sourceAddress), numBytes, oldProtect, &oldProtect);

		// Return the result
		return result;
	}

	// Creates a codecave
	BOOL CreateCodeCave(DWORD destAddress, BYTE patchSize, VOID (*function)(VOID))
	{
		// Offset to make the codecave at
		DWORD offset = 0;

		// Bytes to write
		BYTE patch[5] = {0};

		// Number of extra nops we need
		BYTE nopCount = 0;

		// NOP buffer
		static BYTE nop[0xFF] = {0};

		// Is the buffer filled?
		static BOOL filled = FALSE;

		// Need at least 5 bytes to be patched
		if(patchSize < 5)
			return FALSE;

		// Calculate the code cave
		offset = (PtrToUlong(function) - destAddress) - 5;

		// Construct the patch to the function call
		patch[0] = 0xE8;
		memcpy(patch + 1, &offset, sizeof(DWORD));
		WriteBytes(destAddress, patch, 5);

		// We are done if we do not have NOPs
		nopCount = patchSize - 5;
		if(nopCount == 0)
			return TRUE;

		// Fill in the buffer
		if(filled == FALSE)
		{
			memset(nop, 0x90, 0xFF);
			filled = TRUE;
		}

		// Make the patch now
		WriteBytes(destAddress + 5, nop, nopCount);

		// Success
		return TRUE;
	}

	// Creates a console, need to call FreeConsole before exit
	VOID CreateConsole(CONST CHAR * winTitle)
	{
		// http://www.gamedev.net/community/forums/viewreply.asp?ID=1958358
		INT hConHandle = 0;
		HANDLE lStdHandle = 0;
		FILE *fp = 0 ;

		// Allocate the console
		AllocConsole();

		// Set a title if we need one
		if(winTitle) SetConsoleTitleA(winTitle);

		// redirect unbuffered STDOUT to the console
		lStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
		hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
		fp = _fdopen(hConHandle, "w");
		*stdout = *fp;
		setvbuf(stdout, NULL, _IONBF, 0);

		// redirect unbuffered STDIN to the console
		lStdHandle = GetStdHandle(STD_INPUT_HANDLE);
		hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
		fp = _fdopen(hConHandle, "r");
		*stdin = *fp;
		setvbuf(stdin, NULL, _IONBF, 0);

		// redirect unbuffered STDERR to the console
		lStdHandle = GetStdHandle(STD_ERROR_HANDLE);
		hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
		fp = _fdopen(hConHandle, "w");
		*stderr = *fp;
		setvbuf(stderr, NULL, _IONBF, 0);
	}
}

// by Drew Benton
namespace CC_ExtractPacket
{
	FARPROC fpHandler = (FARPROC)0x6AE8F0;

	DWORD currentOpcode;
	LPBYTE currentBuffer;
	DWORD currentSize;

	void OnProcessDataStart()
	{
		printf("=== %X ===\n", currentOpcode);
	}

	void ProcessData()
	{
		for(DWORD x = 0; x < currentSize; ++x)
		{
			printf("%.2X ", currentBuffer[x]);
			if((x+1)%16 == 0)
				printf("\n");
		}
		printf("\n");
	}

	void OnProcessDataEnd()
	{
		printf("\n\n");
	}

	DWORD codecave_ExtractPacket_ReturnAddress = 0;

	__declspec(naked) void codecave_ExtractPacket()
	{
		__asm pop codecave_ExtractPacket_ReturnAddress
		__asm mov currentOpcode, eax
		__asm pushad
		OnProcessDataStart();
		__asm popad
		__asm CMP EAX, 0x3369 // Original code
		__asm push codecave_ExtractPacket_ReturnAddress
		__asm ret
	}

	DWORD codecave_ReadBytes_ReturnAddress = 0;

	__declspec(naked) void codecave_ReadBytes()
	{
		__asm pop codecave_ReadBytes_ReturnAddress

		__asm mov currentBuffer, eax
		__asm mov currentSize, ebx

		__asm pushad
		ProcessData();
		__asm popad

		// Emulate the rest of the function since our codecave overlaps it all
		__asm POP ESI
		__asm MOV EAX,EBX
		__asm POP EBX
		__asm RET 8
	}

	void EnableParseHook()
	{
		edx::CreateCodeCave(0x4C42FC, 7, codecave_ReadBytes);
	}

	void DisableParseHook()
	{
		static BYTE patch[] = {0x5E, 0x8B, 0xC3, 0x5B, 0xC2, 0x08, 0x00};
		edx::WriteBytes(0x4C42FC, patch, 7);
		OnProcessDataEnd();
	}

	DWORD codecave_InvokeHandlers_ReturnAddress;
	__declspec(naked) void codecave_InvokeHandlers()
	{
		__asm pop codecave_InvokeHandlers_ReturnAddress

		__asm pushad
		EnableParseHook();
		__asm popad

		// We have to use this trick as VS does not support calling direct memory addresses
		__asm call fpHandler

		__asm pushad
		DisableParseHook();
		__asm popad

		__asm push codecave_InvokeHandlers_ReturnAddress
		__asm ret
	}

	void Setup()
	{
		edx::CreateCodeCave(0x74BDDA, 5, codecave_ExtractPacket);
		edx::CreateCodeCave(0x74BE85, 5, codecave_InvokeHandlers);
	}
}