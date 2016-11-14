#include <iostream>
#include <vector>
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#include <basetsd.h>
#include <string>
#include "main.h"
#include "d3d9.h"

#define W_WINDOW			1
#define W_STATIC_GRAPHIC	2
#define W_STATIC_TEXT		3
#define W_CTRL_BUTTON		4
#define W_CTRL_EDITBOX		5

#define W_WINDOW_TITLEBAR   30	// Height of the widget window title bar
#define W_CTRL_EDITBOX_BAR	20

#define W_LOOK_3D			100

using namespace std;

struct sWidget 
{
	int		 x;			// X coordinate
	int		 y;			// Y coordinate
	int		 w;			// Width of the widget
	int		 h;			// Height of the widget
	int		 type;		// Type of the widget (control, static graphic object etc.)
	int		 id;		// Unique ID of the widget for handling events
	int		 parent;	// Unique ID of widget's parent
	D3DCOLOR color;		// Color of the widget
	char     *text;		// Text (if any)
	D3DCOLOR txtColor;  // Color of the text
	int		 fontSize;  // Default font size
	bool	 over;		// Is the mouse over this widget
	bool	 pressed;	// Is the button pressed
	int		 look;		// The look of the widget
	int		 value;		// Value of the widget
};

struct sQuadVertex 
{
	float x, y, z, rhw;
	DWORD dwColor;
};

// by Drew Benton
namespace edx
{
	// Injects a DLL into a process at the specified address
	BOOL InjectDLL(HANDLE hProcess, const char * dllNameToLoad, const char * funcNameToLoad, DWORD injectAddress, bool bDebugAttach);

	// Returns the entry point of an EXE
	ULONGLONG GetEntryPoint(const char * filename);

	// Returns a pointer to a hostent object for the specified address
	hostent * GetHost(const char * address);

	// Returns the absolute directory path of the executable
	std::string GetAbsoluteDirectoryPath();

	// Creates a suspended process
	bool CreateSuspendedProcess(const std::string & filename, const std::string & fileargs, STARTUPINFOA & si, PROCESS_INFORMATION & pi);

	// Returns true if the host is accessible
	bool CanGetHostFromAddress(const std::string & address);

	// Returns the writable directory for this framework.
	// Type in "%appdata%/edxLabs" to access the directory.
	std::string GetWriteableDirectory(std::string baseDir);

	// Creates a codecave
	BOOL CreateCodeCave(DWORD destAddress, BYTE patchSize, VOID (*function)(VOID));

	// Patches bytes in the current process
	BOOL WriteBytes(DWORD destAddress, LPVOID patch, DWORD numBytes);

	// Reads bytes in the current process
	BOOL ReadBytes(DWORD sourceAddress, LPVOID buffer, DWORD numBytes);

	// Reads bytes of a process
	BOOL ReadProcessBytes(HANDLE hProcess, DWORD destAddress, LPVOID buffer, DWORD numBytes);

	// Writes bytes to a process
	BOOL WriteProcessBytes(HANDLE hProcess, DWORD destAddress, LPVOID patch, DWORD numBytes);

	// Creates a console, need to call FreeConsole before exit
	VOID CreateConsole(CONST CHAR * winTitle);

	// Forward declaration for the FileChooser class data so it is not exposed.
	struct tFileChooserData;

	// File chooser class
	class FileChooser
	{
	private:
		tFileChooserData* data;

	public:
		FileChooser();
		~FileChooser();

		// Sets the initial directory the file chooser looks in.
		void SetInitialDirectory(const char * pDir);

		// Sets the default dialog title of the file chooser component.
		void SetDialogTitle(const char * pTitle);

		// Sets the default filename in the file choose dialog.
		void SetDefaultFileName(const char * pFileName);

		// Adds a file browsing filter.
		void AddFilter(const char * pFilterName, const char * pFilterExt);

		// Allow the user to select a file. (open => true for param, save => false for param)
		bool ShowChooseFile(bool open);

		// Returns the file path of the selected file.
		const char * GetSelectedFilePath();

		// Returns the file directory of the selected file.
		const char * GetSelectedFileDirectory();

		// Returns the filename of the selected file.
		const char * GetSelectedFileName();

		// Returns the file title of the selected file.
		const char * GetSelectedFileTitle();

		// Returns the file extension of the selected file.
		const char * GetSelectedFileExtension();
	};

	class ConfigFile
	{
	private:
		std::string mFileName;
		std::string mSection;

	public:
		ConfigFile();
		~ConfigFile();

		// Opens a file to work with
		void Open(std::string filename, bool useCurrentPath, bool & fileExists);

		// Set the section that the 'Write' and 'Read' functions use
		void SetSection(const std::string & section);

		// Get the section that the 'Write' and 'Read' functions use
		std::string GetSection() const;

		// Writes to the current section
		void Write(const std::string & key, const std::string & data);

		// Writes to any section
		void WriteTo(const std::string & section, const std::string & key, const std::string & data);

		// Read from the current section
		std::string Read(const std::string & key);

		// Read from any section
		std::string ReadFrom(const std::string & section, const std::string & key);
	};
}


// by Drew Benton
namespace CC_ExtractPacket
{
	void OnProcessDataStart();
	void ProcessData();
	void OnProcessDataEnd();

	__declspec() void codecave_ExtractPacket();

	__declspec() void codecave_ReadBytes();

	void EnableParseHook();
	void DisableParseHook();

	__declspec() void codecave_InvokeHandlers();

	void Setup();
}
