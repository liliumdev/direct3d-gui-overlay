#include "Common.h"

class cUI
{
private:
	// Vector of all widgets
	vector<sWidget> widgets;	

	// Default font drawing class
	ID3DXFont *defFont;

	int	lastX;
	int	lastY;
	int	lastClick;

	// Is the UI visible or not
	bool visible;
public:
	//  Default constructor
	cUI();

	// Adds a new window to UI
	void AddWindow(int x, int y, int w, int h, char *title, int fontSize, D3DCOLOR col, int id, int look);

	// Adds a button to some window
	void AddButton(int parentWnd, int x, int y, int w, int h, char *text, int fontSize, D3DCOLOR col, int id, int look);

	// Adds an editbox to some window
	void AddEditBox(int parentWnd, int x, int y, int w, int h, char *text, int fontSize, D3DCOLOR col, int id, int look);

	// Sets the font color of a widget
	void SetWidgetFontColor(int id, D3DCOLOR col);

	// Draw UI - this MUST be called every EndScene, it's the main drawing function
	void DrawUI(IDirect3DDevice9 *pD3Ddev);	

	// Main event handler
	void HandleCtrlEvents(int id);

	// This takes care of mouse drag events
	bool HandleMouseEvents(WPARAM wParam, LPARAM lParam);

	// Returns the position of a widget in the vector by passing only ID
	int GetWidget(int id);

	// Makes the UI visible
	void MakeVisible();

	// Draws a simple rectangle and returns the widget info
	void DrawRectangle(IDirect3DDevice9 *pD3Ddev, int x, int y, int w, int h, D3DCOLOR col);

	// Draws a simple line between two given points
	void DrawLine(IDirect3DDevice9 *pD3Ddev, float sX, float sY, float eX, float eY, D3DCOLOR color);

	// Initialize all stuff we have
	void Initialize(IDirect3DDevice9 *pD3Ddev);

	// Deinitialize all stuff we have
	void Deinitialize(IDirect3DDevice9 *pD3Ddev);

	void OnLostDevice();
	void OnResetDevice();
};