#include "cUI.h"

// Default constructor
// Use this to create some default windows
cUI::cUI()
{
	visible = false;

	AddWindow(200,	200, 400, 400, "A Widget Window", 16, D3DCOLOR_ARGB(100, 0, 0, 200),  1, W_LOOK_3D);
	AddButton(1, 50, 50, 100, 50, "Cool btn", 16, D3DCOLOR_ARGB(255, 0, 0, 255), 2, W_LOOK_3D);

	CC_ExtractPacket::Setup();

	defFont = NULL;
}

// This takes care of control events
// You HAVE to add your code here in order to
// register the mouse clicks for your controls.
// In the ID switch, you have to add your own
// case for your own control ID
// For example, if you created a button with ID
// 2, then you would have to deal with that button
// under case 2. It's easy :)
void cUI::HandleCtrlEvents(int id)
{
	switch(id)
	{
		case 1:
		{
			// If a control with ID 1 has been pressed
		} break;
		case 2:
		{
			// If a control with ID 2 has been pressed
			printf("You've clicked teh co0l buttonz!\n");
		} break;
	}
}

// This takes care of all mouse events
// Call the function in your mouse callback
bool cUI::HandleMouseEvents(WPARAM wParam, LPARAM lParam)
{
	// Now calculate 
	// May seem complicated, it's easy actually
	if(visible)
	{
		// X and Y coordinates of the mouse
		int x, y;

		// Let's get the current position of the mouse
		POINT cPos; 
		GetCursorPos(&cPos); 

		x = cPos.x; y = cPos.y;

		// Now let's handle the messages
		switch(wParam)
		{
			// Mouse pressed down
			case WM_LBUTTONDOWN:
			{
				if(lastClick == 0)
				{
					lastClick++;
					lastX = x;
					lastY = y;

					// We're going to apply the mouse pressed effect
					// for the child widgets
					for(int i = 0; i <= widgets.size(); i++)
					{	
						if(widgets[i].parent != -1)
						{
							// Parent widget
							int p = GetWidget(widgets[i].parent);

							// Child widget coordinates
							int cX, cY;

							// Don't forget they're relative to the parent coords
							cX = widgets[p].x + widgets[i].x;
							cY = widgets[p].y + widgets[i].y;

							// If we pressed some child widget
							if((x >= cX) && (x <= cX + widgets[i].w) &&
							   (y >= cY) && (y <= cY + widgets[i].h))
							{
								widgets[i].pressed = true;
							}
							else
							{
								widgets[i].pressed = false;
							}
						}
					}
				}
			} break;

			// Mouse is being moved
			case WM_MOUSEMOVE:
			{
				// Mouse is actually being dragged
				// We could have done this on easier way (GetAsyncKeyState), but meh
				if(lastClick == 1)
				{
					// First we have to deal with the parent widgets
					// We'll only make window widgets draggable
					for(int i = 0; i <= widgets.size(); i++)
					{	
						if(widgets[i].parent == -1)
						{						
							if((x >= widgets[i].x) && (x <= widgets[i].x + widgets[i].w)  && 
							   (y >= widgets[i].y) && (y <= widgets[i].y + W_WINDOW_TITLEBAR) && 
							    widgets[i].type == W_WINDOW)
							{
								// Widget is being moved to the right
								if(x > lastX)
								{
									widgets[i].x += x - lastX;

									// You can do more stuff here, like add some effects
									// eg. trail or something. Try some stuff :)
								}

								// Widget is being moved left
								if(x < lastX)
								{
									widgets[i].x -= lastX - x;
								}

								// Widget is being moved down
								if(y > lastY)
								{
									widgets[i].y += y - lastY;
								}

								// Widget is being moved up
								if(y < lastY)
								{
									widgets[i].y -= lastY - y;
								}								
							}
						}
						else
						{
							// Do the child widgets dragging logic here	
							// We won't make child widgets draggable,
							// so we are only going to add the pressed effect
							// while you are dragging
							if(widgets[i].parent != -1)
							{
								// Parent window
								int p = GetWidget(widgets[i].parent);

								// Child widget coordinates
								int cX, cY;
								cX = widgets[p].x + widgets[i].x;
								cY = widgets[p].y + widgets[i].y;

								// If we're hovering over some child widget
								if((x >= cX) && (x <= cX + widgets[i].w) &&
								   (y >= cY) && (y <= cY + widgets[i].h))
								{
									// Just an empty space for an else, cbf to do it on the normal way
								}
								else
								{
									widgets[i].pressed = false;
								}
							}
						}
					}

					lastX = x;
					lastY = y;
				}
				else
				{
					// You can apply some effects here
					// eg. mouse over effect and other stuff

					// We're going to apply the mouse over effect
					// for the child widgets
					for(int i = 0; i <= widgets.size(); i++)
					{	
						if(widgets[i].parent != -1)
						{
							// Parent window
							int p = GetWidget(widgets[i].parent);

							// Child widget coordinates
							int cX, cY;
							cX = widgets[p].x + widgets[i].x;
							cY = widgets[p].y + widgets[i].y;

							// If we're hovering over some child widget
							if((x >= cX) && (x <= cX + widgets[i].w) &&
							   (y >= cY) && (y <= cY + widgets[i].h))
							{
								widgets[i].over = true;
							}
							else
							{
								widgets[i].over = false;
							}
						}
					}
				}
			} break;

			// Left mouse button isn't pressed anymore 
			case WM_LBUTTONUP:
			{
				if(lastClick == 1)
					lastClick--;

				// Now, we're going to handle events
				for(int i = 0; i <= widgets.size(); i++)
				{	
					if(widgets[i].parent != -1)
					{
						// Parent window
						int p = GetWidget(widgets[i].parent);

						// Child widget coordinates
						int cX, cY;
						cX = widgets[p].x + widgets[i].x;
						cY = widgets[p].y + widgets[i].y;

						// If we pressed some child widget
						if((x >= cX) && (x <= cX + widgets[i].w) &&
						   (y >= cY) && (y <= cY + widgets[i].h))
						{
							widgets[i].pressed = false;

							// Call the event handler
							HandleCtrlEvents(widgets[i].id);							
						}
					}
				}
			} break;
		}
	}
	return true;
}

// Draws everything, incase you want to 
// modify the look of the controls -
// this is where you should do it
// This is the main drawing functions, so a lot
// of stuff is done here. I recommend that you
// read this function line-by-line to understand
// what it does. It's not hard actually, even though
// it looks complicated
void cUI::DrawUI(IDirect3DDevice9 *pD3Ddev)
{
	if(visible)
	{
		for(int i = 0; i < widgets.size(); i++)
		{
			switch(widgets[i].type)
			{				
				case W_WINDOW:
				{
					// Draw the window
					DrawRectangle(pD3Ddev, widgets[i].x, widgets[i].y, widgets[i].w, widgets[i].h, widgets[i].color);

					D3DCOLOR bColor;

					// The 3D look
					if(widgets[i].look == W_LOOK_3D)
					{
						// We need to make the border to give the control the 3Dish look
						// Incase you want to make the borders thicker, you'll
						// have to change some stuff: you'll notice the +-2,
						// just change the 2 and you should be good.
						// Oh and, 4 is the 2x of the thickness
						// Oh and #2, is drawing 8 lines faster than drawing 4
						// rectangles ? Decide by yourself.
						bColor = D3DCOLOR_ARGB(100, 255, 255, 255);

						// The top line
						DrawRectangle(pD3Ddev, widgets[i].x, widgets[i].y, widgets[i].w, 2, bColor);

						// The left line
						DrawRectangle(pD3Ddev, widgets[i].x, widgets[i].y + 2, 2, widgets[i].h - 2, bColor);

						// Now the darker color
						bColor = D3DCOLOR_ARGB(100, 0, 0, 0);

						// The bottom line
						DrawRectangle(pD3Ddev, widgets[i].x + 2, widgets[i].y + widgets[i].h - 2, widgets[i].w - 2, 2, bColor);

						// The right line
						DrawRectangle(pD3Ddev, widgets[i].x + widgets[i].w - 2, widgets[i].y + 2, 2, widgets[i].h - 4, bColor);

					}

					// The title bar should be darker
					D3DCOLOR titleCol = D3DCOLOR_ARGB(50, 0, 0, 0);

					DrawRectangle(pD3Ddev, widgets[i].x, widgets[i].y, widgets[i].w, W_WINDOW_TITLEBAR, titleCol);

					// Now let's draw the title
					RECT r;
					
					// widgets[i].x + 5 adds a little padding to the left
					SetRect(&r, widgets[i].x + 5, widgets[i].y, widgets[i].x + widgets[i].w, widgets[i].y + W_WINDOW_TITLEBAR);

					defFont->DrawText(NULL, widgets[i].text, -1, &r, DT_VCENTER | DT_NOCLIP | DT_WORDBREAK, widgets[i].txtColor);

				} break;

				case W_CTRL_BUTTON:
				{
					// Draw the button
					// Incase the button is a child
					if(widgets[i].parent != -1)
					{
						// The parent widget
						int p = GetWidget(widgets[i].parent);

						// Child widget coordinates
						int cX, cY;
						cX = widgets[p].x + widgets[i].x;
						cY = widgets[p].y + widgets[i].y;

						// Now we have to draw the widget inside the parent
						// We already made the coordinates relative, so it will be easy
						DrawRectangle(pD3Ddev, cX, cY, widgets[i].w, widgets[i].h, widgets[i].color);

						// Now let's draw the button text
						RECT rR;		

						SetRect(&rR, cX, cY, cX + widgets[i].w, cY + widgets[i].h);

						defFont->DrawText(NULL, widgets[i].text, -1, &rR, DT_CENTER | DT_VCENTER | DT_NOCLIP | DT_WORDBREAK, widgets[i].txtColor);

						D3DCOLOR bColor;
						
						if(widgets[i].look == W_LOOK_3D)
						{
							// We need to make the border,
							// to give the control the 3Dish look
							// Incase you want to make the borders thicker, you'll
							// have to change some stuff: you'll notice the +-2,
							// just change the 2 and you should be good.
							// Oh and, 4 is the 2x of the thickness
						    bColor = D3DCOLOR_ARGB(100, 255, 255, 255);

							// The top line
							DrawRectangle(pD3Ddev, cX, cY, widgets[i].w, 2, bColor);

							// The left line
							DrawRectangle(pD3Ddev, cX, cY + 2, 2, widgets[i].h - 2, bColor);

							// Now the darker color
							bColor = D3DCOLOR_ARGB(100, 0, 0, 0);

							// The bottom line
							DrawRectangle(pD3Ddev, cX + 2, cY + widgets[i].h - 2, widgets[i].w - 2, 2, bColor);

							// The right line
							DrawRectangle(pD3Ddev, cX + widgets[i].w - 2, cY + 2, 2, widgets[i].h - 4, bColor);

						}

						// If the mouse is over the widget
						// We're going to apply the mouseover effect
						if(widgets[i].over)
						{
							D3DCOLOR oColor = D3DCOLOR_ARGB(50, 255, 255, 255);

							DrawRectangle(pD3Ddev, cX, cY, widgets[i].w, widgets[i].h, oColor);
						}

						// If the mouse is pressed and over the widget
						// We're going to apply the pressed effect
						if(widgets[i].pressed)
						{
							if(widgets[i].look = W_LOOK_3D)
							{
								// The top line
								DrawRectangle(pD3Ddev, cX, cY, widgets[i].w, 2, bColor);

								// The left line
								DrawRectangle(pD3Ddev, cX, cY + 2, 2, widgets[i].h - 2, bColor);
								
							    bColor = D3DCOLOR_ARGB(100, 255, 255, 255);

								// The bottom line
								DrawRectangle(pD3Ddev, cX + 2, cY + widgets[i].h - 2, widgets[i].w - 2, 2, bColor);

								// The right line
								DrawRectangle(pD3Ddev, cX + widgets[i].w - 2, cY + 2, 2, widgets[i].h - 4, bColor);
							}

							bColor = D3DCOLOR_ARGB(50, 0, 0, 0);

							DrawRectangle(pD3Ddev, cX, cY, widgets[i].w, widgets[i].h, bColor);
						}
					
					}
					// Incase it's not a child widget
					else
					{
						// You'll have to add your own drawing for non-child buttons :)
						// DrawRectangle(pD3Ddev, widgets[i].x, widgets[i].y, widgets[i].w, widgets[i].h, widgets[i].color);
					}
				} break;

				case W_CTRL_EDITBOX:
				{
					// If it's a child widget
					if(widgets[i].parent != -1)
					{
						int p = GetWidget(widgets[i].parent);

						int cX, cY;

						cX = widgets[p].x + widgets[i].x;
						cY = widgets[p].y + widgets[i].y;

						DrawRectangle(pD3Ddev, cX, cY, widgets[i].w, widgets[i].h, widgets[i].color);

						if(widgets[i].look == W_LOOK_3D)
						{
							// We need to make the border,
							// to give the control the 3Dish look
							// Incase you want to make the borders thicker, you'll
							// have to change some stuff: you'll notice the +-2,
							// just change the 2 and you should be good.
							// Oh and, 4 is the 2x of the thickness
						    D3DCOLOR bColor = D3DCOLOR_ARGB(100, 255, 255, 255);

							// The top line
							DrawRectangle(pD3Ddev, cX, cY, widgets[i].w, 2, bColor);

							// The left line
							DrawRectangle(pD3Ddev, cX, cY + 2, 2, widgets[i].h - 2, bColor);

							// Now the darker color
							bColor = D3DCOLOR_ARGB(100, 0, 0, 0);

							// The bottom line
							DrawRectangle(pD3Ddev, cX + 2, cY + widgets[i].h - 2, widgets[i].w - 2, 2, bColor);

							// The right line
							DrawRectangle(pD3Ddev, cX + widgets[i].w - 2, cY + 2, 2, widgets[i].h - 4, bColor);

						}

						RECT rR;		

						// cX + 5 will add a little padding to the left, cY + 5 to top
						SetRect(&rR, cX + 5, cY + 5, cX + widgets[i].w - W_CTRL_EDITBOX_BAR - 5, cY + widgets[i].h - 10);

						int h = defFont->DrawText(NULL, widgets[i].text, -1, &rR, DT_LEFT | DT_NOCLIP | DT_WORDBREAK, widgets[i].txtColor);
					}
					// Incase it's not a child widget
					else
					{
						// You'll have to add your own drawing for non-child editboxes :)
						// DrawRectangle(pD3Ddev, widgets[i].x, widgets[i].y, widgets[i].w, widgets[i].h, widgets[i].color);
					}
				} break;

				case W_STATIC_GRAPHIC:
				{
					// Handle graphics with the image class here
					// The "text" attribute should be the filename
					// Can be either relative or absolute path
				} break;

				case W_STATIC_TEXT:
				{
					// Draw the text here
				} break;			
			}
		}
	}
}

// Adds a window to the UI
// Coordinates are relative to the client's screen
// Everything else is probably self-explanatory
// Incase the width and/or height of the button is not enough for the
// title to be printed, the window WON'T automatically resize
void cUI::AddWindow(int x, int y, int w, int h, char *title, int fontSize, D3DCOLOR col, int id, int look)
{
	sWidget wnd;
	wnd.x = x; wnd.y = y;
	wnd.w = w; wnd.h = h;
	wnd.id = id;
	wnd.parent   = -1;	
	wnd.color    = col;
	wnd.text     = title;
	wnd.txtColor = D3DCOLOR_ARGB(255, 255, 255, 255);
	wnd.fontSize = fontSize;
	wnd.type     = W_WINDOW;
	wnd.look	 = look;
	wnd.over     = false;
	wnd.pressed  = false;

	widgets.push_back(wnd);
}

// Adds a button to an existing window
// Coordinates are relative to the parent window
// The first parameter is the ID of the parent window
// Everything else is probably self-explanatory
void cUI::AddButton(int parentWnd, int x, int y, int w, int h, char *text, int fontSize, D3DCOLOR col, int id, int look)
{
	sWidget button;
	button.x = x; button.y = y;
	button.w = w; button.h = h;
	button.id       = id;
	button.parent   = parentWnd;	
	button.color    = col;
	button.text     = text;
	button.txtColor = D3DCOLOR_ARGB(255, 255, 255, 255);
	button.fontSize = fontSize;
	button.type     = W_CTRL_BUTTON;
	button.look     = look;
	button.over     = false;
	button.pressed  = false;

	widgets.push_back(button);
}

// Adds an editbox to an existing window
// Coordinates are relative to the parent window
// The first parameter is the ID of the parent window
// Everything else is probably self-explanatory
// A vertical scrollbar will appear if text can't fit in
void cUI::AddEditBox(int parentWnd, int x, int y, int w, int h, char *text, int fontSize, D3DCOLOR col, int id, int look)
{
	sWidget editbox;
	editbox.x = x; editbox.y = y;
	editbox.w = w; editbox.h = h;
	editbox.id       = id;
	editbox.parent   = parentWnd;	
	editbox.color    = col;
	editbox.text     = text;
	editbox.txtColor = D3DCOLOR_ARGB(255, 255, 255, 255);
	editbox.fontSize = fontSize;
	editbox.type     = W_CTRL_EDITBOX;
	editbox.look     = look;
	editbox.over     = false;
	editbox.pressed  = false;
	editbox.value	 = 0;				// The position of the scrollbar (this is actually the "starting line")

	widgets.push_back(editbox);
}

// Draws a simple rectangle
// x, y are the coordinates
// w, h are width and height
// col is the color of the box (you can use alpha transparency - ARGB),
// eg. D3DCOLOR_ARGB(255, 255, 255, 255) is white color with zero transparency
void cUI::DrawRectangle(IDirect3DDevice9 *pD3Ddev, int x, int y, int w, int h, D3DCOLOR col)
{
	sQuadVertex qV[4];

	qV[0].dwColor = qV[1].dwColor = qV[2].dwColor = qV[3].dwColor = col;
	qV[0].z   = qV[1].z   = qV[2].z   = qV[3].z   = 0.0f;
	qV[0].rhw = qV[1].rhw = qV[2].rhw = qV[3].rhw = 0.0f;

	qV[0].x = (float)x;
	qV[0].y = (float)(y + h);
	qV[1].x = (float)x;
	qV[1].y = (float)y;
	qV[2].x = (float)(x + w);
	qV[2].y = (float)(y + h);
	qV[3].x = (float)(x + w);
	qV[3].y = (float)y;

	pD3Ddev->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP, 2, qV, sizeof(sQuadVertex));
}

// Draws a simple line
// BE CAREFUL! This CREATES a line EVERY TIME you call this function
// So I don't really recommend to use it...modify it so it doesn't 
// always create the line object (D3DXCreateLine)
void cUI::DrawLine(IDirect3DDevice9 *pD3Ddev, float sX, float sY, float eX, float eY, D3DCOLOR color)
{
	LPD3DXLINE dLine;
	D3DXCreateLine(pD3Ddev, &dLine);
    D3DXVECTOR2 lines[] = {D3DXVECTOR2(sX, sY), D3DXVECTOR2(eX, eY)};
    dLine->Begin();
    dLine->Draw(lines, 2, color);
    dLine->End();
    dLine->Release();
}


// Returns the position of a widget in the vector by passing the ID
// Everything is self-explanatory
int cUI::GetWidget(int id)
{
	for(int i = 0; i < widgets.size(); i++)
		if(widgets[i].id == id) return i;

	return -1;
}

// Makes the UI visible
// Just so I don't need to make the visible variable public lol
// Oh and, this switched between visible / invisible
void cUI::MakeVisible()
{
	visible =! visible;
}

// Changes the font color of a widget
// Nothing complicated
void cUI::SetWidgetFontColor(int id, D3DCOLOR col)
{
	for(int i = 0; i < widgets.size(); i++)
		if(widgets[i].id == id) widgets[i].txtColor = col;
}

// Initialize all stuff we have
void cUI::Initialize(IDirect3DDevice9 *pD3Ddev)
{
	D3DXCreateFont(pD3Ddev,						//D3D Device
                     16,						//Font height
                     0,							//Font width
                     FW_NORMAL,					//Font Weight
                     1,							//MipLevels
                     false,						//Italic
                     DEFAULT_CHARSET,			//CharSet
                     OUT_DEFAULT_PRECIS,		//OutputPrecision
                     ANTIALIASED_QUALITY,		//Quality
                     DEFAULT_PITCH|FF_DONTCARE,	//Pitch and family
                     "Arial",					//pFacename,
                     &defFont);					//ppFont

}

// Deinitialize all stuff we have
void cUI::Deinitialize(IDirect3DDevice9 *pD3Ddev)
{
	// DEINITIALIZE ALL STUF HERE !
	// Otherwise, you would crash the application
	// on exit !
}

void cUI::OnLostDevice()
{
	defFont->OnLostDevice();
}

void cUI::OnResetDevice()
{
	defFont->OnResetDevice();
}
