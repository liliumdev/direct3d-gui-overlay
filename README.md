# direct3d-gui-overlay

Creates a custom GUI overlay inside a DX9 game using Matthew L.'s (aka Azorbix) Direct3D wrapper. This was written in June of 2009, and it's here on GitHub for archival and educational purposes. I've also written a tutorial on how to 'create your own ingame GUI' and [here's a link to it](http://www.elitepvpers.com/forum/sro-guides-templates/271434-guide-creating-your-own-ingame-silkroad-gui.html) and I'll quote some stuff from it below.

## What is this?

A generic ingame GUI framework (if you could call it a framework), which is fully movable/draggable around, features control support and with which you can make your own modifications to the game user interface easily.

## Purpose / Why ?

Well, did you ever think of a bot with a GUI inside the actual game ? Like, you press one key and all options appear there, without even alt-tabbing ! Have you ever thought of creating some utilities, like an ingame IRC or Winamp / WMP control in game ?

## Theory

Well, in theory, what we are trying to do should not be very hard, and it truly isn't hard at all once we see some code. We are going to make a DLL which will hook the DirectX interface, which will also make a global hook for mouse so we can enable dragging the windows around. Also we will need a DLL injector, so we can inject our DLL into our game. Our GUI will be consisting of windows and controls, to whom which we will, from now on, refer as to widgets. We will have two kinds of widgets; parent and child widgets. Child widgets are controls (although you can make them parent also). Since we don't need anything complicated (like moving a window in a window), child widgets are those widgets whose coordinates are relative to the parent widgets. 

## Usage

How to create windows and controls inside the game? With the developed class, it's something like this:

```
AddWindow(200,	200, 400, 400, "A Widget Window", 16, D3DCOLOR_ARGB(100, 0, 0, 200),  1, W_LOOK_3D);
AddButton(1, 50, 50, 100, 100, "Cool btn", 16, D3DCOLOR_ARGB(255, 0, 0, 255), 2, W_LOOK_3D);
```

## Screenshots and ideas

Sadly, all links to screenshots I uploaded back in 2009 are now dead. If you do compile this and get it up and running, please do send me a screenshot so I can put it here! I remember I also had an ingame IRC window back in the day (using a mIRC script and the window message queue hook on a game to communicate) - so there's a fun idea for you to implement. Or, you know, you could implement a full-fledged IRC client inside the DLL xD