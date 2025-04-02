#pragma once


#include "../HAWK_GUI/ToolBar.h"
#include "../HAWK_GUI/PacketCapturePanel.h"
#include "../HAWK_GUI/PortProxyPanel.h"
#include <wx/event.h>
#include <wx/mediactrl.h>
#include <map>

#define WINDOW_HEIGHT 600
#define WINDOW_WIDTH 1000

const wxColour DARKGREY = wxColour("dark grey");


class MainFrame : public wxFrame
{
public:    
    MainFrame();


private:
    ToolBar* _tb;
    wxPanel* _screenPanel;

    PortProxyPanel* _portProxyPanel;
    PacketCapturePanel* _packetCapturePanel;

    wxBoxSizer* _mainSizer;
    wxBoxSizer* _screenSizer;

    wxPanel** getPanelByName(std::string name);
    void OnCheckboxChanged(wxCommandEvent& event);
};

// Define the main application class
class HawkApp : public wxApp {
public:
    virtual bool OnInit() {
        ProtocolDB::init();
        MainFrame* frame = new MainFrame;
        frame->Show();
        return true;
    }
};
