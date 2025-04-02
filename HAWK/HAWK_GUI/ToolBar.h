#pragma once

#include <wx/wx.h>
#include <wx/artprov.h>
#include <wx/statline.h>
#include "../HAWK_PROXY_SERVER/SessionHandlers.h"
#include "../HAWK_WIRESHARK/PacketCapture.h"

wxDEFINE_EVENT(wxEVT_CHECKBOX_CHANGED, wxCommandEvent);



const int SETTINGS_CLICK = 1001;
const int MENU_CLICK = 1002;
const int PACKET_CAPTURE_CLICK = 1003;
const int PROXY_CLICK = 1004;
const int INFO_CLICK = 1005;

class ToolBar : public wxToolBar
{
public:	
	ToolBar(wxFrame* parent);

    ~ToolBar();

    wxMenuItem* GetMenuItemById(int id);

private:
    void OnSettings(wxCommandEvent&);
    void OnToolbarButtonClicked(wxCommandEvent& event);
    void OnOptionSelected(wxCommandEvent& event);

    void OnInfo(wxCommandEvent&);

    void ShowProxyInfoPage(wxWindow* parent,
        const wxString& ipv4,
        const wxString& ipv6
    );

    void OnTimer(wxTimerEvent& event);
    void updateStats();
    
    wxTimer* _updateTimer;
    wxDialog* _infoDialog;
    wxStaticText* _statsText;

    wxMenu* _menu;
    wxMenuItem* _packetCapture;
    wxMenuItem* _proxy;
};
