#include "ToolBar.h"

ToolBar::ToolBar(wxFrame* parent) : wxToolBar(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTB_HORIZONTAL | wxTB_NOICONS | wxTB_TEXT)
{
    AddTool(INFO_CLICK, "Info", wxNullBitmap, "Info");
    AddTool(SETTINGS_CLICK, "Settings", wxNullBitmap, "Settings");

    AddTool(MENU_CLICK, "Tools", wxNullBitmap, "Select view options");

    // Create the menu
    _menu = new wxMenu();

    // Add menu items with checkboxes
    _packetCapture = new wxMenuItem(_menu, PACKET_CAPTURE_CLICK, "Packet Capture", "View PC Network Traffic", wxITEM_CHECK);
    _menu->Append(_packetCapture);

    _proxy = new wxMenuItem(_menu, PROXY_CLICK, "Port Proxy", "Simple MITM Traffic Editing", wxITEM_CHECK);
    _menu->Append(_proxy);


    Bind(wxEVT_TOOL, &ToolBar::OnToolbarButtonClicked, this, MENU_CLICK);
    Bind(wxEVT_MENU, &ToolBar::OnOptionSelected, this, PACKET_CAPTURE_CLICK);
    Bind(wxEVT_MENU, &ToolBar::OnOptionSelected, this, PROXY_CLICK);
    Bind(wxEVT_TOOL, &ToolBar::OnSettings, this, SETTINGS_CLICK);
    Bind(wxEVT_TOOL, &ToolBar::OnInfo, this, INFO_CLICK);


    _updateTimer = new wxTimer(this, wxID_ANY);
    Bind(wxEVT_TIMER, &ToolBar::OnTimer, this); //timer for updating dialog

    // Realize the toolbar (necessary after adding tools)
    Realize();
}

ToolBar::~ToolBar()
{
    if (_updateTimer) {
        _updateTimer->Stop();
        delete _updateTimer;
    }
    delete _menu;
}

void ToolBar::OnSettings(wxCommandEvent&)
{
    wxDialog dialog(this->m_parent, wxID_ANY, "Edit Supported Hosts", wxDefaultPosition, wxSize(300, 400));

    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

    wxListBox* listBox = new wxListBox(&dialog, wxID_ANY, wxDefaultPosition, wxSize(280, 300));
    listBox->SetBackgroundColour(wxColour(30, 30, 30));
    listBox->SetForegroundColour(wxColour(210, 210, 210)); 


    std::vector<std::string> hosts = HTTPSMITMProxy::getAcceptedHosts();
    for (const auto& host : hosts)
    {
        listBox->Append(wxString(host));
    }
    wxTextCtrl* input = new wxTextCtrl(&dialog, wxID_ANY, "", wxDefaultPosition, wxSize(280, 30));
    wxBoxSizer* buttonSizer = new wxBoxSizer(wxHORIZONTAL);
    wxButton* addButton = new wxButton(&dialog, wxID_ADD, "Add");
    wxButton* removeButton = new wxButton(&dialog, wxID_REMOVE, "Remove");
    buttonSizer->Add(addButton, 1, wxALL | wxEXPAND, 5);
    buttonSizer->Add(removeButton, 1, wxALL | wxEXPAND, 5);
    sizer->Add(listBox, 1, wxALL | wxEXPAND, 5);
    sizer->Add(input, 0, wxALL | wxEXPAND, 5);
    sizer->Add(buttonSizer, 0, wxALIGN_CENTER);
    dialog.SetSizerAndFit(sizer);
    addButton->Bind(wxEVT_BUTTON, [=](wxCommandEvent&) {
        wxString newItem = input->GetValue();
        if (!newItem.IsEmpty()) {
            if (HTTPSMITMProxy::addHost(newItem.ToStdString()))
            {
                listBox->Append(newItem);

                input->Clear();
            }
        }
        });
    removeButton->Bind(wxEVT_BUTTON, [=](wxCommandEvent&) {
        int selection = listBox->GetSelection();
        if (selection != wxNOT_FOUND) {
            HTTPSMITMProxy::removeHost(listBox->GetString(selection).ToStdString());
            listBox->Delete(selection);
        }
        });

    dialog.ShowModal();
}
void ToolBar::OnToolbarButtonClicked(wxCommandEvent& event)
{
    PopupMenu(_menu);
}
void ToolBar::OnOptionSelected(wxCommandEvent& event)
{
    wxMenuItem* item = _menu->FindItem(event.GetId());
    if (item && item->IsCheckable())
    {
        wxPostEvent(GetParent(), event);
    }
}

void ToolBar::OnInfo(wxCommandEvent&)
{
    const std::string ipv4Addr = ProxyServer::ipv4Available ? ProxyServer::_myIp : "(Unavailable)";
    const std::string ipv6Addr = ProxyServer::ipv6Available ? ProxyServer::_myIpv6 : "(Unavailable)";

    ShowProxyInfoPage(this->m_parent, ipv4Addr, ipv6Addr);

    _updateTimer->Start(3000);//update every 3 seconds
}

void ToolBar::ShowProxyInfoPage(wxWindow* parent, const wxString& ipv4, const wxString& ipv6)
{
    _infoDialog = new wxDialog(parent, wxID_ANY, "Proxy Information", wxDefaultPosition, wxSize(550, 350), wxDEFAULT_DIALOG_STYLE);
    _infoDialog->SetBackgroundColour(wxColour(30, 30, 30));

    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

    wxStaticText* titleText = new wxStaticText(_infoDialog, wxID_ANY, "Proxy Information");
    titleText->SetForegroundColour(wxColour(255, 255, 255));
    wxFont titleFont(14, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD);
    titleText->SetFont(titleFont);
    sizer->Add(titleText, 0, wxALL | wxALIGN_CENTER_HORIZONTAL, 10);

    wxStaticLine* divider1 = new wxStaticLine(_infoDialog, wxID_ANY, wxDefaultPosition, wxSize(430, 1));
    sizer->Add(divider1, 0, wxALL | wxEXPAND, 5);

    wxString ipInfo = wxString::Format("IPv4 Address: %s\nIPv6 Address: %s", ipv4, ipv6);
    wxStaticText* ipText = new wxStaticText(_infoDialog, wxID_ANY, ipInfo);
    ipText->SetForegroundColour(wxColour(200, 200, 200));
    wxFont ipFont(11, wxFONTFAMILY_TELETYPE, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);
    ipText->SetFont(ipFont);
    sizer->Add(ipText, 0, wxALL | wxALIGN_LEFT, 10);
    wxStaticLine* divider2 = new wxStaticLine(_infoDialog, wxID_ANY, wxDefaultPosition, wxSize(430, 1));
    sizer->Add(divider2, 0, wxALL | wxEXPAND, 5);

    _statsText = new wxStaticText(_infoDialog, wxID_ANY, "");
    _statsText->SetForegroundColour(wxColour(220, 220, 220));
    wxFont statsFont(10, wxFONTFAMILY_TELETYPE, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);
    _statsText->SetFont(statsFont);
    sizer->Add(_statsText, 0, wxALL | wxALIGN_LEFT, 10);
    wxStaticLine* divider3 = new wxStaticLine(_infoDialog, wxID_ANY, wxDefaultPosition, wxSize(430, 1));
    sizer->Add(divider3, 0, wxALL | wxEXPAND, 5);

    wxStaticText* footerText = new wxStaticText(_infoDialog, wxID_ANY, "Proxy program active and monitoring requests.");
    footerText->SetForegroundColour(wxColour(150, 150, 150));
    wxFont footerFont(9, wxFONTFAMILY_SWISS, wxFONTSTYLE_ITALIC, wxFONTWEIGHT_NORMAL);
    footerText->SetFont(footerFont);
    sizer->Add(footerText, 0, wxALL | wxALIGN_CENTER_HORIZONTAL, 5);

    wxButton* okButton = new wxButton(_infoDialog, wxID_OK, "OK");
    okButton->SetForegroundColour(wxColour(255, 255, 255));
    okButton->SetBackgroundColour(wxColour(70, 130, 180));
    sizer->Add(okButton, 0, wxALL | wxALIGN_CENTER_HORIZONTAL, 15);

    _infoDialog->SetSizer(sizer);

    updateStats();

    okButton->Bind(wxEVT_BUTTON, [&](wxCommandEvent&) {
        _updateTimer->Stop();
        _infoDialog->Destroy(); 
        });
    _infoDialog->Bind(wxEVT_CLOSE_WINDOW, [&](wxCloseEvent&) {
        _updateTimer->Stop();
        _infoDialog->Destroy();  
        });
    _infoDialog->Show();
}

void ToolBar::OnTimer(wxTimerEvent& event)
{
    updateStats();
}

void ToolBar::updateStats()
{
    size_t packetsTransferred = ProxyServer::getPacketsTransferred();
    double mbsTransferred = ProxyServer::getMbsTransferred() + PacketCapture::mbsCaptured();
    size_t openSessions = ProxyServer::getNumOpenSessions();

    // Update stats information
    wxString statsInfo = wxString::Format(
        "Packets Diverted: %zu\n"
        "Sessions Open: %zu\n"
        "Data Transferred: %.2f MB\n",
        packetsTransferred, openSessions, mbsTransferred
    );

    // Update the text label in the dialog
    if (_statsText) {
        _statsText->SetLabel(statsInfo);
        _infoDialog->Layout();  // Layout the dialog to reflect the changes
    }
}

wxMenuItem* ToolBar::GetMenuItemById(int id)
{
    return _menu->FindItem(id);
}
