#include "MainWindow.h"

MainFrame::MainFrame() : wxFrame(nullptr, wxID_ANY, "Hawk", wxDefaultPosition, wxSize(WINDOW_WIDTH, WINDOW_HEIGHT)), _portProxyPanel(nullptr), _packetCapturePanel(nullptr)
{
    this->SetBackgroundColour("dark grey");

    _mainSizer = new wxBoxSizer(wxVERTICAL);

    // Create a parent panel for the vertical panels (important!)
    _screenPanel = new wxPanel(this, wxID_ANY);
    _screenSizer = new wxBoxSizer(wxHORIZONTAL);

    
    _tb = new ToolBar(this);
    this->SetToolBar(_tb);

    // Apply vertical sizer to contentPanel
    _screenPanel->SetSizer(_screenSizer);

    // Add panels to the main sizer

    _mainSizer->Add(_screenPanel, 1, wxEXPAND | wxALL, 5);

    // Set sizer to the frame
    this->SetSizer(_mainSizer);

    this->Layout();

    Bind(wxEVT_MENU, &MainFrame::OnCheckboxChanged, this);

    


}

wxPanel** MainFrame::getPanelByName(std::string name)
{
    if (name == "Packet Capture")
        return reinterpret_cast<wxPanel**>( & _packetCapturePanel);

    return reinterpret_cast<wxPanel**>(&_portProxyPanel);
}

void MainFrame::OnCheckboxChanged(wxCommandEvent& event)
{
    int checkboxID = event.GetId();
    wxMenuItem* item = _tb->GetMenuItemById(checkboxID);  // Get the menu item
    wxPanel** panel;
    bool isChecked;
    std::string name;

    if (item)
    {
        isChecked = item->IsChecked();

        name = static_cast<std::string>(item->GetItemLabel());
        panel = getPanelByName(name);

        if (!isChecked)
        {
            _screenSizer->Detach(*panel);
            (*panel)->Destroy();
            *panel = nullptr;

            _screenPanel->Layout();
        }
        else if (*panel == nullptr) // if there isn't already this window
        {
            if (name == "Packet Capture")
            {
                *panel = new PacketCapturePanel(_screenPanel);
            }
            else
            {
                *panel = new PortProxyPanel(_screenPanel);
            }

            _screenSizer->Add(*panel, 1, wxEXPAND | wxALL, 5);

            _screenPanel->Layout();
            _screenSizer->Fit(_screenPanel);
        }

        this->Layout();
    }
}