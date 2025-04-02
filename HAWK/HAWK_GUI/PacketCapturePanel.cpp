#include "PacketCapturePanel.h"




PacketCapturePanel::PacketCapturePanel(wxWindow* parent) : wxPanel(parent, wxID_ANY, wxDefaultPosition, wxSize(-1, 100))
{
	SetBackgroundColour(CAPTURE_COLOUR);

    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

    wxBoxSizer* topSizer = new wxBoxSizer(wxHORIZONTAL);


    _deviceChoice = new wxChoice(this, wxID_ANY);
    const std::vector<std::string>& devices = this->_packetCaptureDev.getAllDeviceNames();
    for (const auto& device : devices) {
        _deviceChoice->Append(device);
    }

    wxBoxSizer* deviceSizer = new wxBoxSizer(wxVERTICAL);
    wxStaticText* text = new wxStaticText(this, wxID_ANY, "Select a Network Device:");
    text->SetForegroundColour(wxColour(210, 210, 210));
    deviceSizer->Add(text, 0, wxALL, 5);
    deviceSizer->Add(_deviceChoice, 0, wxEXPAND | wxALL, 5);


    topSizer->Add(deviceSizer, 1, wxEXPAND | wxALL, 5);

    wxBoxSizer* buttonSizer = new wxBoxSizer(wxHORIZONTAL);

    _startButton = new wxButton(this, wxID_ANY, "Start Capture");
    buttonSizer->Add(_startButton, 0, wxALL, 5);


    _stopButton = new wxButton(this, wxID_ANY, "Stop Capture");
    _stopButton->Disable();
    buttonSizer->Add(_stopButton, 0, wxALL, 5);


    _clearButton = new wxButton(this, wxID_ANY, "Clear");
    buttonSizer->Add(_clearButton, 0, wxALL, 5);


    topSizer->Add(buttonSizer, 0, wxALIGN_CENTER_VERTICAL | wxALL, 5);
    sizer->Add(topSizer, 0, wxEXPAND | wxALL, 5);


    _packetList = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxSize(-1, 200), wxLC_REPORT | wxLC_SINGLE_SEL);

    _packetList->SetBackgroundColour(wxColour(30, 30, 30));

    // Add table columns
    _packetList->InsertColumn(0, "Time", wxLIST_FORMAT_LEFT, 100);
    _packetList->InsertColumn(1, "Source", wxLIST_FORMAT_LEFT, 150);
    _packetList->InsertColumn(2, "Destination", wxLIST_FORMAT_LEFT, 150);
    _packetList->InsertColumn(3, "Protocol", wxLIST_FORMAT_LEFT, 100);
    _packetList->InsertColumn(4, "Length", wxLIST_FORMAT_LEFT, 80);
    _packetList->InsertColumn(5, "Info", wxLIST_FORMAT_LEFT, 300);

    sizer->Add(_packetList, 1, wxEXPAND | wxALL, 5);

    SetSizer(sizer);


    _startButton->Bind(wxEVT_BUTTON, &PacketCapturePanel::OnStartCapture, this);
    _stopButton->Bind(wxEVT_BUTTON, &PacketCapturePanel::OnStopCapture, this);
    _clearButton->Bind(wxEVT_BUTTON, &PacketCapturePanel::OnClear, this);
    Bind(EVT_NEW_PACKET, &PacketCapturePanel::OnNewPacket, this);
    _packetList->Bind(wxEVT_LIST_ITEM_SELECTED, &PacketCapturePanel::OnListItemSelected, this);


    Bind(wxEVT_MAXIMIZE, &PacketCapturePanel::OnMaximize, this);
    Bind(wxEVT_ICONIZE, &PacketCapturePanel::OnMinimize, this);

    Bind(wxEVT_SIZE, &PacketCapturePanel::OnResize, this);
}
//close the packetCaptureDev
//close all threads
PacketCapturePanel::~PacketCapturePanel()
{
    _running = false;
    this->_packetCaptureDev.halt();
    if (_captureThread.joinable()) {
        _captureThread.join();
    }
    if (this->_listeningThread.joinable())
    {
        this->_listeningThread.join();
    }

    clearList();
}

void PacketCapturePanel::clearList()
{
    std::lock_guard<std::mutex> lock(this->_listMutex);
    long item = 0;
    long itemCount = this->_packetList->GetItemCount();
    while (item < itemCount)
    {
        Packet* data = (Packet*)(this->_packetList->GetItemData(item));
        if (data)
            delete data; 
        item++;
        
    }
    this->_packetList->DeleteAllItems();
    
}

void PacketCapturePanel::OnStartCapture(wxCommandEvent& event)
{
    int selection = _deviceChoice->GetSelection();
    if (selection == wxNOT_FOUND) {
        wxMessageBox("Please select a network device.", "Error", wxOK | wxICON_ERROR);
        return;
    }

    std::string selectedDevice = _deviceChoice->GetString(selection).ToStdString();
    this->_listeningThread = std::thread(&PacketCapture::listenDevice, &_packetCaptureDev, std::ref(selectedDevice));
    _running = true;

    _startButton->Disable();
    _stopButton->Enable();

    clearList();
    _captureThread = std::thread(&PacketCapturePanel::PacketProcessingLoop, this);
}


void PacketCapturePanel::OnStopCapture(wxCommandEvent& event)
{
    _running = false;
    this->_packetCaptureDev.halt();
    if (_captureThread.joinable()) {
        _captureThread.join();
    }
    if (this->_listeningThread.joinable())
    {
        this->_listeningThread.join();
    }

    _startButton->Enable();
    _stopButton->Disable();
}

void PacketCapturePanel::OnClear(wxCommandEvent& event)
{
    clearList();
    event.Skip();
}

void PacketCapturePanel::PacketProcessingLoop()
{
    while (_running) {
        Packet* pkt = _packetCaptureDev.getPacket();
        if (pkt) {
            // Send event to GUI thread
            wxThreadEvent* newEvent = new wxThreadEvent(EVT_NEW_PACKET);
            newEvent->SetPayload(pkt);  // Store the packet pointer safely
            wxQueueEvent(this, newEvent);

        }
    }
}

void PacketCapturePanel::OnNewPacket(wxThreadEvent& event) {
    this->resizeColumns();
    Packet* pkt = (Packet*)event.GetPayload<Packet*>();

    std::lock_guard<std::mutex> lock(this->_listMutex);

    long itemIndex = _packetList->InsertItem(_packetList->GetItemCount(), std::to_string(pkt->getTimeStamp()));
    _packetList->SetItem(itemIndex, 1, pkt->getSrc());
    _packetList->SetItem(itemIndex, 2, pkt->getDst());
    _packetList->SetItem(itemIndex, 3, pkt->getProtocol());
    _packetList->SetItem(itemIndex, 4, std::to_string(pkt->getPacketSize()));
    _packetList->SetItem(itemIndex, 5, pkt->getInfo());
    RGBColour colour = pkt->getColour();
    _packetList->SetItemBackgroundColour(itemIndex, wxColour(colour.R, colour.G, colour.B, 200));
    _packetList->SetItemPtrData(itemIndex, (wxUIntPtr)pkt);
    _packetList->EnsureVisible(itemIndex);

}

void PacketCapturePanel::OnListItemSelected(wxListEvent& event)
{
    Packet* pkt = (Packet*)(event.GetItem().GetData());

    if (pkt) {
        // Convert hex view to wxString with proper newlines
        const wxString hexViewStr = wxString::FromUTF8(pkt->payloadHexView());

        // Create a wxDialog with a reasonable default size and resizable border
        wxDialog* dlg = new wxDialog(this, wxID_ANY, "Packet Hex View",
            wxDefaultPosition, wxSize(800, 600),
            wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);

        wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

        // Create a wxTextCtrl that expands properly
        wxTextCtrl* textCtrl = new wxTextCtrl(dlg, wxID_ANY, hexViewStr,
            wxDefaultPosition, wxSize(780, 580),
            wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP | wxHSCROLL | wxVSCROLL);

        // Set a monospaced font with a larger size
        wxFont font(12, wxFONTFAMILY_TELETYPE, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);
        textCtrl->SetFont(font);

        sizer->Add(textCtrl, 1, wxEXPAND | wxALL, 10);
        dlg->SetSizer(sizer);

        dlg->Show();
    }
}

void PacketCapturePanel::resizeColumns()
{

    int width = _packetList->GetClientSize().GetWidth();
    if (width > 0) {
        _packetList->SetColumnWidth(0, width * 0.15);
        _packetList->SetColumnWidth(1, width * 0.20); 
        _packetList->SetColumnWidth(2, width * 0.20); 
        _packetList->SetColumnWidth(3, width * 0.15); 
        _packetList->SetColumnWidth(4, width * 0.10); 
        _packetList->SetColumnWidth(5, width * 0.20); 
    }
    
}

void PacketCapturePanel::OnResize(wxSizeEvent& event)
{
    this->resizeColumns();
    event.Skip();
}

void PacketCapturePanel::OnMaximize(wxMaximizeEvent& event)
{
    this->resizeColumns();
    event.Skip();
}

void PacketCapturePanel::OnMinimize(wxIconizeEvent& event)
{
    this->resizeColumns();
    event.Skip();
}





