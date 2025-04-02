#include "PortProxyPanel.h"




PortProxyPanel::PortProxyPanel(wxWindow* parent) : wxPanel(parent, wxID_ANY, wxDefaultPosition, wxSize(-1, 100)), _running(false), _proxyServer(nullptr) {
    wxBoxSizer* vbox = new wxBoxSizer(wxVERTICAL);

    wxArrayString choices;
    choices.Add("Custom Port");
    choices.Add("HTTP (80)");
    choices.Add("HTTPS (443)");
    _proxyChoice = new wxChoice(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, choices);
    _proxyChoice->SetSelection(0);

    _portInput = new wxTextCtrl(this, wxID_ANY, "", wxDefaultPosition, wxDefaultSize);

    _startBtn = new wxButton(this, wxID_ANY, "Start Proxy");
    _stopBtn = new wxButton(this, wxID_ANY, "Stop Proxy");
    _interceptToggleBtn = new wxButton(this, wxID_ANY, "Intercept");

    _interceptToggleBtn->SetBackgroundColour(wxColour("red"));
    _interceptToggleBtn->Disable();
    _stopBtn->Disable();

    _listCtrl = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxSize(480, 300), wxLC_REPORT);

    _listCtrl->SetBackgroundColour(wxColour(30, 30, 30));

    _listCtrl->InsertColumn(0, "Requests", wxLIST_FORMAT_LEFT, 450);

    vbox->Add(_proxyChoice, 0, wxEXPAND | wxALL, 5);
    vbox->Add(_portInput, 0, wxEXPAND | wxALL, 5);
    vbox->Add(_startBtn, 0, wxEXPAND | wxALL, 5);
    vbox->Add(_stopBtn, 0, wxEXPAND | wxALL, 5);
    vbox->Add(_interceptToggleBtn, 0, wxEXPAND | wxALL, 5);
    vbox->Add(_listCtrl, 1, wxEXPAND | wxALL, 5);

    SetSizer(vbox);

    _startBtn->Bind(wxEVT_BUTTON, &PortProxyPanel::OnStart, this);
    _stopBtn->Bind(wxEVT_BUTTON, &PortProxyPanel::OnStop, this);
    _proxyChoice->Bind(wxEVT_CHOICE, &PortProxyPanel::OnProxyChoice, this);
    _interceptToggleBtn->Bind(wxEVT_BUTTON, &PortProxyPanel::OnInterceptToggle, this);
    Bind(EVT_NEW_APPDATA, &PortProxyPanel::OnNewRequest, this);

    _listCtrl->Bind(wxEVT_LIST_ITEM_SELECTED, &PortProxyPanel::OnListItemSelected, this);


}



PortProxyPanel::~PortProxyPanel()
{
    clearList();
    StopProxyThread();
    if(_proxyServer)
        delete _proxyServer;
}


void PortProxyPanel::OnStart(wxCommandEvent&)
{
    int port = 0;
    if (_proxyChoice->GetSelection() == 1) {
        port = 80;
    }
    else if (_proxyChoice->GetSelection() == 2) {
        port = 443;
    }
    else {
        long enteredPort;
        if (!_portInput->GetValue().ToLong(&enteredPort) || enteredPort < 0 || enteredPort > 65535) {
            wxMessageBox("Invalid port number!", "Error", wxICON_ERROR);
            return;
        }
        port = static_cast<int>(enteredPort);
    }


    clearList();
    delete _proxyServer;
    ProxyServer::closeIntercept();
    _proxyServer = new ProxyServer(port);

    _startBtn->Disable();
    _stopBtn->Enable();
    setInterceptGui(false);
    _interceptToggleBtn->Enable();
    
    _running = true;
    _proxyStartThread = std::thread(&ProxyServer::startProxy, _proxyServer);
    _proxyThread = std::thread(&PortProxyPanel::ProxyLoop, this);
}

void PortProxyPanel::OnInterceptToggle(wxCommandEvent&)
{
    setInterceptGui(!(this->_intercept));

    ProxyServer::toggleIntercept();
}



void PortProxyPanel::OnNewRequest(wxThreadEvent& event)
{
    std::lock_guard<std::mutex> lock(this->_listLock);
    ApplicationData* data = event.GetPayload<ApplicationData*>();
    std::string infoText = "";
    if (data->getDataType() == HTTP_APPLICATION_DATA)
    {
        infoText = ((HTTPApplicationData*)data)->getData().getHost() + " HTTP " + ((HTTPApplicationData*)data)->getData().getMethod();
    }
    else
    {
        infoText = "General Packet";
    }

    if (data->intercepted())
    {
        infoText += " INTERCEPTED!";
    }

    long index = _listCtrl->InsertItem(_listCtrl->GetItemCount(), infoText);

    _listCtrl->SetItemPtrData(index, (wxUIntPtr)data);

    _listCtrl->SetItemTextColour(index, *wxWHITE); 

    if (data->getDirection() == TO_CLIENT)
    {
        _listCtrl->SetItemBackgroundColour(index, wxColour(255, 140, 0));
    }
    else if (data->getDirection() == TO_SERVER)
    {
        _listCtrl->SetItemBackgroundColour(index, wxColour(0, 102, 204));
    }
    if (data->intercepted())
    {
        _listCtrl->SetItemBackgroundColour(index, wxColour(255, 99, 71));
    }

    wxFont font(12, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD);
    _listCtrl->SetItemFont(index, font);

    _listCtrl->Refresh();
}

void PortProxyPanel::OnProxyChoice(wxCommandEvent&)
{
    _portInput->Enable(_proxyChoice->GetSelection() == 0);
}






void PortProxyPanel::OnStop(wxCommandEvent&)
{
    StopProxyThread();
}



void PortProxyPanel::setInterceptGui(bool value)
{
    if (value)
    {
        this->_interceptToggleBtn->SetBackgroundColour(wxColour("green"));
    }
    else
    {
        this->_interceptToggleBtn->SetBackgroundColour(wxColour("red"));
    }
    this->_intercept = value;
}

void PortProxyPanel::OnListItemSelected(wxListEvent& event)
{
    ApplicationData* appData = (ApplicationData*)(event.GetItem().GetData());
    
    if (appData) {
        auto dataType = appData->getDataType();
        std::string data = "";
        if (dataType == HTTP_APPLICATION_DATA)
        {
            HTTPRequest& httpData = ((HTTPApplicationData*)appData)->getData();
            data = httpData.fullRequest();
        }
        else if (dataType == GENERAL_APPLICATION_DATA)
        {
            data = appData->getRawData();
        }

        

        
        if (appData->intercepted() && appData->forwardData())
        {
            EditRequestDialog editDialog(this, appData, event.GetIndex());
            editDialog.ShowModal();
            editDialog.Destroy();
        }
        else
        {
            bool overFlow = false;
            if (data.size() > 65536)
            {
                data.resize(65536);
                overFlow = true;
            }
            wxString result;
            for (unsigned char c : data) {
                if (wxIsprint(c) || c == '\t' || c == '\n' || c == '\r') {
                    result += wxString::FromUTF8((const char*)&c, 1);
                }
                else {
                    result += wxString::Format("\\x%02X", c);
                }
            }
            if (overFlow)
            {
                result += "\n\nCONTENT TOO BIG, ONLY SHOWING 64kb";
            }

            wxDialog* dlg = new wxDialog(this, wxID_ANY, "Proxy Application Data",
                wxDefaultPosition, wxSize(800, 600),
                wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);

            wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
            wxTextCtrl* textCtrl = new wxTextCtrl(dlg, wxID_ANY, result,
                wxDefaultPosition, wxSize(780, 580),
                wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP | wxHSCROLL | wxVSCROLL);

            wxFont font(12, wxFONTFAMILY_TELETYPE, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);
            textCtrl->SetFont(font);

            sizer->Add(textCtrl, 1, wxEXPAND | wxALL, 10);
            dlg->SetSizer(sizer);

            dlg->ShowModal();
            dlg->Destroy();
        }
    }
}


void PortProxyPanel::clearList()
{
    std::lock_guard<std::mutex> lock(this->_listLock);
    long item = 0;
    long itemCount = this->_listCtrl->GetItemCount();
    while (item < itemCount)
    {
        ApplicationData* data = (ApplicationData*)(this->_listCtrl->GetItemData(item));
        if (data)
            delete data;
        item++;

    }
    this->_listCtrl->DeleteAllItems();
}


void PortProxyPanel::StopProxyThread()
{
    if (_running) {
        _running = false;
        ProxyServer::halt();
        _proxyServer->stopProxy();
        if (_proxyThread.joinable()) {
            _proxyThread.join();
        }
        if (_proxyStartThread.joinable()) {
            _proxyStartThread.join();
        }
    }
    _interceptToggleBtn->Disable();
    _startBtn->Enable();
    _stopBtn->Disable();

    delete _proxyServer;
    _proxyServer = nullptr;
}


void PortProxyPanel::ProxyLoop()
{
    while (_running) {
        ApplicationData* appData = ProxyServer::pullAppData();

        if (appData)
        {
            wxThreadEvent* newEvent = new wxThreadEvent(EVT_NEW_APPDATA);
            newEvent->SetPayload(appData);  // Store the packet pointer safely
            wxQueueEvent(this, newEvent);

        }
    }
}

bytes EditRequestDialog::rawHexToBytes(const std::string& rawHex)
{
    bytes output;
    if (rawHex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string length must be even.");
    }

    for (size_t i = 0; i < rawHex.length(); i += 2) {
        if (!std::isxdigit(rawHex[i]) || !std::isxdigit(rawHex[i + 1])) {
            throw std::invalid_argument("Hex string contains non-hex characters at position " + std::to_string(i));
        }

        const std::string byteString = rawHex.substr(i, 2);

        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        output.push_back(byte);
    }

    return output;
}


void EditRequestDialog::OnSaveRequest(wxCommandEvent& event)
{

    if (this->_appData->getDataType() == HTTP_APPLICATION_DATA)
    {
        std::string newValue = this->_editText->GetValue().ToStdString();
        ((HTTPApplicationData*)this->_appData)->setRequest(newValue);
    }
    else if (this->_appData->getDataType() == GENERAL_APPLICATION_DATA)
    {
        try
        {
            if (pureText)//if its a pure text protocol, we can just view it as text, and it would be saved as text
            {
                bytes rawText = this->_editText->GetValue().ToStdString();
                ((GeneralData*)this->_appData)->setData(rawText);
            }
            else
            {
                std::string rawHex = this->_editText->GetValue().ToStdString();
                bytes rawNewValue = this->rawHexToBytes(rawHex);
                ((GeneralData*)this->_appData)->setData(rawNewValue);
            }
        }
        catch (const std::exception& e)
        {
            wxMessageBox(e.what(), "Error", wxOK | wxICON_ERROR, this);
        }
    }
}

void EditRequestDialog::OnBlockRequest(wxCommandEvent& event)
{
    this->_appData->block();
    std::lock_guard<std::mutex> lock(_parent->_listLock);
    _parent->_listCtrl->SetItemBackgroundColour(this->_itemId, wxColour("red"));
    wxString itemText = _parent->_listCtrl->GetItemText(this->_itemId);
    itemText = "[" + itemText + "] BLOCKED!";
    _parent->_listCtrl->SetItemText(this->_itemId, itemText);
    EndModal(wxID_OK);
}

void EditRequestDialog::OnForwardRequest(wxCommandEvent& event)
{
    this->OnSaveRequest(event);
    std::lock_guard<std::mutex> lock(_parent->_listLock);
    _parent->_listCtrl->SetItemBackgroundColour(this->_itemId, wxColour("green"));
    wxString itemText = _parent->_listCtrl->GetItemText(this->_itemId);
    itemText = "[" + itemText + "] FORWARDED!";
    _parent->_listCtrl->SetItemText(this->_itemId, itemText);
    ProxyServer::forwardAppData(this->_appData);
    EndModal(wxID_OK);
}
