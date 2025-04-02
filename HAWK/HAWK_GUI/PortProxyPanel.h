#pragma once

#include <wx/wx.h>
#include <wx/listctrl.h>
#include <wx/stc/stc.h>
#include <wx/choice.h>
#include <wx/textctrl.h>
#include <thread>
#include <atomic>
#include <mutex>
#include "../HAWK_PROXY_SERVER/ProxyServer.hpp"



class PortProxyPanel;
class EditRequestDialog : public wxDialog
{
public:
    EditRequestDialog(PortProxyPanel* parent, ApplicationData* appData, long itemId)
        : wxDialog((wxPanel*)parent, wxID_ANY, "Edit Application Data", wxDefaultPosition, wxSize(800, 600), wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER | wxMAXIMIZE_BOX),
        _parent(parent), _appData(appData), _itemId(itemId)
    {
        bytes data;
        wxString result;

        if (_appData->getDataType() == HTTP_APPLICATION_DATA)
        {
            data = ((HTTPApplicationData*)appData)->getData().fullRequest();
            for (unsigned char c : data) {
                if (wxIsprint(c) || wxIsspace(c)) {
                    result += wxString::FromUTF8((const char*)&c, 1);
                }
                else {
                    result += wxString::Format("\\x%02X", c);
                }
            }
        }
        else if (_appData->getDataType() == GENERAL_APPLICATION_DATA)
        {
            data = _appData->getRawData();
            for (byte b : data)
            {
                if (!wxIsprint(b) && !wxIsspace(b))
                    pureText = false;

                result += wxString::Format("%02X", b);
            }
            if (pureText)
            {
                result = wxString::FromUTF8(data);
            }
        }






        wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

        _editText = new wxStyledTextCtrl(this, wxID_ANY,
            wxDefaultPosition, wxSize(-1, 200));

        wxFont font(12, wxFONTFAMILY_TELETYPE, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);
        _editText->SetFont(font);

        _editText->SetWrapMode(wxSTC_WRAP_NONE);  // Don't wrap text, so line breaks are preserved
        _editText->StyleClearAll();  // Clear any previous styles
        _editText->SetText(result);
        

        sizer->Add(_editText, 1, wxEXPAND | wxALL, 10);

        wxBoxSizer* hbox = new wxBoxSizer(wxHORIZONTAL);
        wxButton* saveBtn = new wxButton(this, wxID_SAVE, "SAVE");
        saveBtn->SetForegroundColour(*wxWHITE);
        saveBtn->SetBackgroundColour(wxColour(128, 0, 128));
        wxButton* blockBtn = new wxButton(this, wxID_CANCEL, "BLOCK");
        blockBtn->SetForegroundColour(*wxWHITE);
        blockBtn->SetBackgroundColour(wxColour(255, 0, 0));
        wxButton* forwardBtn = new wxButton(this, wxID_FORWARD, "FORWARD");
        forwardBtn->SetForegroundColour(*wxWHITE);
        forwardBtn->SetBackgroundColour(wxColour(0, 128, 0));
        hbox->Add(saveBtn, 1, wxALL | wxEXPAND, 5);
        hbox->Add(blockBtn, 1, wxALL | wxEXPAND, 5);
        hbox->Add(forwardBtn, 1, wxALL | wxEXPAND, 5);
        sizer->Add(hbox, 0, wxALIGN_CENTER_HORIZONTAL | wxBOTTOM, 10);
        this->SetSizer(sizer);

        saveBtn->Bind(wxEVT_BUTTON, &EditRequestDialog::OnSaveRequest, this);
        blockBtn->Bind(wxEVT_BUTTON, &EditRequestDialog::OnBlockRequest, this);
        forwardBtn->Bind(wxEVT_BUTTON, &EditRequestDialog::OnForwardRequest, this);
        
    };
private:
    //const pointer
    //not pointer to const
    PortProxyPanel* const _parent;
    ApplicationData* _appData;
    wxStyledTextCtrl* _editText;
    const long _itemId;

    bool pureText = true;

    static bytes rawHexToBytes(const std::string& rawHex);

    void OnSaveRequest(wxCommandEvent&);
    void OnBlockRequest(wxCommandEvent&);
    void OnForwardRequest(wxCommandEvent&);

};




wxDEFINE_EVENT(EVT_NEW_APPDATA, wxThreadEvent);

const wxColour PROXY_COLOUR = *wxRED;

class PortProxyPanel : public wxPanel
{
    friend class EditRequestDialog;

public:
    PortProxyPanel(wxWindow* parent);

    ~PortProxyPanel();

private:
    wxChoice* _proxyChoice;
    wxTextCtrl* _portInput;
    wxButton* _startBtn;
    wxButton* _stopBtn;
    wxButton* _interceptToggleBtn;
    wxListCtrl* _listCtrl;
    std::thread _proxyThread;
    std::thread _proxyStartThread;
    std::atomic<bool> _running;
    ProxyServer* _proxyServer;

    bool _intercept = false;


    std::mutex _listLock;

    void clearList();


    void setInterceptGui(bool value);
    void OnInterceptToggle(wxCommandEvent&);
    void OnStart(wxCommandEvent&);

    void OnStop(wxCommandEvent&);

    void StopProxyThread();

    void ProxyLoop();

    void OnNewRequest(wxThreadEvent& event);

    void OnProxyChoice(wxCommandEvent&);

    void OnListItemSelected(wxListEvent& event);



};