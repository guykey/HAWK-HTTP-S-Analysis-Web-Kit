#pragma once

#include <wx/wx.h>
#include <wx/listctrl.h>

#include "../HAWK_WIRESHARK/PacketCapture.h"

const wxColour CAPTURE_COLOUR = wxColour(0x2b, 0x2b, 0x2b);


wxDEFINE_EVENT(EVT_NEW_PACKET, wxThreadEvent);


class PacketCapturePanel : public wxPanel
{
public:
	PacketCapturePanel(wxWindow* parent);

	~PacketCapturePanel();

protected:
	PacketCapture _packetCaptureDev;

	wxChoice* _deviceChoice;
	wxButton* _startButton;
	wxButton* _clearButton;
	wxButton* _stopButton;
	wxListCtrl* _packetList;




	std::thread _captureThread;
	std::thread _listeningThread;
	std::atomic<bool> _running;

	std::mutex _listMutex;

	void clearList();


    void OnStartCapture(wxCommandEvent& event);

    void OnStopCapture(wxCommandEvent& event);
	void OnClear(wxCommandEvent& event);

    void PacketProcessingLoop();


    void OnNewPacket(wxThreadEvent& event);


	void OnListItemSelected(wxListEvent& event);


	void resizeColumns();
	void OnResize(wxSizeEvent& event);


	void OnMaximize(wxMaximizeEvent& event);
	void OnMinimize(wxIconizeEvent& event);
	


	
};

