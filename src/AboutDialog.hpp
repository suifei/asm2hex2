#ifndef ABOUT_DIALOG_HPP
#define ABOUT_DIALOG_HPP

#include <wx/wx.h>
#include <wx/notebook.h>

class AboutDialog : public wxDialog
{
public:
    AboutDialog(wxWindow* parent);

private:
    void CreateControls();
    wxPanel* CreateGeneralPage(wxNotebook* notebook);
    wxPanel* CreateCapstoneArchPage(wxNotebook* notebook);
    wxPanel* CreateKeystoneArchPage(wxNotebook* notebook);
    
    void OnLinkClicked(wxCommandEvent& event);
};

enum {
    ID_LINK_GITHUB = wxID_HIGHEST + 1000
};

#endif // ABOUT_DIALOG_HPP