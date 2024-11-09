#ifndef APP_HPP
#define APP_HPP

#include <wx/wx.h>
#include "MainWindow.hpp"

class App : public wxApp {
public:
    virtual bool OnInit();
};

wxIMPLEMENT_APP(App);

#endif // APP_HPP