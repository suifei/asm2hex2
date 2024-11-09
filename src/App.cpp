#include "App.hpp"
#include <wx/image.h>

bool App::OnInit()
{
    wxImage::AddHandler(new wxPNGHandler());
    // wxImage::AddHandler(new wxJPEGHandler()); // 支持JPEG
    // wxImage::AddHandler(new wxGIFHandler());  // 支持GIF
    MainWindow *window = new MainWindow();
    window->Show(true);
    return true;
}