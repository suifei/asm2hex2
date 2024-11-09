// Resources.hpp
#ifndef RESOURCES_HPP
#define RESOURCES_HPP

#include <wx/wx.h>
#include <wx/mstream.h>
#include <wx/log.h>

namespace Resources
{
extern unsigned char logo_png[];
extern unsigned int logo_png_len;
extern unsigned char capstone_png[];
extern unsigned int capstone_png_len;
extern unsigned char keystone_png[];
extern unsigned int keystone_png_len;
extern unsigned char wxwidgets_png[];
extern unsigned int wxwidgets_png_len;

// 修改图片加载函数，临时禁用日志
inline wxBitmap CreateBitmapFromMemory(const unsigned char *data, size_t len)
{
    // 暂时禁用日志
    wxLogNull logNo; // 这个对象存在期间会禁用所有日志输出

    wxMemoryInputStream mis(data, len);
    wxImage image(mis, wxBITMAP_TYPE_PNG);
    return wxBitmap(image);
}

// 使用新的辅助函数
inline wxBitmap CreateLogoFromMemory()
{
    return CreateBitmapFromMemory(logo_png, size_t(logo_png_len));
}

inline wxBitmap CreateCapstoneFromMemory()
{
    return CreateBitmapFromMemory(capstone_png, size_t(capstone_png_len));
}

inline wxBitmap CreateKeystoneFromMemory()
{
    return CreateBitmapFromMemory(keystone_png, size_t(keystone_png_len));
}

inline wxBitmap CreateWxWidgetsFromMemory()
{
    return CreateBitmapFromMemory(wxwidgets_png, size_t(wxwidgets_png_len));
}

} // namespace Resources

#endif // RESOURCES_HPP