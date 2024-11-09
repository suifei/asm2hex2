#include "AboutDialog.hpp"
#include "Resources.hpp"
#include <wx/notebook.h>
#include <wx/statline.h>
#include <wx/hyperlink.h>
#include <wx/grid.h>
#include <keystone/keystone.h>
#include <capstone/capstone.h>

AboutDialog::AboutDialog(wxWindow *parent)
    : wxDialog(parent, wxID_ANY, "About", wxDefaultPosition, wxSize(500, 600), wxDEFAULT_DIALOG_STYLE )
{
    CreateControls();
    CenterOnParent();
}

void AboutDialog::CreateControls()
{
    wxBoxSizer *mainSizer = new wxBoxSizer(wxVERTICAL);

    // Logo and basic info at top
    wxBoxSizer *topSizer = new wxBoxSizer(wxHORIZONTAL);

    // TODO: Add logo if available
    wxBitmap logoBitmap = Resources::CreateLogoFromMemory();
    wxImage logoImg = logoBitmap.ConvertToImage();
    logoBitmap = wxBitmap(logoImg.Scale(148, 148, wxIMAGE_QUALITY_HIGH));

    topSizer->Add(new wxStaticBitmap(this, wxID_ANY, logoBitmap), 0, wxALL, 5);

    wxBoxSizer *infoSizer = new wxBoxSizer(wxVERTICAL);
    infoSizer->Add(new wxStaticText(this, wxID_ANY, "ASM to HEX Converter"), 0, wxALL, 5);
    infoSizer->Add(new wxStaticText(this, wxID_ANY, "Version: 1.0.0"), 0, wxALL, 5);
    infoSizer->Add(new wxStaticText(this, wxID_ANY, "Author: suifei <suifei@gmail.com>"), 0, wxALL, 5);
    infoSizer->Add(new wxStaticText(this, wxID_ANY, "License: MIT"), 0, wxALL, 5);
    infoSizer->Add(new wxHyperlinkCtrl(this, ID_LINK_GITHUB, "GitHub Repository", "https://github.com/suifei/asm2hex"),
                   0, wxALL, 5);

    topSizer->Add(infoSizer, 1, wxEXPAND | wxALL, 5);

    mainSizer->Add(topSizer, 0, wxEXPAND | wxALL, 5);

    mainSizer->Add(new wxStaticLine(this, wxID_ANY), 0, wxEXPAND | wxALL, 5);

    // Notebook for different sections
    wxNotebook *notebook = new wxNotebook(this, wxID_ANY);
    notebook->AddPage(CreateGeneralPage(notebook), "General", true);
    notebook->AddPage(CreateCapstoneArchPage(notebook), "Capstone", false);
    notebook->AddPage(CreateKeystoneArchPage(notebook), "Keystone", false);

    mainSizer->Add(notebook, 1, wxEXPAND | wxALL, 5);

    // Bottom buttons
    wxStdDialogButtonSizer *buttonSizer = new wxStdDialogButtonSizer();
    buttonSizer->AddButton(new wxButton(this, wxID_OK, "OK"));
    buttonSizer->Realize();
    mainSizer->Add(buttonSizer, 0, wxALIGN_CENTER | wxALL, 5);

    SetSizer(mainSizer);
}
wxPanel *AboutDialog::CreateGeneralPage(wxNotebook *notebook)
{
    wxPanel *panel = new wxPanel(notebook);
    wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);

    // 创建一个水平sizer来放置Capstone和Keystone的图标和链接
    wxBoxSizer *libSizer = new wxBoxSizer(wxHORIZONTAL);

    // Capstone部分
    wxBoxSizer *capstoneSizer = new wxBoxSizer(wxVERTICAL);
    wxBitmap capstoneBmp = Resources::CreateCapstoneFromMemory();
    wxImage capstoneImg = capstoneBmp.ConvertToImage();
    capstoneBmp = wxBitmap(capstoneImg.Scale(64, 64, wxIMAGE_QUALITY_HIGH));

    capstoneSizer->Add(new wxStaticBitmap(panel, wxID_ANY, capstoneBmp), 0, wxALIGN_CENTER | wxALL, 5);
    capstoneSizer->Add(new wxHyperlinkCtrl(panel, wxID_ANY, "Capstone", "https://www.capstone-engine.org"), 0,
                       wxALIGN_CENTER | wxBOTTOM, 5);
    libSizer->Add(capstoneSizer, 0, wxALIGN_CENTER | wxALL, 10);

    // Keystone部分
    wxBoxSizer *keystoneSizer = new wxBoxSizer(wxVERTICAL);
    wxBitmap keystoneBmp = Resources::CreateKeystoneFromMemory();
    wxImage keystoneImg = keystoneBmp.ConvertToImage();
    keystoneBmp = wxBitmap(keystoneImg.Scale(64, 64, wxIMAGE_QUALITY_HIGH));

    keystoneSizer->Add(new wxStaticBitmap(panel, wxID_ANY, keystoneBmp), 0, wxALIGN_CENTER | wxALL, 5);
    keystoneSizer->Add(new wxHyperlinkCtrl(panel, wxID_ANY, "Keystone", "https://www.keystone-engine.org"), 0,
                       wxALIGN_CENTER | wxBOTTOM, 5);
    libSizer->Add(keystoneSizer, 0, wxALIGN_CENTER | wxALL, 10);

    // wxWidgets
    wxBoxSizer *wxWidgetsSizer = new wxBoxSizer(wxVERTICAL);
    wxBitmap wxWidgetsBmp = Resources::CreateWxWidgetsFromMemory();
    wxImage wxWidgetsImg = wxWidgetsBmp.ConvertToImage();
    wxWidgetsBmp = wxBitmap(wxWidgetsImg.Scale(271, 64, wxIMAGE_QUALITY_HIGH));

    wxWidgetsSizer->Add(new wxStaticBitmap(panel, wxID_ANY, wxWidgetsBmp), 0, wxALIGN_CENTER | wxALL, 5);
    wxWidgetsSizer->Add(new wxHyperlinkCtrl(panel, wxID_ANY, "wxWidgets", "https://wxwidgets.org/"), 0,
                       wxALIGN_CENTER | wxBOTTOM, 5);
    libSizer->Add(wxWidgetsSizer, 0, wxALIGN_CENTER | wxALL, 10);

    sizer->Add(libSizer, 0, wxALIGN_CENTER | wxALL, 5);

    // 添加感谢清单
    wxString credits = "Special Thanks To:\n\n"
                       "• Capstone Engine - The Ultimate Disassembler\n"
                       "• Keystone Engine - The Ultimate Assembler\n"
                       "• wxWidgets - Cross-Platform GUI Library\n"
                       "• All contributors and supporters";

    wxStaticText *creditsText = new wxStaticText(panel, wxID_ANY, credits);
    sizer->Add(creditsText, 0, wxALIGN_CENTER | wxALL, 10);

    // 只添加一个分隔线
    sizer->Add(new wxStaticLine(panel, wxID_ANY), 0, wxALL | wxLEFT | wxRIGHT, 5);

    // 版本信息，直接跟在分隔线后面
    wxString info =
        wxString::Format("Built with:\n"
                         "wxWidgets %s\n"
                         "Keystone v%d.%d\n"
                         "Capstone v%d.%d\n\n"
                         "Copyright (c) 2024 suifei",
                         wxVERSION_STRING, KS_VERSION_MAJOR, KS_VERSION_MINOR, CS_VERSION_MAJOR, CS_VERSION_MINOR);

    sizer->Add(new wxStaticText(panel, wxID_ANY, info), 0, wxALIGN_CENTER | wxALL, 5); // 减小间距

    // 设置背景色为白色
    panel->SetBackgroundColour(*wxWHITE);
    panel->SetSizer(sizer);
    return panel;
}

wxPanel *AboutDialog::CreateCapstoneArchPage(wxNotebook *notebook)
{
    wxPanel *panel = new wxPanel(notebook);
    wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);

    wxGrid *grid = new wxGrid(panel, wxID_ANY);
    grid->CreateGrid(12, 2);

    grid->SetColLabelValue(0, "Architecture");
    grid->SetColLabelValue(1, "Supported");

    struct ArchInfo
    {
        const char *name;
        cs_arch arch; // 修改为cs_arch类型
    };

    ArchInfo archs[] = {
        {"ARM", CS_ARCH_ARM},   {"ARM64", CS_ARCH_ARM64},           {"MIPS", CS_ARCH_MIPS}, {"X86", CS_ARCH_X86},
        {"PPC", CS_ARCH_PPC},   {"SPARC", CS_ARCH_SPARC},           {"SYSZ", CS_ARCH_SYSZ}, {"XCORE", CS_ARCH_XCORE},
        {"M68K", CS_ARCH_M68K}, {"TMS320C64X", CS_ARCH_TMS320C64X}, {"BPF", CS_ARCH_BPF},   {"RISCV", CS_ARCH_RISCV}};

    for (int i = 0; i < 12; i++)
    {
        grid->SetCellValue(i, 0, archs[i].name);
        grid->SetCellValue(i, 1, cs_support(archs[i].arch) ? "Yes" : "No");
        grid->SetReadOnly(i, 0, true);
        grid->SetReadOnly(i, 1, true);
    }

    grid->AutoSizeColumns();

    sizer->Add(grid, 1, wxEXPAND | wxALL, 10);
    panel->SetSizer(sizer);
    return panel;
}

wxPanel *AboutDialog::CreateKeystoneArchPage(wxNotebook *notebook)
{
    wxPanel *panel = new wxPanel(notebook);
    wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);

    wxGrid *grid = new wxGrid(panel, wxID_ANY);
    grid->CreateGrid(9, 2);

    grid->SetColLabelValue(0, "Architecture");
    grid->SetColLabelValue(1, "Supported");

    struct ArchInfo
    {
        const char *name;
        ks_arch arch; // 修改为ks_arch类型
    };

    ArchInfo archs[] = {{"ARM", KS_ARCH_ARM},         {"ARM64", KS_ARCH_ARM64},     {"MIPS", KS_ARCH_MIPS},
                        {"X86", KS_ARCH_X86},         {"PPC", KS_ARCH_PPC},         {"SPARC", KS_ARCH_SPARC},
                        {"HEXAGON", KS_ARCH_HEXAGON}, {"SYSTEMZ", KS_ARCH_SYSTEMZ}, {"EVM", KS_ARCH_EVM}};

    for (int i = 0; i < 9; i++)
    {
        grid->SetCellValue(i, 0, archs[i].name);
        grid->SetCellValue(i, 1, ks_arch_supported(archs[i].arch) ? "Yes" : "No");
        grid->SetReadOnly(i, 0, true);
        grid->SetReadOnly(i, 1, true);
    }

    grid->AutoSizeColumns();

    sizer->Add(grid, 1, wxEXPAND | wxALL, 10);
    panel->SetSizer(sizer);
    return panel;
}

void AboutDialog::OnLinkClicked(wxCommandEvent &event)
{
    wxLaunchDefaultBrowser("https://github.com/suifei/asm2hex");
}