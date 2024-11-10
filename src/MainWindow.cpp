#include "MainWindow.hpp"

wxColour csColor(128, 0, 0, 80);         // 蓝色
wxColour ksColor(0, 0, 255, 80);         // 红色
wxColour convertBtnColor(0, 255, 0, 80); // 绿色
wxColour clearBtnColor(128, 0, 0, 80);   // 红色
wxColour aboutBtnColor(255, 0, 255, 80); // 紫色
wxColour blackColor(0, 0, 0, 80);        // 黑色
wxColour whiteColor(255, 255, 255, 80);  // 白色

wxBEGIN_EVENT_TABLE(MainWindow, wxFrame) EVT_BUTTON(ID_CONVERT_BUTTON, MainWindow::OnConvert)
    EVT_BUTTON(ID_CLEAR_BUTTON, MainWindow::OnClear) EVT_BUTTON(ID_TOGGLE_MODE_BUTTON, MainWindow::OnToggleMode)
        EVT_BUTTON(ID_ABOUT_BUTTON, MainWindow::OnAbout) EVT_CHOICE(ID_ARCH_CHOICE, MainWindow::OnArchChanged)
            EVT_CHOICE(ID_MODE_CHOICE, MainWindow::OnModeChanged)
                EVT_CHECKBOX(ID_HEX_CHECKBOX, MainWindow::OnHexChecked)
                    EVT_SPLITTER_SASH_POS_CHANGED(wxID_ANY, MainWindow::OnSplitterSashPosChanged)
                        wxEND_EVENT_TABLE()

                            MainWindow::MainWindow()
    : wxFrame(nullptr, wxID_ANY, "Assembly/Hex Converter", wxDefaultPosition, wxDefaultSize), // 使用 wxDefaultSize
      m_isAsmToHexMode(true),
      lastSelectedArch("arm64")
{

    InitializeComponents();

    UpdateStatusBar("Ready");
}

void MainWindow::InitializeComponents()
{

    // 获取屏幕大小
    wxDisplay display(wxDisplay::GetFromWindow(this));
    wxRect screenRect = display.GetGeometry();

    // 计算合理的窗口大小（例如屏幕的70%）
    int width = (int)(screenRect.GetWidth() * 0.7);
    int height = (int)(screenRect.GetHeight() * 0.7);

    // 设置最小尺寸（可以是固定值或基于屏幕比例）
    SetMinSize(wxSize(800, 600));

    {
        wxWindowUpdateLocker lockUpdates(this);
        m_isAsmToHexMode = true;

        wxPanel *panel = new wxPanel(this);
        wxBoxSizer *mainSizer = new wxBoxSizer(wxVERTICAL);

        // 顶部布局：包含logo和标题
        wxBoxSizer *headerSizer = new wxBoxSizer(wxHORIZONTAL);

        // Logo部分
        wxBitmap logoBitmap = Resources::CreateLogoFromMemory();
        // 将logo缩放到48x48
        wxImage img = logoBitmap.ConvertToImage();
        logoBitmap = wxBitmap(img.Scale(48, 48, wxIMAGE_QUALITY_HIGH));
        wxStaticBitmap *logo = new wxStaticBitmap(panel, wxID_ANY, logoBitmap);
        headerSizer->Add(logo, 0, wxALIGN_CENTER_VERTICAL | wxALL, 5);

        // 标题文本
        wxFont titleFont(18, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD, false, "Verdana");

        m_titleText = new wxStaticText(panel, wxID_ANY, m_isAsmToHexMode ? KS_TITLE : CS_TITLE);
        m_titleText->SetFont(titleFont);
        headerSizer->Add(m_titleText, 0, wxALIGN_CENTER_VERTICAL | wxALL, 5);

        // 添加一些弹性空间
        headerSizer->AddStretchSpacer();

        // 将headerSizer添加到mainSizer
        mainSizer->Add(headerSizer, 0, wxEXPAND | wxALL, 5);

        // 工具栏布局：arch、mode选择和复选框
        toolSizer = new wxBoxSizer(wxHORIZONTAL);

        // 添加架构和模式选择
        m_archChoice = new wxChoice(panel, ID_ARCH_CHOICE);
        m_modeChoice = new wxChoice(panel, ID_MODE_CHOICE);
        m_archChoice->SetMinSize(wxSize(150, -1));
        m_modeChoice->SetMinSize(wxSize(230, -1));

        toolSizer->Add(m_archChoice, 0, wxALL | wxALIGN_CENTER_VERTICAL, 5);
        toolSizer->Add(m_modeChoice, 0, wxALL | wxALIGN_CENTER_VERTICAL, 5);

        toolSizer->AddStretchSpacer();

        // 添加复选框
        m_hexCheckbox = new wxCheckBox(panel, ID_HEX_CHECKBOX, "0x");
        m_verboseCheckbox = new wxCheckBox(panel, ID_VERBOSE_CHECKBOX, "Verbose");
        m_gdbCheckbox = new wxCheckBox(panel, ID_GDB_CHECKBOX, "GDB/LLDB");
        m_skipDataCheckbox = new wxCheckBox(panel, ID_SKIPDATA_CHECKBOX, "SKIPDATA");

        m_verboseCheckbox->SetValue(false);
        m_gdbCheckbox->SetValue(false);

        toolSizer->Add(m_hexCheckbox, 0, wxALL | wxALIGN_CENTER_VERTICAL, 5);
        toolSizer->Add(m_verboseCheckbox, 0, wxALL | wxALIGN_CENTER_VERTICAL, 5);
        toolSizer->Add(m_gdbCheckbox, 0, wxALL | wxALIGN_CENTER_VERTICAL, 5);
        toolSizer->Add(m_skipDataCheckbox, 0, wxALL | wxALIGN_CENTER_VERTICAL, 5);
        mainSizer->Add(toolSizer, 0, wxEXPAND | wxALL, 5);

        // 创建分割窗口
        wxSplitterWindow *splitter = new wxSplitterWindow(panel, wxID_ANY,
                                                          wxDefaultPosition, wxDefaultSize,
                                                          wxSP_3D | wxSP_LIVE_UPDATE);
        splitter->SetMinimumPaneSize(100); // 设置最小面板大小

        // 创建左右面板
        wxPanel *leftPanel = new wxPanel(splitter, wxID_ANY);
        wxPanel *rightPanel = new wxPanel(splitter, wxID_ANY);

        // 为左右面板创建 sizer
        wxBoxSizer *leftSizer = new wxBoxSizer(wxVERTICAL);
        wxBoxSizer *rightSizer = new wxBoxSizer(wxVERTICAL);

        // 创建文本控件
        m_leftTextCtrl = new wxStyledTextCtrl(leftPanel, ID_LEFT_TEXT);
        m_rightTextCtrl = new wxStyledTextCtrl(rightPanel, ID_RIGHT_TEXT);
        // m_rightTextCtrl->SetReadOnly(true); // 只读

        // 将文本控件添加到对应的 sizer
        leftSizer->Add(m_leftTextCtrl, 1, wxEXPAND | wxALL, 5);
        rightSizer->Add(m_rightTextCtrl, 1, wxEXPAND | wxALL, 5);

        // 设置面板的 sizer
        leftPanel->SetSizer(leftSizer);
        rightPanel->SetSizer(rightSizer);

        // 分割窗口
        splitter->SplitVertically(leftPanel, rightPanel);
        splitter->SetSashGravity(0.5); // 设置分割线的重力，0.5 表示均分

        // 将分割窗口添加到主 sizer
        mainSizer->Add(splitter, 1, wxEXPAND | wxALL, 5);

        // 底部控件行
        wxBoxSizer *bottomSizer = new wxBoxSizer(wxHORIZONTAL);
        m_offsetTextCtrl = new wxTextCtrl(panel, ID_OFFSET_TEXT);
        m_convertBtn = new wxButton(panel, ID_CONVERT_BUTTON, "Convert", wxDefaultPosition, wxDefaultSize, wxBORDER_NONE);
        m_clearBtn = new wxButton(panel, ID_CLEAR_BUTTON, "Clear", wxDefaultPosition, wxDefaultSize, wxBORDER_NONE);
        m_toggleModeBtn = new wxButton(panel, ID_TOGGLE_MODE_BUTTON, "Toggle Mode", wxDefaultPosition, wxDefaultSize, wxBORDER_NONE);
        m_aboutBtn = new wxButton(panel, ID_ABOUT_BUTTON, "About", wxDefaultPosition, wxDefaultSize, wxBORDER_NONE);

        m_convertBtn->SetBackgroundColour(convertBtnColor);
        m_convertBtn->SetForegroundColour(blackColor);
        m_convertBtn->SetMinSize(wxSize(100, 25));

        m_clearBtn->SetBackgroundColour(clearBtnColor);
        m_clearBtn->SetForegroundColour(whiteColor);
        m_clearBtn->SetMinSize(wxSize(100, 25));

        m_toggleModeBtn->SetBackgroundColour(m_isAsmToHexMode ? ksColor : csColor);
        m_toggleModeBtn->SetForegroundColour(whiteColor);
        m_toggleModeBtn->SetMinSize(wxSize(100, 25));

        m_aboutBtn->SetBackgroundColour(aboutBtnColor);
        m_aboutBtn->SetForegroundColour(whiteColor);
        m_aboutBtn->SetMinSize(wxSize(100, 25));

        bottomSizer->Add(new wxStaticText(panel, wxID_ANY, "Offset: "), 0, wxALIGN_CENTER_VERTICAL | wxALL, 5);
        bottomSizer->Add(m_offsetTextCtrl, 0, wxALL, 5);
        bottomSizer->AddStretchSpacer();
        bottomSizer->Add(m_convertBtn, 0, wxALL, 5);
        bottomSizer->Add(m_clearBtn, 0, wxALL, 5);
        bottomSizer->Add(m_toggleModeBtn, 0, wxALL, 5);
        bottomSizer->Add(m_aboutBtn, 0, wxALL, 5);

        mainSizer->Add(bottomSizer, 0, wxEXPAND | wxALL, 5);

        // 状态栏
        m_statusBar = CreateStatusBar();

        panel->SetSizer(mainSizer);
        panel->SetSizerAndFit(mainSizer);
        mainSizer->SetSizeHints(this);
        Layout();

        // 初始化架构和模式选择
        InitializeArchitectures();

        // 设置一些默认值
        m_hexCheckbox->SetValue(false);
        m_verboseCheckbox->SetValue(false);
        m_gdbCheckbox->SetValue(false);
        m_skipDataCheckbox->SetValue(true);
        m_hexCheckbox->Show(m_isAsmToHexMode);
        m_gdbCheckbox->Show(m_isAsmToHexMode);
        m_skipDataCheckbox->Show(!m_isAsmToHexMode);
        m_offsetTextCtrl->SetValue("0x0");

        // 设置默认汇编代码
        const wxString defaultCode = "; Example code\n"
                                     "nop\n"
                                     "ret\n"
                                     "b #0x1018de444\n"
                                     "mov x0, #0x11fe0000\n"
                                     "beq #0x10020c\n"
                                     "cbnz r0, #0x682c4\n";

        m_leftTextCtrl->SetValue(defaultCode);
    }

    SetupTextCtrlStyles(m_leftTextCtrl, m_isAsmToHexMode);
    SetupTextCtrlStyles(m_rightTextCtrl, !m_isAsmToHexMode);

    // AddCustomSyntaxHighlighting(m_rightTextCtrl); // 添加自定义高亮

    CreateMenuBar();

    // 设置实际大小（使用计算的合理大小）
    SetSize(width, height);

    // 确保窗口不会小于最小尺寸
    SetSizeHints(GetMinSize());

    // 居中显示
    Centre(wxBOTH);

    UpdateModeUI();
}
void MainWindow::AddCustomSyntaxHighlighting(wxStyledTextCtrl *stc)
{ // 设置自定义的十六进制模式
    wxString hexPattern =
        // 基本的十六进制数
        "\\b0x[0-9A-Fa-f]+\\b|"
        // 十六进制字节序列
        "\\b[0-9A-Fa-f]{2}\\b|"
        // 地址格式
        "\\b[0-9A-Fa-f]{8}\\b|"
        // 带分隔符的十六进制序列
        "\\b[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+\\b";

    stc->SetKeyWords(2, hexPattern);

    // 为不同的模式设置不同的颜色
    stc->StyleSetForeground(wxSTC_C_WORD, wxColour(160, 32, 240)); // 0x开头的数
    stc->StyleSetForeground(wxSTC_C_WORD2, wxColour(0, 128, 192)); // 字节序列
    stc->StyleSetBold(wxSTC_C_WORD2, true);
}
void MainWindow::SetupTextCtrlStyles(wxStyledTextCtrl *stc, bool isAssembly)
{
    // 设置汇编语言词法分析器
    stc->SetLexer(wxSTC_LEX_ASM);

    // 默认样式
    stc->StyleSetForeground(wxSTC_ASM_DEFAULT, wxColour(0, 0, 0));

    // 注释
    stc->StyleSetForeground(wxSTC_ASM_COMMENT, wxColour(0, 128, 0));
    stc->StyleSetItalic(wxSTC_ASM_COMMENT, true);

    // 块注释
    stc->StyleSetForeground(wxSTC_ASM_COMMENTBLOCK, wxColour(0, 128, 0));
    stc->StyleSetItalic(wxSTC_ASM_COMMENTBLOCK, true);

    // 数值
    stc->StyleSetForeground(wxSTC_ASM_NUMBER, wxColour(128, 0, 128));

    // 字符串
    stc->StyleSetForeground(wxSTC_ASM_STRING, wxColour(128, 128, 0));

    // 字符
    stc->StyleSetForeground(wxSTC_ASM_CHARACTER, wxColour(128, 128, 0));

    // 操作符
    stc->StyleSetForeground(wxSTC_ASM_OPERATOR, wxColour(0, 0, 128));
    stc->StyleSetBold(wxSTC_ASM_OPERATOR, true);

    // 标识符
    stc->StyleSetForeground(wxSTC_ASM_IDENTIFIER, wxColour(64, 64, 64));

    // CPU指令
    stc->StyleSetForeground(wxSTC_ASM_CPUINSTRUCTION, wxColour(0, 0, 255));
    stc->StyleSetBold(wxSTC_ASM_CPUINSTRUCTION, true);

    // 数学指令
    stc->StyleSetForeground(wxSTC_ASM_MATHINSTRUCTION, wxColour(0, 0, 160));
    stc->StyleSetBold(wxSTC_ASM_MATHINSTRUCTION, true);

    // 寄存器
    stc->StyleSetForeground(wxSTC_ASM_REGISTER, wxColour(128, 0, 0));

    // 汇编指令
    stc->StyleSetForeground(wxSTC_ASM_DIRECTIVE, wxColour(0, 128, 128));
    stc->StyleSetBold(wxSTC_ASM_DIRECTIVE, true);

    // 指令操作数
    stc->StyleSetForeground(wxSTC_ASM_DIRECTIVEOPERAND, wxColour(128, 64, 0));

    // 扩展指令
    stc->StyleSetForeground(wxSTC_ASM_EXTINSTRUCTION, wxColour(0, 0, 200));
    stc->StyleSetBold(wxSTC_ASM_EXTINSTRUCTION, true);

    // 设置关键字列表
    // CPU 指令集
    wxString cpuInstructions = "mov add sub mul div ldr str push pop b bl beq bne blt bgt nop "
                               "adc and orr eor xor cmp cmn tst bic mvn "
                               "id groups op_count operands access imm read jump branch_relative reg write registers modified : code-condition return nzcv branch_relative "
                               "ldrh strh ldrb strb ldrsh ldrsb "
                               "ldp stp ldxr stxr "
                               "cbz cbnz tbz tbnz "
                               "adr adrp "
                               "ldrsw ldrh ldrsh ldrb ldrsb "
                               "ldur stur "
                               "ldar stlr "
                               "ldaxr stlxr "
                               "ldarb stlrb "
                               "ldarh stlrh "
                               "ldaxp stlxp "
                               "ldaxrb stlxrb "
                               "ldaxrh stlxrh "
                               "ldadd ldadda ldaddal ldaddl "
                               "ldsub ldsuba ldsubal ldsubl "
                               "ldmax ldmaxa ldmaxal ldmaxl "
                               "ldmin ldmina ldminal ldminl "
                               "ldumax ldumaxa ldumaxal ldumaxl "
                               "ldumin ldumina lduminal lduminl "
                               "br blr ret ";
    stc->SetKeyWords(0, cpuInstructions);

    // 数学指令集
    wxString mathInstructions = "fadd fsub fmul fdiv fcmp fabs "
                                "fneg fsqrt fcvts fcvtd fcvtsd fcvtzs fcvtzu fmov "
                                "scvtf ucvtf ";
    stc->SetKeyWords(1, mathInstructions);

    // 寄存器
    wxString registers = "r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 "
                         "x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 x16 x17 x18 x19 x20 x21 x22 x23 x24 x25 x26 x27 x28 x29 x30 "
                         "w0 w1 w2 w3 w4 w5 w6 w7 w8 w9 w10 w11 w12 w13 w14 w15 w16 w17 w18 w19 w20 w21 w22 w23 w24 w25 w26 w27 w28 w29 w30 "
                         "sp lr pc fpsr fpcr "
                         "v0 v1 v2 v3 v4 v5 v6 v7 v8 v9 v10 v11 v12 v13 v14 v15 "
                         "v16 v17 v18 v19 v20 v21 v22 v23 v24 v25 v26 v27 v28 v29 v30 v31 ";

    stc->SetKeyWords(2, registers);

    // 指令
    wxString directives =
        ".text .data .bss .global .section .align "
        ".ascii .asciz .byte .double .float .half .int .long .short .quad "
        ".comm .lcomm .org .space .zero "
        ".macro .endm .include "
        ".if .else .endif "
        ".equ .set .equiv "
        ".type .size .align .ident .option .file .previous .section .pushsection .popsection ";
    stc->SetKeyWords(3, directives);

    // 扩展指令
    wxString extInstructions = "vld1 vst1 vmul vadd "
                               "vld2 vst2 vld3 vst3 vld4 vst4 "
                               "vld1q vst1q vmulq vaddq vsubq vdivq "
                               "vand vandq vorq vxor vxorq "
                               "vshlq vshrq vrol vrolq vror vrorq "
                               "vldm vstm "
                               "vaddp vsubp vmulp vdivp "
                               "vshl vshr vsra "
                               "vorr veor "
                               "vmin vmax vminp vmaxp "
                               "vext vtrn vzip vuzp ";
    stc->SetKeyWords(4, extInstructions);

    // 通用设置
    stc->SetTabWidth(4);
    stc->SetUseTabs(false); // 使用空格而不是制表符

    // 显示行号
    stc->SetMarginWidth(0, 0);
    // stc->SetMarginType(0, wxSTC_MARGIN_NUMBER);

    // 设置边距
    stc->SetMarginLeft(0); // 左边距

    // 当前行高亮
    stc->SetCaretLineVisible(true);
    stc->SetCaretLineBackground(wxColour(240, 240, 240));
    stc->SetCaretLineVisibleAlways(true);

    // 选择文本的背景色
    stc->SetSelBackground(true, wxColour(200, 200, 200));

    // 设置等宽字体
    wxFont fixedFont(12, wxFONTFAMILY_TELETYPE, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);
    stc->StyleSetFont(wxSTC_STYLE_DEFAULT, fixedFont);

    // 设置标尺（可选）
    // stc->SetEdgeMode(wxSTC_EDGE_LINE);
    // stc->SetEdgeColumn(80);
    // stc->SetEdgeColour(wxColour(220, 220, 220));
}
void MainWindow::SwitchMode()
{
    m_isAsmToHexMode = !m_isAsmToHexMode;

    // 重新初始化架构和模式列表
    InitializeArchitectures();

    // 初始隐藏SKIPDATA复选框（如果初始是KS模式）
    m_hexCheckbox->Show(m_isAsmToHexMode);
    m_gdbCheckbox->Show(m_isAsmToHexMode);
    m_skipDataCheckbox->Show(!m_isAsmToHexMode);
    // 交换文本框的内容
    wxString tempContent = m_leftTextCtrl->GetValue();
    m_leftTextCtrl->SetValue(m_rightTextCtrl->GetValue());
    m_rightTextCtrl->SetValue(tempContent);

    SetupTextCtrlStyles(m_leftTextCtrl, m_isAsmToHexMode);
    SetupTextCtrlStyles(m_rightTextCtrl, !m_isAsmToHexMode);
    // AddCustomSyntaxHighlighting(m_rightTextCtrl); // 添加自定义高亮
    toolSizer->Layout();
    Layout();
    Refresh();

    UpdateModeUI();
}
void MainWindow::UpdateModeUI()
{
    wxWindowUpdateLocker lockUpdates(this);

    // 更新按钮颜色
    m_toggleModeBtn->SetBackgroundColour(m_isAsmToHexMode ? ksColor : csColor);

    // 更新标题和提示
    if (m_isAsmToHexMode)
    {
        if (m_titleText)
        {
            m_titleText->SetLabel(KS_TITLE);
            m_titleText->SetForegroundColour(ksColor); // 表示KS模式
        }
        SetTitle("Assembly to Hex Converter (KS Mode)");
        // m_leftTextCtrl->SetHint("Enter assembly code here...");
        // m_rightTextCtrl->SetHint("Hex output will appear here...");
        m_convertBtn->SetLabel("Assemble");
    }
    else
    {
        if (m_titleText)
        {
            m_titleText->SetLabel(CS_TITLE);
            m_titleText->SetForegroundColour(csColor); //  表示CS模式
        }
        SetTitle("Hex to Assembly Converter (CS Mode)");
        // m_leftTextCtrl->SetHint("Enter hex code here...");
        // m_rightTextCtrl->SetHint("Assembly output will appear here...");
        m_convertBtn->SetLabel("Disassemble");
    }

    Layout();
    Refresh();

    // 更新状态栏
    UpdateStatusBar(m_isAsmToHexMode ? "Switched to ASM->HEX mode" : "Switched to HEX->ASM mode");
}
void MainWindow::CreateMenuBar()
{

    wxMenuBar *menuBar = new wxMenuBar;
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    wxMenu *fileMenu = new wxMenu;
    fileMenu->Append(wxID_EXIT, "E&xit\tAlt-X", "Quit this program");
    menuBar->Append(fileMenu, "&File");
    wxMenu *helpMenu = new wxMenu;
    helpMenu->Append(wxID_ABOUT, "&About\tF1", "Show about dialog");
    menuBar->Append(helpMenu, "&Help");
#endif
#if wxOSX_USE_COCOA // 对于Mac，我们需要将菜单栏设置在父窗口上
    wxMenu *appleMenu = menuBar->OSXGetAppleMenu();
    appleMenu->Insert(0, wxID_ABOUT, "&About\tF1", "Show about dialog");
    appleMenu->InsertSeparator(1);
#elif wxWIN
#endif
    Bind(wxEVT_MENU, &MainWindow::OnExit, this, wxID_EXIT);
    Bind(wxEVT_MENU, &MainWindow::OnAbout, this, wxID_ABOUT);
    SetMenuBar(menuBar);
}
void MainWindow::OnExit(wxCommandEvent &event)
{
    this->Destroy();
}
void MainWindow::InitializeArchitectures()
{
    m_archChoice->Clear();

    if (m_isAsmToHexMode)
    {
        auto archs = KsEngine::getArchList();
        for (const auto &arch : archs)
        {
            m_archChoice->Append(arch);
        }
    }
    else
    {
        auto archs = CsEngine::getArchList();
        for (const auto &arch : archs)
        {
            m_archChoice->Append(arch);
        }
    }

    if (m_archChoice->GetCount() > 0)
    {
        // 查找上次选择的架构
        int lastIndex = m_archChoice->FindString(lastSelectedArch);
        if (lastIndex != wxNOT_FOUND)
        {
            m_archChoice->SetSelection(lastIndex);
        }
        else
        {
            // 如果找不到上次的选择，尝试设置arm64
            int arm64Index = m_archChoice->FindString("arm64");
            if (arm64Index != wxNOT_FOUND)
            {
                m_archChoice->SetSelection(arm64Index);
            }
            else
            {
                m_archChoice->SetSelection(0);
            }
        }

        UpdateModeChoices(m_archChoice->GetString(m_archChoice->GetSelection()));
    }
}

void MainWindow::UpdateModeChoices(const wxString &arch)
{
    m_modeChoice->Clear();
    if (m_isAsmToHexMode)
    {
        auto modes = KsEngine::getModeList(arch.ToStdString());
        for (const auto &mode : modes)
        {
            m_modeChoice->Append(mode);
        }
    }
    else
    {
        auto modes = CsEngine::getModeList(arch.ToStdString());
        for (const auto &mode : modes)
        {
            m_modeChoice->Append(mode);
        }
    }

    if (m_modeChoice->GetCount() > 0)
    {
        m_modeChoice->SetSelection(0);
    }
}

void MainWindow::OnConvert(wxCommandEvent &event)
{

    UpdateStatusBar("Converting...");

    if (m_isAsmToHexMode)
    {
        ConvertAsmToHex();
    }
    else
    {
        ConvertHexToAsm();
    }
}

// 新增：处理HEX到ASM的转换
void MainWindow::ConvertHexToAsm()
{
    wxString mode = m_modeChoice->GetString(m_modeChoice->GetSelection());
    wxString hexString = m_leftTextCtrl->GetValue();
    wxString startAddr = m_offsetTextCtrl->GetValue();

    if (hexString.IsEmpty())
    {
        UpdateStatusBar("Please enter hex code");
        return;
    }

    std::vector<CsEngine::DisasmResult> results;
    std::string errorMsg;

    bool success = CsEngine::convert(mode.ToStdString(), hexString.ToStdString(), startAddr.ToStdString(),
                                     m_skipDataCheckbox->GetValue(), // skipDataMode
                                     m_verboseCheckbox->GetValue(),  // verbose
                                     results, errorMsg);

    if (success)
    {
        wxString output;
        for (const auto &result : results)
        {
            if (!output.IsEmpty())
                output += "\n";

            // 格式化输出
            output += wxString::Format("0x%08llx: ", result.address);
            output += result.bytes;

            if (m_verboseCheckbox->GetValue())
            {
                output += wxString::Format("\t%s\t%s", result.mnemonic, result.operands);
                if (!result.detail.empty())
                {
                    output += "\n" + result.detail;
                }
            }
            else
            {
                output += wxString::Format("\t%s\t%s", result.mnemonic, result.operands);
            }
        }
        m_rightTextCtrl->ClearAll();
        m_rightTextCtrl->AddText(output);
        UpdateStatusBar("Disassembly successful");
    }
    else
    {
        UpdateStatusBar(errorMsg);
    }
}

void MainWindow::ConvertAsmToHex()
{
    // 使用选中的架构名称
    wxString arch = m_archChoice->GetString(m_archChoice->GetSelection());
    wxString assembly = m_leftTextCtrl->GetValue();
    wxString startAddr = m_offsetTextCtrl->GetValue();

    if (assembly.IsEmpty())
    {
        UpdateStatusBar("Please enter assembly code");
        return;
    }

    std::string output, errorMsg;
    bool success = KsEngine::convert(arch.ToStdString(), // 直接使用架构名称
                                     assembly.ToStdString(), startAddr.ToStdString(), m_hexCheckbox->GetValue(),
                                     m_verboseCheckbox->GetValue(), // 传递verbose标志
                                     m_gdbCheckbox->GetValue(),     // 添加GDB选项
                                     output, errorMsg);

    if (success)
    {
        m_rightTextCtrl->ClearAll();
        m_rightTextCtrl->AddText(output);
        UpdateStatusBar("Conversion successful");
    }
    else
    {
        UpdateStatusBar(errorMsg);
    }
}

// 事件处理函数：
void MainWindow::OnSplitterSashPosChanged(wxSplitterEvent &event)
{
    // 可以在这里保存分割位置
    event.Skip();
}

void MainWindow::OnClear(wxCommandEvent &event)
{
    ClearAllFields();
}

void MainWindow::OnToggleMode(wxCommandEvent &event)
{
    SwitchMode();
}

void MainWindow::OnAbout(wxCommandEvent &event)
{
    AboutDialog dlg(this);
    dlg.ShowModal();
    dlg.Destroy(); // 清理对话框
}

void MainWindow::OnArchChanged(wxCommandEvent &event)
{
    wxString arch = m_archChoice->GetString(m_archChoice->GetSelection());
    this->lastSelectedArch = arch.Clone();
    UpdateModeChoices(arch);
}

void MainWindow::OnModeChanged(wxCommandEvent &event)
{
    // TODO: 根据选择的模式更新相关设置
}

void MainWindow::OnHexChecked(wxCommandEvent &event)
{
    // TODO: 处理十六进制显示选项
}

void MainWindow::UpdateStatusBar(const wxString &message)
{
    m_statusBar->SetStatusText(message);
}

void MainWindow::ClearAllFields()
{
    // 提示用户是否清空？
    bool confirmed = wxMessageBox("Are you sure you want to clear all fields?", "Clear all fields",
                                  wxYES_NO | wxICON_QUESTION, this) == wxYES;
    if (!confirmed)
        return;

    m_leftTextCtrl->ClearAll();
    m_rightTextCtrl->ClearAll();
    m_offsetTextCtrl->SetValue("0x0");
    UpdateStatusBar("Cleared all fields");
}
