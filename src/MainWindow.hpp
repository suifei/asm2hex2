#ifndef MAIN_WINDOW_HPP
#define MAIN_WINDOW_HPP

#include <wx/wx.h>
#include <wx/statline.h>
#include <wx/splitter.h>
#include <wx/stc/stc.h>
#include "KsEngine.hpp" // 新增：包含KsEngine头文件

// 前向声明
class wxChoice;
class wxCheckBox;
class wxTextCtrl;
class wxButton;
class wxStatusBar;

#define CS_TITLE "HEX to ASM Converter"
#define KS_TITLE "ASM to HEX Converter"

class MainWindow : public wxFrame
{
public:
  MainWindow();

private:
  // GUI组件
  wxStaticText *m_titleText;
  wxBoxSizer *toolSizer;
  wxChoice *m_archChoice;
  wxChoice *m_modeChoice;
  wxCheckBox *m_hexCheckbox;
  wxCheckBox *m_verboseCheckbox;  // 新增: verbose复选框
  wxCheckBox *m_gdbCheckbox;      // 加回GDB复选框
  wxCheckBox *m_skipDataCheckbox; // 新增 SKIPDATA 复选框
  wxStyledTextCtrl *m_leftTextCtrl;
  wxStyledTextCtrl *m_rightTextCtrl;
  wxTextCtrl *m_offsetTextCtrl;
  wxButton *m_convertBtn;
  wxButton *m_clearBtn;
  wxButton *m_toggleModeBtn;
  wxButton *m_aboutBtn;
  wxStatusBar *m_statusBar;

  // 内部状态
  bool m_isAsmToHexMode;
  wxString lastSelectedArch; // 默认值

  // 事件处理函数
  void OnConvert(wxCommandEvent &event);
  void OnClear(wxCommandEvent &event);
  void OnToggleMode(wxCommandEvent &event);
  void OnAbout(wxCommandEvent &event);
  void OnArchChanged(wxCommandEvent &event);
  void OnModeChanged(wxCommandEvent &event);
  void OnHexChecked(wxCommandEvent &event);
  void OnSplitterSashPosChanged(wxSplitterEvent &event);

  // 辅助函数
  void InitializeComponents();
  void CreateMenuBar();

  // 新增：Keystone相关函数
  void InitializeArchitectures();
  void UpdateModeChoices(const wxString &arch);
  void UpdateStatusBar(const wxString &message);
  void ClearAllFields();
  void SetupTextCtrlStyles(wxStyledTextCtrl *stc, bool isAssembly);
  void AddCustomSyntaxHighlighting(wxStyledTextCtrl *stc);
  void SwitchMode();
  void UpdateModeUI();
  void ConvertHexToAsm();
  void ConvertAsmToHex();

  wxDECLARE_EVENT_TABLE();
};

// 自定义事件ID
enum
{
  ID_ARCH_CHOICE = wxID_HIGHEST + 1,
  ID_MODE_CHOICE,
  ID_HEX_CHECKBOX,
  ID_VERBOSE_CHECKBOX,  // 新增: verbose复选框ID
  ID_GDB_CHECKBOX,      // GDB复选框ID
  ID_SKIPDATA_CHECKBOX, // 新增 ID
  ID_CONVERT_BUTTON,
  ID_CLEAR_BUTTON,
  ID_TOGGLE_MODE_BUTTON,
  ID_ABOUT_BUTTON,
  ID_LEFT_TEXT,
  ID_RIGHT_TEXT,
  ID_OFFSET_TEXT
};

#endif // MAIN_WINDOW_HPP