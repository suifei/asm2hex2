#ifndef CS_ENGINE_HPP
#define CS_ENGINE_HPP

#include <capstone/capstone.h>
#include <string>
#include <vector>
#include <utility>

class CsEngine {
public:
    // 存储arch和mode组合的结构
    struct ArchModeInfo {
        std::string name;      // 显示名称，如 "x16"
        std::string desc;      // 描述，如 "X86 16bit, Intel syntax"
        cs_arch arch;          // Capstone架构
        cs_mode mode;          // Capstone模式
        
        ArchModeInfo(const std::string& n, const std::string& d, 
                    cs_arch a, cs_mode m)
            : name(n), desc(d), arch(a), mode(m) {}
    };

    // 从字节码转换到汇编的结构
    struct DisasmResult {
        uint64_t address;      // 指令地址
        std::string bytes;     // 原始字节码
        std::string mnemonic;  // 助记符
        std::string operands;  // 操作数
        std::string detail;    // 详细信息（当verbose模式启用时）
    };

    static std::vector<ArchModeInfo> getSupportedArchModes();
    static std::vector<std::string> getArchList();
    static std::vector<std::string> getModeList(const std::string& arch);
    
    // 转换函数
    static bool convert(const std::string& archMode,       // x64, arm等
                       const std::string& hexString,       // hex字符串
                       const std::string& startAddr,       // 16进制起始地址
                       bool skipDataMode,                  // 是否启用SKIPDATA模式
                       bool verbose,                       // 是否显示详细信息
                       std::vector<DisasmResult>& results, // 反汇编结果
                       std::string& errorMsg);            // 错误信息

private:
    // 辅助函数
    static bool parseArchMode(const std::string& archMode, 
                            cs_arch& arch, 
                            cs_mode& mode,
                            std::string& errorMsg);
                            
    static bool parseHexString(const std::string& hexString, 
                             std::vector<uint8_t>& bytes);
};

#endif // CS_ENGINE_HPP