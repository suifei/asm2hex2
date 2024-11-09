#ifndef KS_ENGINE_HPP
#define KS_ENGINE_HPP

#include <keystone/keystone.h>
#include <string>
#include <vector>
#include <utility>

class KsEngine
{
  public:
    // 用于存储arch和mode组合的结构
    struct ArchModeInfo
    {
        std::string name; // 显示名称，如 "x16"
        std::string desc; // 描述，如 "X86 16bit, Intel syntax"
        ks_arch arch;     // Keystone架构
        ks_mode mode;     // Keystone模式

        // 添加构造函数
        ArchModeInfo(const std::string &n, const std::string &d, ks_arch a, ks_mode m)
            : name(n), desc(d), arch(a), mode(m)
        {
        }
    };

    static std::vector<ArchModeInfo> getSupportedArchModes();
    static std::vector<std::string> getArchList();
    static std::vector<std::string> getModeList(const std::string &arch);

    static bool convert(const std::string &archMode, const std::string &assembly, const std::string &startAddr,
                        bool addHexPrefix, bool verbose, bool gdbFormat, std::string &output, std::string &errorMsg);

  private:
    static bool parseArchMode(const std::string &archMode, ks_arch &arch, ks_mode &mode, std::string &errorMsg);
};

#endif // KS_ENGINE_HPP