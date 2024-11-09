#include "KsEngine.hpp"
#include "OSCross.hpp"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <stdio.h> 

std::vector<KsEngine::ArchModeInfo> KsEngine::getSupportedArchModes()
{
    bool KS_ARCH_ARM_Is_Supported = ks_arch_supported(KS_ARCH_ARM);
    bool KS_ARCH_ARM64_Is_Supported = ks_arch_supported(KS_ARCH_ARM64);
    bool KS_ARCH_MIPS_Is_Supported = ks_arch_supported(KS_ARCH_MIPS);
    bool KS_ARCH_PPC_Is_Supported = ks_arch_supported(KS_ARCH_PPC);
    bool KS_ARCH_SPARC_Is_Supported = ks_arch_supported(KS_ARCH_SPARC);
    bool KS_ARCH_X86_Is_Supported = ks_arch_supported(KS_ARCH_X86);
    bool KS_ARCH_HEXAGON_Is_Supported = ks_arch_supported(KS_ARCH_HEXAGON);
    bool KS_ARCH_SYSTEMZ_Is_Supported = ks_arch_supported(KS_ARCH_SYSTEMZ);
    bool KS_ARCH_EVM_Is_Supported = ks_arch_supported(KS_ARCH_EVM);

    // 打印调试信息
    char buffer[256];
    SAFE_SPRINTF(buffer, sizeof(buffer), "KS_ARCH_ARM:%s", KS_ARCH_ARM_Is_Supported ? " ON" : " OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "KS_ARCH_ARM64:%s", KS_ARCH_ARM64_Is_Supported ? "ON" : "OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "KS_ARCH_MIPS:%s", KS_ARCH_MIPS_Is_Supported ? "ON" : "OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "KS_ARCH_PPC:%s", KS_ARCH_PPC_Is_Supported ? "ON" : "OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "KS_ARCH_SPARC:%s", KS_ARCH_SPARC_Is_Supported ? "ON" : "OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "KS_ARCH_X86:%s", KS_ARCH_X86_Is_Supported ? "ON" : "OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "KS_ARCH_HEXAGON:%s", KS_ARCH_HEXAGON_Is_Supported ? "ON" : "OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "KS_ARCH_SYSTEMZ:%s", KS_ARCH_SYSTEMZ_Is_Supported ? "ON" : "OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "KS_ARCH_EVM:%s", KS_ARCH_EVM_Is_Supported ? "ON" : "OFF");
    DEBUG_OUTPUT(buffer);

    std::vector<ArchModeInfo> supported;

    // X86架构
    if (KS_ARCH_X86_Is_Supported)
    {
        supported.push_back(ArchModeInfo("x16", "X86 16bit, Intel syntax", KS_ARCH_X86, KS_MODE_16));
        supported.push_back(ArchModeInfo("x32", "X86 32bit, Intel syntax", KS_ARCH_X86, KS_MODE_32));
        supported.push_back(ArchModeInfo("x64", "X86 64bit, Intel syntax", KS_ARCH_X86, KS_MODE_64));
        supported.push_back(ArchModeInfo("x16att", "X86 16bit, AT&T syntax", KS_ARCH_X86, KS_MODE_16));
        supported.push_back(ArchModeInfo("x32att", "X86 32bit, AT&T syntax", KS_ARCH_X86, KS_MODE_32));
        supported.push_back(ArchModeInfo("x64att", "X86 64bit, AT&T syntax", KS_ARCH_X86, KS_MODE_64));
        supported.push_back(ArchModeInfo("x16nasm", "X86 16bit, NASM syntax", KS_ARCH_X86, KS_MODE_16));
        supported.push_back(ArchModeInfo("x32nasm", "X86 32bit, NASM syntax", KS_ARCH_X86, KS_MODE_32));
        supported.push_back(ArchModeInfo("x64nasm", "X86 64bit, NASM syntax", KS_ARCH_X86, KS_MODE_64));
    }

    // ARM架构
    if (KS_ARCH_ARM_Is_Supported)
    {
        supported.push_back(ArchModeInfo("arm", "ARM - little endian", KS_ARCH_ARM,
                                         static_cast<ks_mode>(KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("armbe", "ARM - big endian", KS_ARCH_ARM,
                                         static_cast<ks_mode>(KS_MODE_ARM | KS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("thumb", "Thumb - little endian", KS_ARCH_ARM,
                                         static_cast<ks_mode>(KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("thumbbe", "Thumb - big endian", KS_ARCH_ARM,
                                         static_cast<ks_mode>(KS_MODE_THUMB | KS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("armv8", "ARM V8 - little endian", KS_ARCH_ARM,
                                         static_cast<ks_mode>(KS_MODE_ARM | KS_MODE_V8 | KS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("armv8be", "ARM V8 - big endian", KS_ARCH_ARM,
                                         static_cast<ks_mode>(KS_MODE_ARM | KS_MODE_V8 | KS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("thumbv8", "Thumb V8 - little endian", KS_ARCH_ARM,
                                         static_cast<ks_mode>(KS_MODE_THUMB | KS_MODE_V8 | KS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("thumbv8be", "Thumb V8 - big endian", KS_ARCH_ARM,
                                         static_cast<ks_mode>(KS_MODE_THUMB | KS_MODE_V8 | KS_MODE_BIG_ENDIAN)));
    }

    // ARM64架构
    if (KS_ARCH_ARM64_Is_Supported)
    {
        supported.push_back(ArchModeInfo("arm64", "AArch64", KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN));
    }

    // HEXAGON架构
    if (KS_ARCH_HEXAGON_Is_Supported)
    {
        supported.push_back(ArchModeInfo("hexagon", "Hexagon", KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN));
    }

    // MIPS架构
    if (KS_ARCH_MIPS_Is_Supported)
    {
        supported.push_back(ArchModeInfo("mips", "Mips - little endian", KS_ARCH_MIPS,
                                         static_cast<ks_mode>(KS_MODE_MIPS32 | KS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("mipsbe", "Mips - big endian", KS_ARCH_MIPS,
                                         static_cast<ks_mode>(KS_MODE_MIPS32 | KS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("mips64", "Mips64 - little endian", KS_ARCH_MIPS,
                                         static_cast<ks_mode>(KS_MODE_MIPS64 | KS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("mips64be", "Mips64 - big endian", KS_ARCH_MIPS,
                                         static_cast<ks_mode>(KS_MODE_MIPS64 | KS_MODE_BIG_ENDIAN)));
    }

    // PowerPC架构
    if (KS_ARCH_PPC_Is_Supported)
    {
        supported.push_back(ArchModeInfo("ppc32be", "PowerPC32 - big endian", KS_ARCH_PPC,
                                         static_cast<ks_mode>(KS_MODE_PPC32 | KS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("ppc64", "PowerPC64 - little endian", KS_ARCH_PPC,
                                         static_cast<ks_mode>(KS_MODE_PPC64 | KS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("ppc64be", "PowerPC64 - big endian", KS_ARCH_PPC,
                                         static_cast<ks_mode>(KS_MODE_PPC64 | KS_MODE_BIG_ENDIAN)));
    }

    // SPARC架构
    if (KS_ARCH_SPARC_Is_Supported)
    {
        supported.push_back(ArchModeInfo("sparc", "Sparc - little endian", KS_ARCH_SPARC,
                                         static_cast<ks_mode>(KS_MODE_SPARC32 | KS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("sparcbe", "Sparc - big endian", KS_ARCH_SPARC,
                                         static_cast<ks_mode>(KS_MODE_SPARC32 | KS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("sparc64be", "Sparc64 - big endian", KS_ARCH_SPARC,
                                         static_cast<ks_mode>(KS_MODE_SPARC64 | KS_MODE_BIG_ENDIAN)));
    }

    // SystemZ架构
    if (KS_ARCH_SYSTEMZ_Is_Supported)
    {
        supported.push_back(ArchModeInfo("systemz", "SystemZ (S390x)", KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN));
    }

    // EVM架构
    if (KS_ARCH_EVM_Is_Supported)
    {
        supported.push_back(ArchModeInfo("evm", "Ethereum Virtual Machine", KS_ARCH_EVM, KS_MODE_LITTLE_ENDIAN));
    }

    return supported;
}

std::vector<std::string> KsEngine::getArchList()
{
    std::vector<std::string> archs;
    std::string lastArch;

    auto supported = getSupportedArchModes();
    for (const auto &info : supported)
    {
        // 获取name，不再进行字符串处理
        if (info.name != lastArch)
        {
            archs.push_back(info.name);
            lastArch = info.name;
        }
    }

    return archs;
}

// 修改 getModeList() 实现
std::vector<std::string> KsEngine::getModeList(const std::string &arch)
{
    std::vector<std::string> modes;
    auto supported = getSupportedArchModes();

    for (const auto &info : supported)
    {
        // 如果选中的架构匹配，则添加描述文本
        if (info.name == arch)
        {
            modes.push_back(info.desc);
        }
    }

    return modes;
}

// 相应地，修改 parseArchMode() 实现
bool KsEngine::parseArchMode(const std::string &archMode, ks_arch &arch, ks_mode &mode, std::string &errorMsg)
{
    auto supported = getSupportedArchModes();
    for (const auto &info : supported)
    {
        // 直接用name进行匹配
        if (info.name == archMode)
        {
            arch = info.arch;
            mode = info.mode;
            return true;
        }
    }

    errorMsg = "Unsupported architecture/mode: " + archMode;
    return false;
}

bool KsEngine::convert(const std::string &archMode, const std::string &assembly, const std::string &startAddr,
                       bool addHexPrefix, bool verbose, bool gdbFormat, std::string &output, std::string &errorMsg)
{
    ks_engine *ks;
    ks_arch arch;
    ks_mode mode;

    if (!parseArchMode(archMode, arch, mode, errorMsg))
    {
        return false;
    }

    if (ks_open(arch, mode, &ks) != KS_ERR_OK)
    {
        errorMsg = "ERROR: failed to initialize engine";
        return false;
    }

    // 设置语法选项
    if (archMode.find("att") != std::string::npos)
    {
        ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
    }
    else if (archMode.find("nasm") != std::string::npos)
    {
        ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
    }

    // 解析起始地址
    uint64_t address = 0;
    if (!startAddr.empty())
    {
        try
        {
            address = std::stoull(startAddr, nullptr, 16);
        }
        catch (...)
        {
            errorMsg = "ERROR: invalid starting address";
            ks_close(ks);
            return false;
        }
    }

    // 存储所有转换结果
    std::stringstream finalOutput;
    bool isFirstLine = true;
    bool hasValidCode = false; // 新增：跟踪是否有任何有效代码

    // 按行分割输入的汇编代码
    std::istringstream iss(assembly);
    std::string line;

    while (std::getline(iss, line))
    {
        // 跳过空行和只包含空白字符的行
        if (line.empty() || std::all_of(line.begin(), line.end(), ::isspace))
        {
            continue;
        }

        // 去除行首尾的空白字符
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        // 跳过注释行（以;或//开头的行）
        if (line[0] == ';' || (line[0] == '/' && line[1] == '/'))
        {
            continue;
        }

        // 汇编当前行
        unsigned char *encode = nullptr;
        size_t count;
        size_t size;

        if (!isFirstLine)
        {
            finalOutput << "\n";
        }

        finalOutput << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << address << ": ";

        if (ks_asm(ks, line.c_str(), address, &encode, &size, &count))
        {
            if (verbose)
            {
                std::string error = ks_strerror(ks_errno(ks));
                finalOutput << "ERROR: " << error << "  ; " << line;
            }
            else
            {
                finalOutput << "ERROR";
            }
            if (encode)
            {
                ks_free(encode);
            }
        }
        else
        {
            // 汇编成功
            if (size > 0)
            {
                if (gdbFormat)
                {
                    // GDB/LLDB格式
                    for (size_t i = 0; i < size; i += 4)
                    {
                        if (i > 0)
                            finalOutput << " ";
                        size_t groupSize = std::min(size_t(4), size - i);
                        std::stringstream groupHex;
                        for (int j = groupSize - 1; j >= 0; --j)
                        {
                            groupHex << std::hex << std::setw(2) << std::setfill('0')
                                     << static_cast<unsigned int>(encode[i + j]);
                        }
                        if (addHexPrefix)
                        {
                            finalOutput << "0x";
                        }
                        finalOutput << groupHex.str();
                    }
                }
                else
                {
                    // 普通格式
                    if (addHexPrefix)
                    {
                        finalOutput << "0x";
                    }
                    for (size_t i = 0; i < size; i++)
                    {
                        finalOutput << std::hex << std::setw(2) << std::setfill('0')
                                    << static_cast<unsigned int>(encode[i]);
                    }
                }

                if (verbose)
                {
                    finalOutput << "  ; " << line;
                }

                address += size;
                hasValidCode = true;
            }

            if (encode)
            {
                ks_free(encode);
                encode = nullptr;
            }
        }

        isFirstLine = false;
    }

    output = finalOutput.str();
    ks_close(ks);

    if (!hasValidCode)
    {
        // 只有当没有任何行被成功汇编时才返回失败
        errorMsg = "No valid assembly code found";
        return false;
    }

    return true;
}