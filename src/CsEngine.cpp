#include "CsEngine.hpp"
#include "cstool.h"
#include "OSCross.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <stdio.h>

std::vector<CsEngine::ArchModeInfo> CsEngine::getSupportedArchModes()
{
    bool CS_ARCH_ARM_Is_Supported = cs_support(CS_ARCH_ARM);
    bool CS_ARCH_ARM64_Is_Supported = cs_support(CS_ARCH_ARM64);
    bool CS_ARCH_MIPS_Is_Supported = cs_support(CS_ARCH_MIPS);
    bool CS_ARCH_X86_Is_Supported = cs_support(CS_ARCH_X86);
    bool CS_ARCH_PPC_Is_Supported = cs_support(CS_ARCH_PPC);
    bool CS_ARCH_SPARC_Is_Supported = cs_support(CS_ARCH_SPARC);
    bool CS_ARCH_SYSZ_Is_Supported = cs_support(CS_ARCH_SYSZ);
    bool CS_ARCH_XCORE_Is_Supported = cs_support(CS_ARCH_XCORE);
    bool CS_ARCH_M68K_Is_Supported = cs_support(CS_ARCH_M68K);
    bool CS_ARCH_TMS320C64X_Is_Supported = cs_support(CS_ARCH_TMS320C64X);
    bool CS_ARCH_BPF_Is_Supported = cs_support(CS_ARCH_BPF);
    bool CS_ARCH_RISCV_Is_Supported = cs_support(CS_ARCH_RISCV);

    // 打印调试信息
    char buffer[256];
    SAFE_SPRINTF(buffer, sizeof(buffer), "CS_ARCH_ARM:%s", CS_ARCH_ARM_Is_Supported ? " ON" : " OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "CS_ARCH_ARM64:%s", CS_ARCH_ARM64_Is_Supported ? " ON" : " OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "CS_ARCH_MIPS:%s", CS_ARCH_MIPS_Is_Supported ? " ON" : " OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "CS_ARCH_X86:%s", CS_ARCH_X86_Is_Supported ? " ON" : " OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "CS_ARCH_PPC:%s", CS_ARCH_PPC_Is_Supported ? " ON" : " OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "CS_ARCH_SPARC:%s", CS_ARCH_SPARC_Is_Supported ? " ON" : " OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "CS_ARCH_SYSZ:%s", CS_ARCH_SYSZ_Is_Supported ? " ON" : " OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "CS_ARCH_XCORE:%s", CS_ARCH_XCORE_Is_Supported ? " ON" : " OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "CS_ARCH_M68K:%s", CS_ARCH_M68K_Is_Supported ? " ON" : " OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "CS_ARCH_TMS320C64X:%s", CS_ARCH_TMS320C64X_Is_Supported ? " ON" : " OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "CS_ARCH_BPF:%s", CS_ARCH_BPF_Is_Supported ? " ON" : " OFF");
    DEBUG_OUTPUT(buffer);
    SAFE_SPRINTF(buffer, sizeof(buffer), "CS_ARCH_RISCV:%s", CS_ARCH_RISCV_Is_Supported ? " ON" : " OFF");
    DEBUG_OUTPUT(buffer);

    std::vector<ArchModeInfo> supported;

    // ARM
    if (CS_ARCH_ARM_Is_Supported)
    {
        supported.push_back(ArchModeInfo("arm", "ARM", CS_ARCH_ARM, CS_MODE_ARM));
        supported.push_back(ArchModeInfo("armb", "ARM + big endian", CS_ARCH_ARM,
                                         static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("armbe", "ARM + big endian", CS_ARCH_ARM,
                                         static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("arml", "ARM + little endian", CS_ARCH_ARM,
                                         static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("armle", "ARM + little endian", CS_ARCH_ARM,
                                         static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)));
        supported.push_back(
            ArchModeInfo("armv8", "ARM V8", CS_ARCH_ARM, static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_V8)));
        supported.push_back(ArchModeInfo("thumbv8", "Thumb V8", CS_ARCH_ARM,
                                         static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_V8)));
        supported.push_back(ArchModeInfo("armv8be", "ARM V8 + big endian", CS_ARCH_ARM,
                                         static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_V8 | CS_MODE_BIG_ENDIAN)));
        supported.push_back(
            ArchModeInfo("thumbv8be", "Thumb V8 + big endian", CS_ARCH_ARM,
                         static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_V8 | CS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("cortexm", "Thumb + Cortex-M", CS_ARCH_ARM,
                                         static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_MCLASS)));
        supported.push_back(
            ArchModeInfo("thumb", "Thumb", CS_ARCH_ARM, static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_THUMB)));
        supported.push_back(ArchModeInfo("thumbbe", "Thumb + big endian", CS_ARCH_ARM,
                                         static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("thumble", "Thumb + little endian", CS_ARCH_ARM,
                                         static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)));
    }

    // ARM64
    if (CS_ARCH_ARM64_Is_Supported)
    {
        supported.push_back(ArchModeInfo("arm64", "AArch64", CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN));
        supported.push_back(ArchModeInfo("arm64be", "AArch64 + big endian", CS_ARCH_ARM64, CS_MODE_BIG_ENDIAN));
    }

    // MIPS
    if (CS_ARCH_MIPS_Is_Supported)
    {
        supported.push_back(ArchModeInfo("mips", "MIPS + little endian", CS_ARCH_MIPS,
                                         static_cast<cs_mode>(CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("mipsmicro", "MIPS + micro", CS_ARCH_MIPS,
                                         static_cast<cs_mode>(CS_MODE_MIPS32 | CS_MODE_MICRO)));
        supported.push_back(ArchModeInfo("mipsbemicro", "MIPS + big endian + micro", CS_ARCH_MIPS,
                                         static_cast<cs_mode>(CS_MODE_MIPS32 | CS_MODE_MICRO | CS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("mipsbe32r6", "MIPS32R6 + big endian", CS_ARCH_MIPS,
                                         static_cast<cs_mode>(CS_MODE_MIPS32R6 | CS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("mipsbe32r6micro", "MIPS32R6 + big endian + micro", CS_ARCH_MIPS,
                                         static_cast<cs_mode>(CS_MODE_MIPS32R6 | CS_MODE_BIG_ENDIAN | CS_MODE_MICRO)));
        supported.push_back(ArchModeInfo("mips32r6", "MIPS32R6", CS_ARCH_MIPS, CS_MODE_MIPS32R6));
        supported.push_back(ArchModeInfo("mips32r6micro", "MIPS32R6 + micro", CS_ARCH_MIPS,
                                         static_cast<cs_mode>(CS_MODE_MIPS32R6 | CS_MODE_MICRO)));
        supported.push_back(ArchModeInfo("mipsbe", "MIPS + big endian", CS_ARCH_MIPS,
                                         static_cast<cs_mode>(CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("mips64", "MIPS64 + little endian", CS_ARCH_MIPS,
                                         static_cast<cs_mode>(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("mips64be", "MIPS64 + big endian", CS_ARCH_MIPS,
                                         static_cast<cs_mode>(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)));
    }

    // X86
    if (CS_ARCH_X86_Is_Supported)
    {
        supported.push_back(ArchModeInfo("x16", "X86 16-bit", CS_ARCH_X86, CS_MODE_16));
        supported.push_back(ArchModeInfo("x32", "X86 32-bit", CS_ARCH_X86, CS_MODE_32));
        supported.push_back(ArchModeInfo("x64", "X86 64-bit", CS_ARCH_X86, CS_MODE_64));
        supported.push_back(
            ArchModeInfo("x16att", "X86 16-bit, AT&T syntax", CS_ARCH_X86, CS_MODE_16)); // 语法模式在convert时设置
        supported.push_back(
            ArchModeInfo("x32att", "X86 32-bit, AT&T syntax", CS_ARCH_X86, CS_MODE_32)); // 语法模式在convert时设置
        supported.push_back(
            ArchModeInfo("x64att", "X86 64-bit, AT&T syntax", CS_ARCH_X86, CS_MODE_64)); // 语法模式在convert时设置
    }

    // PowerPC
    if (CS_ARCH_PPC_Is_Supported)
    {
        supported.push_back(ArchModeInfo("ppc32", "PowerPC32 + little endian", CS_ARCH_PPC,
                                         static_cast<cs_mode>(CS_MODE_32 | CS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("ppc32be", "PowerPC32 + big endian", CS_ARCH_PPC,
                                         static_cast<cs_mode>(CS_MODE_32 | CS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("ppc32qpx", "PowerPC32 + QPX + little endian", CS_ARCH_PPC,
                                         static_cast<cs_mode>(CS_MODE_32 | CS_MODE_QPX | CS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("ppc32beqpx", "PowerPC32 + QPX + big endian", CS_ARCH_PPC,
                                         static_cast<cs_mode>(CS_MODE_32 | CS_MODE_QPX | CS_MODE_BIG_ENDIAN)));
        supported.push_back(ArchModeInfo("ppc64", "PowerPC64 + little endian", CS_ARCH_PPC,
                                         static_cast<cs_mode>(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN)));
        supported.push_back(ArchModeInfo("ppc64be", "PowerPC64 + big endian", CS_ARCH_PPC,
                                         static_cast<cs_mode>(CS_MODE_64 | CS_MODE_BIG_ENDIAN)));
    }

    // Sparc
    if (CS_ARCH_SPARC_Is_Supported)
    {
        supported.push_back(ArchModeInfo("sparc", "Sparc", CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN));
        supported.push_back(
            ArchModeInfo("sparcv9", "SparcV9", CS_ARCH_SPARC, static_cast<cs_mode>(CS_MODE_BIG_ENDIAN | CS_MODE_V9)));
    }

    // SystemZ
    if (CS_ARCH_SYSZ_Is_Supported)
    {
        supported.push_back(ArchModeInfo("systemz", "SystemZ", CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN));
        supported.push_back(ArchModeInfo("sysz", "SystemZ", CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN));
        supported.push_back(ArchModeInfo("s390x", "SystemZ (S390x)", CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN));
    }

    // XCore
    if (CS_ARCH_XCORE_Is_Supported)
    {
        supported.push_back(ArchModeInfo("xcore", "XCore", CS_ARCH_XCORE, CS_MODE_BIG_ENDIAN));
    }

    // M68K
    if (CS_ARCH_M68K_Is_Supported)
    {
        supported.push_back(ArchModeInfo("m68k", "M68K", CS_ARCH_M68K, CS_MODE_BIG_ENDIAN));
        supported.push_back(ArchModeInfo("m68k40", "M68K040", CS_ARCH_M68K, CS_MODE_M68K_040));
    }

    // TMS320C64x
    if (CS_ARCH_TMS320C64X_Is_Supported)
    {
        supported.push_back(ArchModeInfo("tms320c64x", "TMS320C64x", CS_ARCH_TMS320C64X, CS_MODE_BIG_ENDIAN));
    }

    // BPF
    if (CS_ARCH_BPF_Is_Supported)
    {
        supported.push_back(ArchModeInfo("bpf", "Classic BPF", CS_ARCH_BPF,
                                         static_cast<cs_mode>(CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_CLASSIC)));
        supported.push_back(ArchModeInfo("bpfbe", "Classic BPF + big endian", CS_ARCH_BPF,
                                         static_cast<cs_mode>(CS_MODE_BIG_ENDIAN | CS_MODE_BPF_CLASSIC)));
        supported.push_back(ArchModeInfo("ebpf", "Extended BPF", CS_ARCH_BPF,
                                         static_cast<cs_mode>(CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_EXTENDED)));
        supported.push_back(ArchModeInfo("ebpfbe", "Extended BPF + big endian", CS_ARCH_BPF,
                                         static_cast<cs_mode>(CS_MODE_BIG_ENDIAN | CS_MODE_BPF_EXTENDED)));
    }

    // RISCV
    if (CS_ARCH_RISCV_Is_Supported)
    {
        supported.push_back(
            ArchModeInfo("riscv32", "RISCV32", CS_ARCH_RISCV, static_cast<cs_mode>(CS_MODE_RISCV32 | CS_MODE_RISCVC)));
        supported.push_back(
            ArchModeInfo("riscv64", "RISCV64", CS_ARCH_RISCV, static_cast<cs_mode>(CS_MODE_RISCV64 | CS_MODE_RISCVC)));
    }

    return supported;
}
std::vector<std::string> CsEngine::getArchList()
{
    std::vector<std::string> archs;
    std::string lastArch;

    auto supported = getSupportedArchModes();
    for (const auto &info : supported)
    {
        std::string arch = info.name;
        if (arch != lastArch)
        {
            archs.push_back(arch);
            lastArch = arch;
        }
    }

    return archs;
}

std::vector<std::string> CsEngine::getModeList(const std::string &arch)
{
    std::vector<std::string> modes;
    auto supported = getSupportedArchModes();

    for (const auto &info : supported)
    {
        if (info.name == arch)
        {
            modes.push_back(info.desc);
        }
    }

    return modes;
}

bool CsEngine::parseArchMode(const std::string &archMode, cs_arch &arch, cs_mode &mode, std::string &errorMsg)
{
    auto supported = getSupportedArchModes();
    for (const auto &info : supported)
    {
        if (info.desc == archMode)
        {
            arch = info.arch;
            mode = info.mode;
            return true;
        }
    }

    errorMsg = "Unsupported architecture mode: " + archMode;
    return false;
}

bool CsEngine::parseHexString(const std::string &hexString, std::vector<uint8_t> &bytes)
{
    bytes.clear();
    std::string currentLine;
    std::istringstream stream(hexString);

    // 处理多行输入
    while (std::getline(stream, currentLine))
    {
        // 跳过空行
        if (currentLine.empty())
        {
            continue;
        }

        // 移除可能的地址前缀 (类似 "00000000: ")
        size_t colonPos = currentLine.find(':');
        if (colonPos != std::string::npos)
        {
            currentLine = currentLine.substr(colonPos + 1);
        }
        // 移除可能的地址后缀 (类似 " ; comment")
        size_t semicolonPos = currentLine.find(';');
        if (semicolonPos != std::string::npos)
        {
            currentLine = currentLine.substr(0, semicolonPos);
        }

        // 跳过包含 "ERROR" 的行
        if (currentLine.find("ERROR") != std::string::npos)
        {
            continue;
        }

        // 移除首尾空白字符
        currentLine.erase(0, currentLine.find_first_not_of(" \t\r\n"));
        currentLine.erase(currentLine.find_last_not_of(" \t\r\n") + 1);

        // 检查是否是整行0x前缀的格式
        if (currentLine.substr(0, 2) == "0x" || currentLine.substr(0, 2) == "0X")
        {
            std::string numberStr = currentLine.substr(2); // 移除0x前缀
            // 确保字符串长度是偶数
            if (numberStr.length() % 2 != 0)
            {
                return false;
            }

            // 每两个字符处理一个字节
            for (size_t i = 0; i < numberStr.length(); i += 2)
            {
                std::string byteStr = numberStr.substr(i, 2);
                uint8_t byte;
                try
                {
                    byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
                    bytes.push_back(byte);
                }
                catch (...)
                {
                    return false;
                }
            }
            continue; // 处理下一行
        }

        // 处理其他格式的行
        std::string cleaned;
        for (size_t i = 0; i < currentLine.length(); ++i)
        {
            char c = currentLine[i];
            // 跳过空白字符
            if (std::isspace(c))
            {
                continue;
            }
            // 跳过单个字节的0x/0X前缀
            if (c == '0' && i + 1 < currentLine.length() && (currentLine[i + 1] == 'x' || currentLine[i + 1] == 'X'))
            {
                ++i; // 跳过'x'
                continue;
            }
            // 保留有效的十六进制字符
            if (std::isxdigit(c))
            {
                cleaned += c;
            }
        }

        // 每两个字符转换为一个字节
        for (size_t i = 0; i < cleaned.length(); i += 2)
        {
            if (i + 1 >= cleaned.length())
            {
                return false; // 不完整的字节
            }

            uint8_t highNibble = 0;
            uint8_t lowNibble = 0;

            // 处理高位
            char highChar = std::toupper(cleaned[i]);
            if (highChar >= '0' && highChar <= '9')
            {
                highNibble = highChar - '0';
            }
            else if (highChar >= 'A' && highChar <= 'F')
            {
                highNibble = highChar - 'A' + 10;
            }
            else
            {
                return false; // 无效字符
            }

            // 处理低位
            char lowChar = std::toupper(cleaned[i + 1]);
            if (lowChar >= '0' && lowChar <= '9')
            {
                lowNibble = lowChar - '0';
            }
            else if (lowChar >= 'A' && lowChar <= 'F')
            {
                lowNibble = lowChar - 'A' + 10;
            }
            else
            {
                return false; // 无效字符
            }

            bytes.push_back((highNibble << 4) | lowNibble);
        }
    }

    return !bytes.empty();
}

// 辅助函数：用于调试输出（可选）
void printBytes(const std::vector<uint8_t> &bytes)
{
    for (uint8_t byte : bytes)
    {
        printf("0x%02X ", byte);
    }
    printf("\n");
}

bool CsEngine::convert(const std::string &archMode, const std::string &hexString, const std::string &startAddr,
                       bool skipDataMode, bool verbose, std::vector<DisasmResult> &results, std::string &errorMsg)
{
    cs_arch arch;
    cs_mode mode;
    csh handle;

    if (!parseArchMode(archMode, arch, mode, errorMsg))
    {
        return false;
    }

    // 初始化反汇编引擎
    if (cs_open(arch, mode, &handle) != CS_ERR_OK)
    {
        errorMsg = "Failed to initialize Capstone engine";
        return false;
    }

    // 设置AT&T语法（如果需要）
    if (archMode.find("att") != std::string::npos)
    {
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    }

    // 启用详细信息模式（如果需要）
    if (verbose)
    {
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    }

    // 启用SKIPDATA模式（如果需要）
    if (skipDataMode)
    {
        cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
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
            cs_close(&handle);
            errorMsg = "ERROR: invalid starting address";
            return false;
        }
    }

    // 解析hex字符串
    std::vector<uint8_t> bytes;
    if (!parseHexString(hexString, bytes))
    {
        cs_close(&handle);
        errorMsg = "ERROR: invalid hex string";
        return false;
    }

    printBytes(bytes);

    // 开始反汇编
    cs_insn *insn;
    size_t count = cs_disasm(handle, bytes.data(), bytes.size(), address, 0, &insn);

    if (count <= 0)
    {
        cs_close(&handle);
        errorMsg = "ERROR: failed to disassemble given code";
        return false;
    }

    // 处理每条指令
    for (size_t i = 0; i < count; i++)
    {
        size_t j;

        DisasmResult result;
        result.address = insn[i].address;

        // 格式化字节码
        std::stringstream ss;
        for (j = 0; j < insn[i].size; j++)
        {
            if (j > 0)
                ss << " ";
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(insn[i].bytes[j]);
        }
        // Align instruction when it varies in size.
        // ex: x86, s390x or compressed riscv
        if (arch == CS_ARCH_RISCV)
        {
            for (; j < 4; j++)
            {
                ss << "   ";
            }
        }
        else if (arch == CS_ARCH_X86)
        {
            for (; j < 16; j++)
            {
                ss << "   ";
            }
        }
        else if (arch == CS_ARCH_SYSZ)
        {
            for (; j < 6; j++)
            {
                ss << "   ";
            }
        }
        result.bytes = ss.str();

        result.mnemonic = insn[i].mnemonic;
        result.operands = insn[i].op_str;

        // 如果启用verbose模式，添加详细信息
        if (verbose)
        {
            std::string detail = print_details(handle, arch, mode, &insn[i]);
            result.detail = detail.c_str();
            clear_printf_buffer();
        }else{
            result.detail = "";
        }

        results.push_back(result);
    }

    cs_free(insn, count);
    cs_close(&handle);
    return true;
}
