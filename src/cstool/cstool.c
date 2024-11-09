/* Tang Yuhang <tyh000011112222@gmail.com> 2016 */
/* pancake <pancake@nopcode.org> 2017 */

#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <capstone/capstone.h>
#include "cstool.h"

const char *get_detail()
{
	const char *result = get_printf_buffer();
	return result;
}

const char *print_details(csh handle, cs_arch arch, cs_mode md, cs_insn *ins)
{
	printf_to_string("\tID: %u (%s)\n", ins->id, cs_insn_name(handle, ins->id));

	switch (arch)
	{
	case CS_ARCH_X86:
		print_insn_detail_x86(handle, md, ins);
		break;
	case CS_ARCH_ARM:
		print_insn_detail_arm(handle, ins);
		break;
	case CS_ARCH_ARM64:
		print_insn_detail_arm64(handle, ins);
		break;
	case CS_ARCH_MIPS:
		print_insn_detail_mips(handle, ins);
		break;
	case CS_ARCH_PPC:
		print_insn_detail_ppc(handle, ins);
		break;
	case CS_ARCH_SPARC:
		print_insn_detail_sparc(handle, ins);
		break;
	case CS_ARCH_SYSZ:
		print_insn_detail_sysz(handle, ins);
		break;
	case CS_ARCH_XCORE:
		print_insn_detail_xcore(handle, ins);
		break;
	case CS_ARCH_M68K:
		print_insn_detail_m68k(handle, ins);
		break;
	case CS_ARCH_TMS320C64X:
		print_insn_detail_tms320c64x(handle, ins);
		break;
	case CS_ARCH_M680X:
		print_insn_detail_m680x(handle, ins);
		break;
	case CS_ARCH_EVM:
		print_insn_detail_evm(handle, ins);
		break;
	case CS_ARCH_WASM:
		print_insn_detail_wasm(handle, ins);
		break;
	case CS_ARCH_MOS65XX:
		print_insn_detail_mos65xx(handle, ins);
		break;
	case CS_ARCH_BPF:
		print_insn_detail_bpf(handle, ins);
		break;
	case CS_ARCH_RISCV:
		print_insn_detail_riscv(handle, ins);
		break;
	case CS_ARCH_SH:
		print_insn_detail_sh(handle, ins);
		break;
	case CS_ARCH_TRICORE:
		print_insn_detail_tricore(handle, ins);
		break;
	default:
		break;
	}
	if (ins->detail)
	{
		if (ins->detail->groups_count)
		{
			int j;

			printf_to_string("\tGroups: ");
			for (j = 0; j < ins->detail->groups_count; j++)
			{
				printf_to_string("%s ", cs_group_name(handle, ins->detail->groups[j]));
			}
			printf_to_string("\n");
		}
	}
	printf_to_string("\n");

	return get_detail();
}