/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#include <stdio.h>

#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_sparc(csh handle, cs_insn *ins)
{
	cs_sparc *sparc;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	sparc = &(ins->detail->sparc);
	if (sparc->op_count)
		printf_to_string("\top_count: %u\n", sparc->op_count);

	for (i = 0; i < sparc->op_count; i++) {
		cs_sparc_op *op = &(sparc->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case SPARC_OP_REG:
				printf_to_string("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case SPARC_OP_IMM:
				printf_to_string("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
			case SPARC_OP_MEM:
				printf_to_string("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != X86_REG_INVALID)
					printf_to_string("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					printf_to_string("\t\t\toperands[%u].mem.index: REG = %s\n",
							i, cs_reg_name(handle, op->mem.index));
				if (op->mem.disp != 0)
					printf_to_string("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

				break;
		}
	}

	if (sparc->cc != 0)
		printf_to_string("\tCode condition: %u\n", sparc->cc);

	if (sparc->hint != 0)
		printf_to_string("\tHint code: %u\n", sparc->hint);
}
