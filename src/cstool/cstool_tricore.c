#include <stdio.h>
#include <stdlib.h>

#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_tricore(csh handle, cs_insn *ins)
{
	cs_tricore *tricore;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	tricore = &(ins->detail->tricore);

	if (tricore->op_count)
		printf_to_string("\top_count: %u\n", tricore->op_count);

	for (i = 0; i < tricore->op_count; i++) {
		cs_tricore_op *op = &(tricore->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case TRICORE_OP_REG:
			printf_to_string("\t\toperands[%u].type: REG = %s\n", i,
			       cs_reg_name(handle, op->reg));
			break;
		case TRICORE_OP_IMM:
			printf_to_string("\t\toperands[%u].type: IMM = 0x%x\n", i,
			       op->imm);
			break;
		case TRICORE_OP_MEM:
			printf_to_string("\t\toperands[%u].type: MEM\n"
			       "\t\t\t.mem.base: REG = %s\n"
			       "\t\t\t.mem.disp: 0x%x\n",
			       i, cs_reg_name(handle, op->mem.base),
			       op->mem.disp);
			break;
		}

		switch (op->access) {
		default:
			break;
		case CS_AC_READ:
			printf_to_string("\t\t\t.access: READ\n");
			break;
		case CS_AC_WRITE:
			printf_to_string("\t\t\t.access: WRITE\n");
			break;
		case CS_AC_READ | CS_AC_WRITE:
			printf_to_string("\t\t\t.access: READ | WRITE\n");
			break;
		}
	}
	// Print out all registers accessed by this instruction (either implicit or
	// explicit)
	if (!cs_regs_access(handle, ins, regs_read, &regs_read_count,
			    regs_write, &regs_write_count)) {
		if (regs_read_count) {
			printf_to_string("\tRegisters read:");
			for (i = 0; i < regs_read_count; i++) {
				printf_to_string(" %s",
				       cs_reg_name(handle, regs_read[i]));
			}
			printf_to_string("\n");
		}

		if (regs_write_count) {
			printf_to_string("\tRegisters modified:");
			for (i = 0; i < regs_write_count; i++) {
				printf_to_string(" %s",
				       cs_reg_name(handle, regs_write[i]));
			}
			printf_to_string("\n");
		}
	}

	if (tricore->update_flags)
		printf_to_string("\tUpdate-flags: True\n");
}
