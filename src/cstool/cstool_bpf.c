#include <stdio.h>
#include <inttypes.h>  // 为 PRIx64 宏
#include <capstone/capstone.h>
#include <capstone/platform.h>
#include "cstool.h"

// 改用普通数组初始化方式
static const char* ext_name[] = {
    [0] = NULL,         // BPF_EXT_INVALID
    [1] = "#len"        // BPF_EXT_LEN
};
// static const char * ext_name[] = {
//     [BPF_EXT_LEN] = "#len",
// };
void print_insn_detail_bpf(csh handle, cs_insn *ins)
{
    unsigned i;
    cs_bpf *bpf;
    cs_regs regs_read, regs_write;
    uint8_t regs_read_count, regs_write_count;

    // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
    if (ins->detail == NULL)
        return;

    bpf = &(ins->detail->bpf);

    printf_to_string("\tOperand count: %u\n", bpf->op_count);

    for (i = 0; i < bpf->op_count; i++) {
        cs_bpf_op *op = &(bpf->operands[i]);
        printf_to_string("\t\toperands[%u].type: ", i);
        switch (op->type) {
            case BPF_OP_INVALID:
                printf_to_string("INVALID\n");
                break;
            case BPF_OP_REG:
                printf_to_string("REG = %s\n", cs_reg_name(handle, op->reg));
                break;
            case BPF_OP_IMM:
                printf_to_string("IMM = 0x%" PRIx64 "\n", op->imm);
                break;
            case BPF_OP_OFF:
                printf_to_string("OFF = +0x%x\n", op->off);
                break;
            case BPF_OP_MEM:
                printf_to_string("MEM\n");
                if (op->mem.base != BPF_REG_INVALID)
                    printf_to_string("\t\t\toperands[%u].mem.base: REG = %s\n",
                            i, cs_reg_name(handle, op->mem.base));
                printf_to_string("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
                break;
            case BPF_OP_MMEM:
                printf_to_string("MMEM = M[0x%x]\n", op->mmem);
                break;
            case BPF_OP_MSH:
                printf_to_string("MSH = 4*([0x%x]&0xf)\n", op->msh);
                break;
            case BPF_OP_EXT:
                if (op->ext < sizeof(ext_name)/sizeof(ext_name[0]) && ext_name[op->ext])
                    printf_to_string("EXT = %s\n", ext_name[op->ext]);
                else
                    printf_to_string("EXT = <invalid>\n");
                break;
        }
    }

    /* print all registers that are involved in this instruction */
    if (!cs_regs_access(handle, ins,
            regs_read, &regs_read_count,
            regs_write, &regs_write_count)) {
        if (regs_read_count) {
            printf_to_string("\tRegisters read:");
            for(i = 0; i < regs_read_count; i++) {
                printf_to_string(" %s", cs_reg_name(handle, regs_read[i]));
            }
            printf_to_string("\n");
        }

        if (regs_write_count) {
            printf_to_string("\tRegisters modified:");
            for(i = 0; i < regs_write_count; i++) {
                printf_to_string(" %s", cs_reg_name(handle, regs_write[i]));
            }
            printf_to_string("\n");
        }
    }
}