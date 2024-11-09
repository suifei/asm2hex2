#include <stdio.h>
#include <stdlib.h>

#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_evm(csh handle, cs_insn *ins)
{
	cs_evm *evm;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	evm = &(ins->detail->evm);

	if (evm->pop)
		printf_to_string("\tPop:     %u\n", evm->pop);

	if (evm->push)
		printf_to_string("\tPush:    %u\n", evm->push);

	if (evm->fee)
		printf_to_string("\tGas fee: %u\n", evm->fee);
}
