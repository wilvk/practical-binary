#ifndef DISASM_UTIL_H
#define DISASM_UTIL_H

#include <stdint.h>

#include "../inc/loader.h"

int disasm_one(Section *sec, uint64_t addr, char *mnemonic, char *op_str);

#endif /* DISASM_UTIL_H */
