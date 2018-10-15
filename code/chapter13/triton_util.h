#ifndef TRITON_UTIL_H
#define TRITON_UTIL_H

#include <stdint.h>

#include <map>

#include <triton/api.hpp>

triton::arch::registers_e get_triton_regnum(char *regname);

int parse_sym_config(
  const char *fname, 
  std::map<triton::arch::registers_e, uint64_t> *regs, 
  std::map<uint64_t, uint8_t> *mem,
  std::vector<triton::arch::registers_e> *symregs = NULL,
  std::vector<uint64_t> *symmem = NULL
);

#endif /* TRITON_UTIL_H */
