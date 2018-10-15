/*
 * Output the backward slice with respect to the specified register, starting from the
 * given instruction.
 *
 * Based on Triton's backward_slicing.py example (src/examples/python/backward_slicing.py).
 *
 * Uses Triton's symbolic emulation mode.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "../inc/loader.h"
#include "triton_util.h"
#include "disasm_util.h"

#include <string>
#include <map>

#include <triton/api.hpp>
#include <triton/x86Specifications.hpp>

static int
set_triton_arch(Binary &bin, triton::API &api, triton::arch::registers_e &ip)
{
  if(bin.arch != Binary::BinaryArch::ARCH_X86) {
    fprintf(stderr, "Unsupported architecture\n");
    return -1;
  }

  if(bin.bits == 32) {
    api.setArchitecture(triton::arch::ARCH_X86);
    ip = triton::arch::ID_REG_EIP;
  } else if(bin.bits == 64) {
    api.setArchitecture(triton::arch::ARCH_X86_64);
    ip = triton::arch::ID_REG_RIP;
  } else {
    fprintf(stderr, "Unsupported bit width for x86: %u bits\n", bin.bits);
    return -1;
  }

  return 0;
}

static void
print_slice(triton::API &api, Section *sec, uint64_t slice_addr, 
            triton::arch::registers_e reg, const char *regname)
{
  triton::engines::symbolic::SymbolicExpression *regExpr;
  std::map<triton::usize, triton::engines::symbolic::SymbolicExpression*> slice;
  char mnemonic[32], operands[200];

  regExpr = api.getSymbolicRegisters()[reg];
  slice = api.sliceExpressions(regExpr);

  for(auto &kv: slice) {
    printf("%s\n", kv.second->getComment().c_str());
  }

  disasm_one(sec, slice_addr, mnemonic, operands);
  std::string target = mnemonic; target += " "; target += operands;

  printf("(slice for %s @ 0x%jx: %s)\n", regname, slice_addr, target.c_str());
}

int
main(int argc, char *argv[])
{
  Binary bin;
  triton::API api;
  triton::arch::registers_e ip;
  std::map<triton::arch::registers_e, uint64_t> regs;
  std::map<uint64_t, uint8_t> mem;

  if(argc < 6) {
    printf("Usage: %s <binary> <sym-config> <entry> <slice-addr> <reg>\n", argv[0]);
    return 1;
  }

  std::string fname(argv[1]);
  if(load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) return 1;

  if(set_triton_arch(bin, api, ip) < 0) return 1;
  api.enableMode(triton::modes::ALIGNED_MEMORY, true);

  if(parse_sym_config(argv[2], &regs, &mem) < 0) return 1;
  for(auto &kv: regs) {
    triton::arch::Register r = api.getRegister(kv.first);
    api.setConcreteRegisterValue(r, kv.second);
  }
  for(auto &kv: mem) {
    api.setConcreteMemoryValue(kv.first, kv.second);
  }

  uint64_t pc         = strtoul(argv[3], NULL, 0);
  uint64_t slice_addr = strtoul(argv[4], NULL, 0);
  Section *sec = bin.get_text_section();

  while(sec->contains(pc)) {
    char mnemonic[32], operands[200];
    int len = disasm_one(sec, pc, mnemonic, operands);
    if(len <= 0) return 1;

    triton::arch::Instruction insn;
    insn.setOpcode(sec->bytes+(pc-sec->vma), len);
    insn.setAddress(pc);

    api.processing(insn);

    for(auto &se: insn.symbolicExpressions) {
      std::string comment = mnemonic; comment += " "; comment += operands;
      se->setComment(comment);
    }

    if(pc == slice_addr) {
      print_slice(api, sec, slice_addr, get_triton_regnum(argv[5]), argv[5]);
      break;
    }

    pc = (uint64_t)api.getConcreteRegisterValue(api.getRegister(ip));
  }

  unload_binary(&bin);

  return 0;
}

