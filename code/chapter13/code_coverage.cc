/*
 * Symbolically execute up to and including a given jump instruction, and then compute an input
 * to take the branch direction that wasn't taken previously.
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
#include <vector>

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
find_new_input(triton::API &api, Section *sec, uint64_t branch_addr)
{
  triton::ast::AstContext &ast = api.getAstContext();
  triton::ast::AbstractNode *constraint_list = ast.equal(ast.bvtrue(), ast.bvtrue());

  printf("evaluating branch 0x%jx:\n", branch_addr);

  const std::vector<triton::engines::symbolic::PathConstraint> &path_constraints = api.getPathConstraints();
  for(auto &pc: path_constraints) {
    if(!pc.isMultipleBranches()) continue;
    for(auto &branch_constraint: pc.getBranchConstraints()) {
      bool flag         = std::get<0>(branch_constraint);
      uint64_t src_addr = std::get<1>(branch_constraint);
      uint64_t dst_addr = std::get<2>(branch_constraint);
      triton::ast::AbstractNode *constraint = std::get<3>(branch_constraint);

      if(src_addr != branch_addr) {
        /* this is not our target branch, so keep the existing "true" constraint */
        if(flag) {
          constraint_list = ast.land(constraint_list, constraint);
        }
      } else {
        /* this is our target branch, compute new input */
        printf("    0x%jx -> 0x%jx (%staken)\n", src_addr, dst_addr, flag ? "" : "not ");

        if(!flag) {
          printf("    computing new input for 0x%jx -> 0x%jx\n", src_addr, dst_addr);
          constraint_list = ast.land(constraint_list, constraint);
          for(auto &kv: api.getModel(constraint_list)) {
            printf("      SymVar %u (%s) = 0x%jx\n", 
                   kv.first, 
                   api.getSymbolicVariableFromId(kv.first)->getComment().c_str(), 
                   (uint64_t)kv.second.getValue());
          }
        }
      }
    }
  }
}

int
main(int argc, char *argv[])
{
  Binary bin;
  triton::API api;
  triton::arch::registers_e ip;
  std::map<triton::arch::registers_e, uint64_t> regs;
  std::map<uint64_t, uint8_t> mem;
  std::vector<triton::arch::registers_e> symregs;
  std::vector<uint64_t> symmem;

  if(argc < 5) {
    printf("Usage: %s <binary> <sym-config> <entry> <branch-addr>\n", argv[0]);
    return 1;
  }

  std::string fname(argv[1]);
  if(load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) return 1;

  if(set_triton_arch(bin, api, ip) < 0) return 1;
  api.enableMode(triton::modes::ALIGNED_MEMORY, true);
 
  if(parse_sym_config(argv[2], &regs, &mem, &symregs, &symmem) < 0) return 1;
  for(auto &kv: regs) {
    triton::arch::Register r = api.getRegister(kv.first);
    api.setConcreteRegisterValue(r, kv.second);
  }
  for(auto regid: symregs) {
    triton::arch::Register r = api.getRegister(regid);
    api.convertRegisterToSymbolicVariable(r)->setComment(r.getName());
  }
  for(auto &kv: mem) {
    api.setConcreteMemoryValue(kv.first, kv.second);
  }
  for(auto memaddr: symmem) {
    api.convertMemoryToSymbolicVariable(triton::arch::MemoryAccess(memaddr, 1))->setComment(std::to_string(memaddr));
  }

  uint64_t pc          = strtoul(argv[3], NULL, 0);
  uint64_t branch_addr = strtoul(argv[4], NULL, 0);
  Section *sec = bin.get_text_section();

  while(sec->contains(pc)) {
    char mnemonic[32], operands[200];
    int len = disasm_one(sec, pc, mnemonic, operands);
    if(len <= 0) return 1;

    triton::arch::Instruction insn;
    insn.setOpcode(sec->bytes+(pc-sec->vma), len);
    insn.setAddress(pc);

    api.processing(insn);

    if(pc == branch_addr) {
      find_new_input(api, sec, branch_addr);
      break;
    }

    pc = (uint64_t)api.getConcreteRegisterValue(api.getRegister(ip));
  }

  unload_binary(&bin);

  return 0;
}

