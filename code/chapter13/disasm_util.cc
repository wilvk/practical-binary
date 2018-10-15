#include <stdint.h>
#include <string.h>

#include <capstone/capstone.h>

#include "disasm_util.h"
#include "../inc/loader.h"

static csh dis;

static int
init_capstone(Binary *bin)
{
  cs_arch arch;
  cs_mode mode;

  if(bin->arch == Binary::BinaryArch::ARCH_X86) {
    arch = CS_ARCH_X86;
    switch(bin->bits) {
    case 32:
      mode = CS_MODE_32;
      break;
    case 64:
      mode = CS_MODE_64;
      break;
    default:
      fprintf(stderr, "Unsupported bit width for x86: %u bits\n", bin->bits);
      return -1;
    }
  } else {
    fprintf(stderr, "Unsupported architecture\n");
    return -1;
  }

  if(cs_open(arch, mode, &dis) != CS_ERR_OK) {
    fprintf(stderr, "Failed to open Capstone\n");
    return -1;
  }

  return 0;
}

int
disasm_one(Section *sec, uint64_t addr, char *mnemonic, char *op_str)
{
  cs_insn *insn;
  int len;
  size_t n;
  uint64_t off;
  const uint8_t *pc;
  static bool capstone_inited = false;

  if(!capstone_inited) {
    if(init_capstone(sec->binary) < 0) return -1;
    capstone_inited = true;
  }

  if(!sec->contains(addr)) {
    fprintf(stderr, "Section %s does not contain address 0x%jx\n", sec->name.c_str(), addr);
    return -1;
  }

  insn = cs_malloc(dis);
  if(!insn) {
    fprintf(stderr, "Out of memory\n");
    return -1;
  }

  off = addr - sec->vma;
  pc  = sec->bytes+off;
  n   = sec->size-off;
  if(!cs_disasm_iter(dis, &pc, &n, &addr, insn)) {
    fprintf(stderr, "Disassembly error: %s\n", cs_strerror(cs_errno(dis)));
    return -1;
  }

  if(mnemonic) {
    strcpy(mnemonic, insn->mnemonic);
  }
  if(op_str) {
    strcpy(op_str, insn->op_str);
  }
  len = (int)insn->size;

  cs_free(insn, 1);

  return len;
}

