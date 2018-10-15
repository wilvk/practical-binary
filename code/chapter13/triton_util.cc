#include <stdio.h>
#include <stdint.h>

#include <string>
#include <map>

#include <triton/api.hpp>

#include "triton_util.h"

triton::arch::registers_e
get_triton_regnum(char *regname)
{
       if(!strcmp(regname, "al"))  return triton::arch::ID_REG_AL;
  else if(!strcmp(regname, "ah"))  return triton::arch::ID_REG_AH;
  else if(!strcmp(regname, "ax"))  return triton::arch::ID_REG_AX;
  else if(!strcmp(regname, "eax")) return triton::arch::ID_REG_EAX;
  else if(!strcmp(regname, "rax")) return triton::arch::ID_REG_RAX;
  else if(!strcmp(regname, "bl"))  return triton::arch::ID_REG_BL;
  else if(!strcmp(regname, "bh"))  return triton::arch::ID_REG_BH;
  else if(!strcmp(regname, "bx"))  return triton::arch::ID_REG_BX;
  else if(!strcmp(regname, "ebx")) return triton::arch::ID_REG_EBX;
  else if(!strcmp(regname, "rbx")) return triton::arch::ID_REG_RBX;
  else if(!strcmp(regname, "cl"))  return triton::arch::ID_REG_CL;
  else if(!strcmp(regname, "ch"))  return triton::arch::ID_REG_CH;
  else if(!strcmp(regname, "cx"))  return triton::arch::ID_REG_CX;
  else if(!strcmp(regname, "ecx")) return triton::arch::ID_REG_ECX;
  else if(!strcmp(regname, "rcx")) return triton::arch::ID_REG_RCX;
  else if(!strcmp(regname, "dl"))  return triton::arch::ID_REG_DL;
  else if(!strcmp(regname, "dh"))  return triton::arch::ID_REG_DH;
  else if(!strcmp(regname, "dx"))  return triton::arch::ID_REG_DX;
  else if(!strcmp(regname, "edx")) return triton::arch::ID_REG_EDX;
  else if(!strcmp(regname, "rdx")) return triton::arch::ID_REG_RDX;
  else if(!strcmp(regname, "dil")) return triton::arch::ID_REG_DIL;
  else if(!strcmp(regname, "di"))  return triton::arch::ID_REG_DI;
  else if(!strcmp(regname, "edi")) return triton::arch::ID_REG_EDI;
  else if(!strcmp(regname, "rdi")) return triton::arch::ID_REG_RDI;
  else if(!strcmp(regname, "sil")) return triton::arch::ID_REG_SIL;
  else if(!strcmp(regname, "si"))  return triton::arch::ID_REG_SI;
  else if(!strcmp(regname, "esi")) return triton::arch::ID_REG_ESI;
  else if(!strcmp(regname, "rsi")) return triton::arch::ID_REG_RSI;
  else if(!strcmp(regname, "bpl")) return triton::arch::ID_REG_BPL;
  else if(!strcmp(regname, "bp"))  return triton::arch::ID_REG_BP;
  else if(!strcmp(regname, "ebp")) return triton::arch::ID_REG_EBP;
  else if(!strcmp(regname, "rbp")) return triton::arch::ID_REG_RBP;
  else if(!strcmp(regname, "spl")) return triton::arch::ID_REG_SPL;
  else if(!strcmp(regname, "sp"))  return triton::arch::ID_REG_SP;
  else if(!strcmp(regname, "esp")) return triton::arch::ID_REG_ESP;
  else if(!strcmp(regname, "rsp")) return triton::arch::ID_REG_RSP;
  else if(!strcmp(regname, "ip"))  return triton::arch::ID_REG_IP;
  else if(!strcmp(regname, "eip")) return triton::arch::ID_REG_EIP;
  else if(!strcmp(regname, "rip")) return triton::arch::ID_REG_RIP;

  return triton::arch::ID_REG_INVALID;
}

int
parse_sym_config(const char *fname,
                 std::map<triton::arch::registers_e, uint64_t> *regs,
                 std::map<uint64_t, uint8_t> *mem,
                 std::vector<triton::arch::registers_e> *symregs,
                 std::vector<uint64_t> *symmem)
{
  FILE *f;
  char buf[4096], *s, *key, *val;
  uint64_t addr, regval;
  uint8_t memval;
  triton::arch::registers_e triton_reg;

  f = fopen(fname, "r");
  if(!f) {
    fprintf(stderr, "Failed to open file \"%s\"\n", fname);
    return -1;
  }

  while(fgets(buf, sizeof(buf), f)) {
    if((s = strchr(buf, '#')))  s[0] = '\0';
    if((s = strchr(buf, '\n'))) s[0] = '\0';
    if(!(s = strchr(buf, '='))) continue;

    key = buf;
    val = s+1;
    s[0] = '\0';

    if(key[0] == '%') {
      /* key is a register name and val is an unsigned long */
      key++;
      triton_reg = get_triton_regnum(key);
      if(triton_reg == triton::arch::ID_REG_INVALID) {
        fprintf(stderr, "Unrecognized register name \"%s\"\n", key);
        return -1;
      }
      if(val[0] != '$') {
        regval = strtoul(val, NULL, 0);
        (*regs)[triton_reg] = regval;
      } else if(symregs) {
        symregs->push_back(triton_reg);
      }
    } else if(key[0] == '@') {
      /* key is a memory address and val is a uint8_t */
      key++;
      addr   = strtoul(key, NULL, 0);
      if(val[0] != '$') {
        memval = (uint8_t)strtoul(val, NULL, 0);
        (*mem)[addr] = memval;
      } else if(symmem) {
        symmem->push_back(addr);
      }
    }
  }

  fclose(f);

  return 0;
}

