/* Find ROP gadgets in a given binary using Capstone. */

#include <stdio.h>
#include <map>
#include <vector>
#include <string>

#include <capstone/capstone.h>

#include "../inc/loader.h"

bool
is_cs_cflow_group(uint8_t g)
{
  return (g == CS_GRP_JUMP) || (g == CS_GRP_CALL) 
          || (g == CS_GRP_RET) || (g == CS_GRP_IRET);
}

bool
is_cs_cflow_ins(cs_insn *ins)
{
  for(size_t i = 0; i < ins->detail->groups_count; i++) {
    if(is_cs_cflow_group(ins->detail->groups[i])) {
      return true;
    }
  }

  return false;
}

bool
is_cs_ret_ins(cs_insn *ins)
{
  switch(ins->id) {
  case X86_INS_RET:
    return true;
  default:
    return false;
  }
}

int
find_gadgets_at_root(Section *text, uint64_t root, 
                     std::map<std::string, std::vector<uint64_t> > *gadgets, 
                     csh dis)
{
  size_t n, len;
  const uint8_t *pc;
  uint64_t offset, addr;
  std::string gadget_str;
  cs_insn *cs_ins; 

  const size_t max_gadget_len    = 5; /* instructions */
  const size_t x86_max_ins_bytes = 15;
  const uint64_t root_offset     = max_gadget_len*x86_max_ins_bytes;

  cs_ins = cs_malloc(dis);
  if(!cs_ins) {
    fprintf(stderr, "Out of memory\n");
    return -1;
  }

  for(uint64_t a = root-1; 
               a >= root-root_offset && a >= 0;
               a--) {
    addr   = a;
    offset = addr - text->vma;
    pc     = text->bytes + offset;
    n      = text->size - offset;
    len    = 0;
    gadget_str = "";
    while(cs_disasm_iter(dis, &pc, &n, &addr, cs_ins)) {
      if(cs_ins->id == X86_INS_INVALID || cs_ins->size == 0) {
        break;
      } else if(cs_ins->address > root) {
        break;
      } else if(is_cs_cflow_ins(cs_ins) && !is_cs_ret_ins(cs_ins)) {
        break;
      } else if(++len > max_gadget_len) {
        break;
      }

      gadget_str += std::string(cs_ins->mnemonic) 
                    + " " + std::string(cs_ins->op_str);

      if(cs_ins->address == root) {
        (*gadgets)[gadget_str].push_back(a);
        break;
      }

      gadget_str += "; ";
    }
  }

  cs_free(cs_ins, 1);

  return 0;
}

int
find_gadgets(Binary *bin)
{
  csh dis;
  Section *text;
  std::map<std::string, std::vector<uint64_t> > gadgets;
 
  const uint8_t x86_opc_ret = 0xc3;

  text = bin->get_text_section();
  if(!text) {
    fprintf(stderr, "Nothing to disassemble\n");
    return 0;
  }

  if(cs_open(CS_ARCH_X86, CS_MODE_64, &dis) != CS_ERR_OK) {
    fprintf(stderr, "Failed to open Capstone\n");
    return -1;
  }
  cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);

  for(size_t i = 0; i < text->size; i++) {
    if(text->bytes[i] == x86_opc_ret) {
      if(find_gadgets_at_root(text, text->vma+i, &gadgets, dis) < 0) {
        break;
      }
    }
  }

  for(auto &kv: gadgets) {
    printf("%s\t[ ", kv.first.c_str());
    for(auto addr: kv.second) {
      printf("0x%jx ", addr);
    }
    printf("]\n");
  }

  cs_close(&dis);

  return 0;
}

int
main(int argc, char *argv[])
{
  Binary bin;
  std::string fname;

  if(argc < 2) {
    printf("Usage: %s <binary>\n", argv[0]);
    return 1;
  }

  fname.assign(argv[1]);
  if(load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) {
    return 1;
  }

  if(find_gadgets(&bin) < 0) {
    return 1;
  }

  unload_binary(&bin);

  return 0;
}

