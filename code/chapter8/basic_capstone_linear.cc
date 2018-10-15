/* Linearly disassemble a given binary using Capstone. */

#include <stdio.h>
#include <string>

#include <capstone/capstone.h>

#include "../inc/loader.h"

int
disasm(Binary *bin)
{
  csh dis;
  cs_insn *insns;
  Section *text;
  size_t n;
 
  text = bin->get_text_section();
  if(!text) {
    fprintf(stderr, "Nothing to disassemble\n");
    return 0;
  }

  if(cs_open(CS_ARCH_X86, CS_MODE_64, &dis) != CS_ERR_OK) {
    fprintf(stderr, "Failed to open Capstone\n");
    return -1;
  }

  n = cs_disasm(dis, text->bytes, text->size, text->vma, 0, &insns);
  if(n <= 0) {
    fprintf(stderr, "Disassembly error: %s\n", cs_strerror(cs_errno(dis)));
    return -1;
  }

  for(size_t i = 0; i < n; i++) {
    printf("0x%016jx: ", insns[i].address);
    for(size_t j = 0; j < 16; j++) {
      if(j < insns[i].size) printf("%02x ", insns[i].bytes[j]);
      else printf("   ");
    }
    printf("%-12s %s\n", insns[i].mnemonic, insns[i].op_str);
  }
 
  cs_free(insns, n);
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

  if(disasm(&bin) < 0) {
    return 1;
  }

  unload_binary(&bin);

  return 0;
}

