#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <getopt.h>
#include <gelf.h>
#include <libelf.h>

#define ABITAG_NAME   ".note.ABI-tag"
#define SHSTRTAB_NAME ".shstrtab"

typedef struct {
  int fd;         /* file descriptor */
  Elf *e;         /* main elf descriptor */
  int bits;       /* 32-bit or 64-bit */
  GElf_Ehdr ehdr; /* executable header */
} elf_data_t;

typedef struct {
  size_t pidx;    /* index of program header to overwrite */
  GElf_Phdr phdr; /* program header to overwrite */
  size_t sidx;    /* index of section header to overwrite */
  Elf_Scn *scn;   /* section to overwrite */
  GElf_Shdr shdr; /* section header to overwrite */
  off_t shstroff; /* offset to section name to overwrite */
  char *code;     /* code to inject */
  size_t len;     /* number of code bytes */
  long entry;     /* code buffer offset to entry point (-1 for none) */
  off_t off;      /* file offset to injected code */
  size_t secaddr; /* section address for injected code */
  char *secname;  /* section name for injected code */
} inject_data_t;


int
write_code(elf_data_t *elf, inject_data_t *inject)
{
  off_t off;
  size_t n;

  off = lseek(elf->fd, 0, SEEK_END);
  if(off < 0) {
    fprintf(stderr, "lseek failed\n");
    return -1;
  }

  n = write(elf->fd, inject->code, inject->len);
  if(n != inject->len) {
    fprintf(stderr, "Failed to inject code bytes\n");
    return -1;
  }
  inject->off = off;

  return 0;
}


int
write_ehdr(elf_data_t *elf)
{
  off_t off;
  size_t n, ehdr_size;
  void *ehdr_buf;

  if(!gelf_update_ehdr(elf->e, &elf->ehdr)) {
    fprintf(stderr, "Failed to update executable header\n");
    return -1;
  }

  if(elf->bits == 32) {
    ehdr_buf = elf32_getehdr(elf->e);
    ehdr_size = sizeof(Elf32_Ehdr);
  } else {
    ehdr_buf = elf64_getehdr(elf->e);
    ehdr_size = sizeof(Elf64_Ehdr);
  }

  if(!ehdr_buf) {
    fprintf(stderr, "Failed to get executable header\n");
    return -1;
  }

  off = lseek(elf->fd, 0, SEEK_SET);
  if(off < 0) {
    fprintf(stderr, "lseek failed\n");
    return -1;
  }

  n = write(elf->fd, ehdr_buf, ehdr_size);
  if(n != ehdr_size) {
    fprintf(stderr, "Failed to write executable header\n");
    return -1;
  }

  return 0;
}


int
write_phdr(elf_data_t *elf, inject_data_t *inject)
{
  off_t off;
  size_t n, phdr_size;
  Elf32_Phdr *phdr_list32;
  Elf64_Phdr *phdr_list64;
  void *phdr_buf;

  if(!gelf_update_phdr(elf->e, inject->pidx, &inject->phdr)) {
    fprintf(stderr, "Failed to update program header\n");
    return -1;
  }

  phdr_buf = NULL;
  if(elf->bits == 32) {
    phdr_list32 = elf32_getphdr(elf->e);
    if(phdr_list32) {
      phdr_buf = &phdr_list32[inject->pidx];
      phdr_size = sizeof(Elf32_Phdr);
    }
  } else {
    phdr_list64 = elf64_getphdr(elf->e);
    if(phdr_list64) {
      phdr_buf = &phdr_list64[inject->pidx];
      phdr_size = sizeof(Elf64_Phdr);
    }
  }
  if(!phdr_buf) {
    fprintf(stderr, "Failed to get program header\n");
    return -1;
  }

  off = lseek(elf->fd, elf->ehdr.e_phoff + inject->pidx*elf->ehdr.e_phentsize, SEEK_SET);
  if(off < 0) {
    fprintf(stderr, "lseek failed\n");
    return -1;
  }

  n = write(elf->fd, phdr_buf, phdr_size);
  if(n != phdr_size) {
    fprintf(stderr, "Failed to write program header\n");
    return -1;
  }

  return 0;
}


int
write_shdr(elf_data_t *elf, Elf_Scn *scn, GElf_Shdr *shdr, size_t sidx)
{
  off_t off;
  size_t n, shdr_size;
  void *shdr_buf;

  if(!gelf_update_shdr(scn, shdr)) {
    fprintf(stderr, "Failed to update section header\n");
    return -1;
  }

  if(elf->bits == 32) {
    shdr_buf = elf32_getshdr(scn);
    shdr_size = sizeof(Elf32_Shdr);
  } else {
    shdr_buf = elf64_getshdr(scn);
    shdr_size = sizeof(Elf64_Shdr);
  }

  if(!shdr_buf) {
    fprintf(stderr, "Failed to get section header\n");
    return -1;
  }

  off = lseek(elf->fd, elf->ehdr.e_shoff + sidx*elf->ehdr.e_shentsize, SEEK_SET);
  if(off < 0) {
    fprintf(stderr, "lseek failed\n");
    return -1;
  }
    
  n = write(elf->fd, shdr_buf, shdr_size);
  if(n != shdr_size) {
    fprintf(stderr, "Failed to write section header\n");
    return -1;
  }

  return 0;
}


int
reorder_shdrs(elf_data_t *elf, inject_data_t *inject)
{
  int direction, skip;
  size_t i;
  Elf_Scn *scn;
  GElf_Shdr shdr;

  direction = 0;

  scn = elf_getscn(elf->e, inject->sidx - 1);
  if(scn && !gelf_getshdr(scn, &shdr)) {
    fprintf(stderr, "Failed to get section header\n");
    return -1;
  }

  if(scn && shdr.sh_addr > inject->shdr.sh_addr) {
    /* Injected section header must be moved left */
    direction = -1;
  }

  scn = elf_getscn(elf->e, inject->sidx + 1);
  if(scn && !gelf_getshdr(scn, &shdr)) {
    fprintf(stderr, "Failed to get section header\n");
    return -1;
  }

  if(scn && shdr.sh_addr < inject->shdr.sh_addr) {
    /* Injected section header must be moved right */
    direction = 1;
  }

  if(direction == 0) {
    /* Section headers are already in order */
    return 0;
  }

  i = inject->sidx;

  /* Order section headers by increasing address */
  skip = 0;
  for(scn = elf_getscn(elf->e, inject->sidx + direction); 
      scn != NULL;
      scn = elf_getscn(elf->e, inject->sidx + direction + skip)) {

    if(!gelf_getshdr(scn, &shdr)) {
      fprintf(stderr, "Failed to get section header\n");
      return -1;
    }

    if((direction < 0 && shdr.sh_addr <= inject->shdr.sh_addr)
       || (direction > 0 && shdr.sh_addr >= inject->shdr.sh_addr)) {
      /* The order is okay from this point on */
      break;
    }

    /* Only reorder code section headers */
    if(shdr.sh_type != SHT_PROGBITS) {
      skip += direction;
      continue;
    }

    /* Swap the injected shdr with its neighbor PROGBITS header */
    if(write_shdr(elf, scn, &inject->shdr, elf_ndxscn(scn)) < 0) {
      return -1;
    }

    if(write_shdr(elf, inject->scn, &shdr, inject->sidx) < 0) {
      return -1;
    }

    inject->sidx += direction + skip;
    inject->scn = elf_getscn(elf->e, inject->sidx);
    skip = 0;
  }

  return 0;
}


int
write_secname(elf_data_t *elf, inject_data_t *inject)
{
  off_t off;
  size_t n;

  off = lseek(elf->fd, inject->shstroff, SEEK_SET);
  if(off < 0) {
    fprintf(stderr, "lseek failed\n");
    return -1;
  }
  
  n = write(elf->fd, inject->secname, strlen(inject->secname));
  if(n != strlen(inject->secname)) {
    fprintf(stderr, "Failed to write section name\n");
    return -1;
  }

  n = strlen(ABITAG_NAME) - strlen(inject->secname);
  while(n > 0) {
    if(!write(elf->fd, "\0", 1)) {
      fprintf(stderr, "Failed to write section name\n");
      return -1;
    }
    n--;
  }

  return 0;
}


int
find_rewritable_segment(elf_data_t *elf, inject_data_t *inject)
{
  int ret;
  size_t i, n;

  ret = elf_getphdrnum(elf->e, &n);
  if(ret != 0) {
    fprintf(stderr, "Cannot find any program headers\n");
    return -1;
  }

  for(i = 0; i < n; i++) {
    if(!gelf_getphdr(elf->e, i, &inject->phdr)) {
      fprintf(stderr, "Failed to get program header\n");
      return -1;
    }

    switch(inject->phdr.p_type) {
    case PT_NOTE:
      inject->pidx = i;
      return 0;
    default:
      break;
    }
  }

  fprintf(stderr, "Cannot find segment to rewrite\n");
  return -1;
}


int
rewrite_code_segment(elf_data_t *elf, inject_data_t *inject)
{
  inject->phdr.p_type   = PT_LOAD;         /* type */
  inject->phdr.p_offset = inject->off;     /* file offset to start of segment */
  inject->phdr.p_vaddr  = inject->secaddr; /* virtual address to load segment at */
  inject->phdr.p_paddr  = inject->secaddr; /* physical address to load segment at */
  inject->phdr.p_filesz = inject->len;     /* byte size in file */
  inject->phdr.p_memsz  = inject->len;     /* byte size in memory */
  inject->phdr.p_flags  = PF_R | PF_X;     /* flags */
  inject->phdr.p_align  = 0x1000;          /* alignment in memory and file */

  if(write_phdr(elf, inject) < 0) {
    return -1;
  }

  return 0;
}


int
rewrite_code_section(elf_data_t *elf, inject_data_t *inject)
{
  Elf_Scn *scn;
  GElf_Shdr shdr;
  char *s;
  size_t shstrndx;

  if(elf_getshdrstrndx(elf->e, &shstrndx) < 0) {
    fprintf(stderr, "Failed to get string table section index\n");
    return -1;
  }

  scn = NULL;
  while((scn = elf_nextscn(elf->e, scn))) {
    if(!gelf_getshdr(scn, &shdr)) {
      fprintf(stderr, "Failed to get section header\n");
      return -1;
    }
    s = elf_strptr(elf->e, shstrndx, shdr.sh_name);
    if(!s) {
      fprintf(stderr, "Failed to get section name\n");
      return -1;
    }

    if(!strcmp(s, ABITAG_NAME)) {
      shdr.sh_name      = shdr.sh_name;              /* offset into string table */
      shdr.sh_type      = SHT_PROGBITS;              /* type */
      shdr.sh_flags     = SHF_ALLOC | SHF_EXECINSTR; /* flags */
      shdr.sh_addr      = inject->secaddr;           /* address to load section at */
      shdr.sh_offset    = inject->off;               /* file offset to start of section */
      shdr.sh_size      = inject->len;               /* size in bytes */
      shdr.sh_link      = 0;                         /* not used for code section */
      shdr.sh_info      = 0;                         /* not used for code section */
      shdr.sh_addralign = 16;                        /* memory alignment */
      shdr.sh_entsize   = 0;                         /* not used for code section */

      inject->sidx = elf_ndxscn(scn);
      inject->scn = scn;
      memcpy(&inject->shdr, &shdr, sizeof(shdr));

      if(write_shdr(elf, scn, &shdr, elf_ndxscn(scn)) < 0) {
        return -1;
      }

      if(reorder_shdrs(elf, inject) < 0) {
        return -1;
      }

      break;
    }
  }
  if(!scn) {
    fprintf(stderr, "Cannot find section to rewrite\n");
    return -1;
  }

  return 0;
}


int
rewrite_section_name(elf_data_t *elf, inject_data_t *inject)
{
  Elf_Scn *scn;
  GElf_Shdr shdr;
  char *s;
  size_t shstrndx, stroff, strbase;

  if(strlen(inject->secname) > strlen(ABITAG_NAME)) {
    fprintf(stderr, "Section name too long\n");
    return -1;
  }

  if(elf_getshdrstrndx(elf->e, &shstrndx) < 0) {
    fprintf(stderr, "Failed to get string table section index\n");
    return -1;
  }

  stroff = 0;
  strbase = 0;
  scn = NULL;
  while((scn = elf_nextscn(elf->e, scn))) {
    if(!gelf_getshdr(scn, &shdr)) {
      fprintf(stderr, "Failed to get section header\n");
      return -1;
    }
    s = elf_strptr(elf->e, shstrndx, shdr.sh_name);
    if(!s) {
      fprintf(stderr, "Failed to get section name\n");
      return -1;
    }

    if(!strcmp(s, ABITAG_NAME)) {
      stroff = shdr.sh_name;    /* offset into shstrtab */
    } else if(!strcmp(s, SHSTRTAB_NAME)) {
      strbase = shdr.sh_offset; /* offset to start of shstrtab */
    }
  }

  if(stroff == 0) {
    fprintf(stderr, "Cannot find shstrtab entry for injected section\n");
    return -1;
  } else if(strbase == 0) {
    fprintf(stderr, "Cannot find shstrtab\n");
    return -1;
  }

  inject->shstroff = strbase + stroff;

  if(write_secname(elf, inject) < 0) {
    return -1;
  }

  return 0;
}


int
rewrite_entry_point(elf_data_t *elf, inject_data_t *inject)
{
  elf->ehdr.e_entry = inject->phdr.p_vaddr + inject->entry;
  return write_ehdr(elf);
}


int
inject_code(int fd, inject_data_t *inject)
{
  elf_data_t elf;
  int ret;
  size_t n;

  elf.fd = fd;
  elf.e  = NULL;

  if(elf_version(EV_CURRENT) == EV_NONE) {
    fprintf(stderr, "Failed to initialize libelf\n");
    goto fail;
  }

  /* Use libelf to read the file, but do writes manually */
  elf.e = elf_begin(elf.fd, ELF_C_READ, NULL);
  if(!elf.e) {
    fprintf(stderr, "Failed to open ELF file\n");
    goto fail;
  }

  if(elf_kind(elf.e) != ELF_K_ELF) {
    fprintf(stderr, "Not an ELF executable\n");
    goto fail;
  }

  ret = gelf_getclass(elf.e);
  switch(ret) {
  case ELFCLASSNONE:
    fprintf(stderr, "Unknown ELF class\n");
    goto fail;
  case ELFCLASS32:
    elf.bits = 32;
    break;
  default:
    elf.bits = 64;
    break;
  }

  if(!gelf_getehdr(elf.e, &elf.ehdr)) {
    fprintf(stderr, "Failed to get executable header\n");
    goto fail;
  }

  /* Find a rewritable program header */
  if(find_rewritable_segment(&elf, inject) < 0) {
    goto fail;
  }

  /* Write the injected code to the binary */
  if(write_code(&elf, inject) < 0) {
    goto fail;
  }

  /* Align code address so it's congruent to the file offset modulo 4096 */
  n = (inject->off % 4096) - (inject->secaddr % 4096);
  inject->secaddr += n;

  /* Rewrite a section for the injected code */
  if((rewrite_code_section(&elf, inject) < 0)
      || (rewrite_section_name(&elf, inject) < 0)) {
    goto fail;
  }

  /* Rewrite a segment for the added code section */
  if(rewrite_code_segment(&elf, inject) < 0) {
    goto fail;
  }

  /* Rewrite entry point if requested */
  if((inject->entry >= 0) && (rewrite_entry_point(&elf, inject) < 0)) {
    goto fail;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(elf.e) {
    elf_end(elf.e);
  }

  return ret;
}


int
main(int argc, char *argv[])
{
  FILE *inject_f;
  int elf_fd, ret;
  size_t len, secaddr;
  long entry;
  char *elf_fname, *inject_fname, *secname, *code;
  inject_data_t inject;

  if(argc != 6) {
    printf("Usage: %s <elf> <inject> <name> <addr> <entry>\n\n", argv[0]);
    printf("Inject the file <inject> into the given <elf>, using\n");
    printf("the given <name> and base <addr>. You can optionally specify\n");
    printf("an offset to a new <entry> point (-1 if none)\n");
    return 1;
  }

  elf_fname    = argv[1];
  inject_fname = argv[2];
  secname      = argv[3];
  secaddr      = strtoul(argv[4], NULL, 0);
  entry        = strtol(argv[5], NULL, 0);

  inject_f = fopen(inject_fname, "r");
  if(!inject_f) {
    fprintf(stderr, "Failed to open \"%s\"\n", inject_fname);
    return 1;
  }

  fseek(inject_f, 0, SEEK_END);
  len = ftell(inject_f);
  fseek(inject_f, 0, SEEK_SET);

  code = malloc(len);
  if(!code) {
    fprintf(stderr, "Failed to alloc code buffer\n");
    fclose(inject_f);
    return 1;
  }
  if(fread(code, 1, len, inject_f) != len) {
    fprintf(stderr, "Failed to read inject file\n");
    return 1;
  }
  fclose(inject_f);

  elf_fd = open(elf_fname, O_RDWR);
  if(elf_fd < 0) {
    fprintf(stderr, "Failed to open \"%s\"\n", elf_fname);
    free(code);
    return 1;
  }

  inject.code    = code;
  inject.len     = len;
  inject.entry   = entry;
  inject.secname = secname;
  inject.secaddr = secaddr;

  ret = 0;
  ret = inject_code(elf_fd, &inject);

  free(code);
  close(elf_fd);

  return ret;
}

