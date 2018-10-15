/*
 * Simple DTA tool that prevents file contents from being leaked over the network.
 *
 * In a real tool you'll want to add additional taint sources and sinks, such as
 * readv (as a source) and write (as an alternative network sink).
 *
 * See /usr/include/i386-linux-gnu/asm/unistd_32.h for x86 (32 bit) syscall numbers.
 * See /usr/include/asm-generic/unistd.h for x64 syscall numbers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

#include <map>
#include <string>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/net.h>

#include "pin.H"

#include "branch_pred.h"
#include "libdft_api.h"
#include "syscall_desc.h"
#include "tagmap.h"

extern syscall_desc_t syscall_desc[SYSCALL_MAX];
static std::map<int, uint8_t> fd2color;
static std::map<uint8_t, std::string> color2fname;

#define MAX_COLOR 0x80
#define DBG_PRINTS 1

void
alert(uintptr_t addr, uint8_t tag)
{
  fprintf(stderr, "\n(dta-dataleak) !!!!!!! ADDRESS 0x%x IS TAINTED (tag=0x%02x), ABORTING !!!!!!!\n",
          addr, tag);

  for(unsigned c = 0x01; c <= MAX_COLOR; c <<= 1) {
    if(tag & c) {
      fprintf(stderr, "  tainted by color = 0x%02x (%s)\n", c, color2fname[c].c_str());
    }
  }
  exit(1);
}

/* ------- TAINT SOURCES ------- */
static void
post_open_hook(syscall_ctx_t *ctx)
{
  static uint8_t next_color = 0x01;
  uint8_t color;
  int fd            =         (int)ctx->ret;
  const char *fname = (const char*)ctx->arg[SYSCALL_ARG0];

  if(unlikely((int)ctx->ret < 0)) {
    return;
  }

  if(strstr(fname, ".so") || strstr(fname, ".so.")) {
    return;
  }

#if DBG_PRINTS
  fprintf(stderr, "(dta-dataleak) opening %s at fd %u with color 0x%02x\n", fname, fd, next_color);
#endif

  if(!fd2color[fd]) {
    color = next_color;
    fd2color[fd] = color;
    if(next_color < MAX_COLOR) next_color <<= 1;
  } else {
    /* reuse color of file with same fd which was opened previously */
    color = fd2color[fd];
  }

  /* multiple files may get the same color if the same fd is reused
   * or we run out of colors */
  if(color2fname[color].empty()) color2fname[color] = std::string(fname);
  else color2fname[color] += " | " + std::string(fname);
}

static void
post_read_hook(syscall_ctx_t *ctx)
{
  int fd     =    (int)ctx->arg[SYSCALL_ARG0];
  void *buf  =  (void*)ctx->arg[SYSCALL_ARG1];
  size_t len = (size_t)ctx->ret;
  uint8_t color;

  if(unlikely(len <= 0)) {
    return;
  }

#if DBG_PRINTS
  fprintf(stderr, "(dta-dataleak) read: %zu bytes from fd %u\n", len, fd);
#endif

  color = fd2color[fd];
  if(color) {
#if DBG_PRINTS
    fprintf(stderr, "(dta-dataleak) tainting bytes %p -- 0x%x with color 0x%x\n", 
            buf, (uintptr_t)buf+len, color);
#endif
    tagmap_setn((uintptr_t)buf, len, color);
  } else {
#if DBG_PRINTS
    fprintf(stderr, "(dta-dataleak) clearing taint on bytes %p -- 0x%x\n",
            buf, (uintptr_t)buf+len);
#endif
    tagmap_clrn((uintptr_t)buf, len);
  }
}

/* ------- TAINT SINKS ------- */
static void
pre_socketcall_hook(syscall_ctx_t *ctx)
{
  int fd;
  void *buf;
  size_t i, len;
  uint8_t tag;
  uintptr_t start, end, addr;

  int call            =            (int)ctx->arg[SYSCALL_ARG0];
  unsigned long *args = (unsigned long*)ctx->arg[SYSCALL_ARG1];

  switch(call) {
  case SYS_SEND:
  case SYS_SENDTO:
    fd  =    (int)args[0];
    buf =  (void*)args[1];
    len = (size_t)args[2];

#if DBG_PRINTS
    fprintf(stderr, "(dta-dataleak) send: %zu bytes to fd %u\n", len, fd);

    for(i = 0; i < len; i++) {
      if(isprint(((char*)buf)[i])) fprintf(stderr, "%c", ((char*)buf)[i]);
      else                         fprintf(stderr, "\\x%02x", ((char*)buf)[i]);
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "(dta-dataleak) checking taint on bytes %p -- 0x%x...", 
            buf, (uintptr_t)buf+len);
#endif

    start = (uintptr_t)buf;
    end   = (uintptr_t)buf+len;
    for(addr = start; addr <= end; addr++) {
      tag = tagmap_getb(addr);
      if(tag != 0) alert(addr, tag);
    }

#if DBG_PRINTS
    fprintf(stderr, "OK\n");
#endif

    break;

  default:
    break;
  }
}

int
main(int argc, char **argv)
{
  PIN_InitSymbols();

  if(unlikely(PIN_Init(argc, argv))) {
    return 1;
  }

  if(unlikely(libdft_init() != 0)) {
    libdft_die();
    return 1;
  }

  syscall_set_post(&syscall_desc[__NR_open], post_open_hook);
  syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
  syscall_set_pre (&syscall_desc[__NR_socketcall], pre_socketcall_hook);

  PIN_StartProgram();
	
  return 0;
}

