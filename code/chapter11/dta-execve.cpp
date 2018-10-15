/*
 * Simple DTA tool that prevents data read from the network (using recv/recvfrom)
 * from influencing execve calls.
 *
 * In a real tool, you'll want to add more taint sources/sinks. For instance, 
 * you'll also want to consider data read from the network using the read
 * syscall. To prevent tainting "innocent" reads, you'll need to figure out 
 * which file descriptors are reading from the network by hooking network calls
 * like accept, and so on.
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

#define DBG_PRINTS 1

void
alert(uintptr_t addr, const char *source, uint8_t tag)
{
  fprintf(stderr, "\n(dta-execve) !!!!!!! ADDRESS 0x%x IS TAINTED (%s, tag=0x%02x), ABORTING !!!!!!!\n",
          addr, source, tag);
  exit(1);
}

void
check_string_taint(const char *str, const char *source)
{
  uint8_t tag;
  uintptr_t start = (uintptr_t)str;
  uintptr_t end   = (uintptr_t)str+strlen(str);

#if DBG_PRINTS
  fprintf(stderr, "(dta-execve) checking taint on bytes 0x%x -- 0x%x (%s)... ",
          start, end, source);
#endif

  for(uintptr_t addr = start; addr <= end; addr++) {
    tag = tagmap_getb(addr);
    if(tag != 0) alert(addr, source, tag);
  }

#if DBG_PRINTS
  fprintf(stderr, "OK\n");
#endif
}

/* ------- TAINT SOURCES ------- */
static void
post_socketcall_hook(syscall_ctx_t *ctx)
{
  int fd;
  void *buf;
  size_t len;

  int call            =            (int)ctx->arg[SYSCALL_ARG0];
  unsigned long *args = (unsigned long*)ctx->arg[SYSCALL_ARG1];

  switch(call) {
  case SYS_RECV:
  case SYS_RECVFROM:
    if(unlikely(ctx->ret <= 0)) {
      return;
    }

    fd  =    (int)args[0];
    buf =  (void*)args[1];
    len = (size_t)ctx->ret;

#if DBG_PRINTS
    fprintf(stderr, "(dta-execve) recv: %zu bytes from fd %u\n", len, fd);

    for(size_t i = 0; i < len; i++) {
      if(isprint(((char*)buf)[i])) fprintf(stderr, "%c", ((char*)buf)[i]);
      else                         fprintf(stderr, "\\x%02x", ((char*)buf)[i]);
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "(dta-execve) tainting bytes %p -- 0x%x with tag 0x%x\n", 
            buf, (uintptr_t)buf+len, 0x01);
#endif

    tagmap_setn((uintptr_t)buf, len, 0x01);

    break;

  default:
    break;
  }
}

/* ------- TAINT SINKS ------- */
static void
pre_execve_hook(syscall_ctx_t *ctx)
{
  const char *filename =  (const char*)ctx->arg[SYSCALL_ARG0];
  char * const *args   = (char* const*)ctx->arg[SYSCALL_ARG1];
  char * const *envp   = (char* const*)ctx->arg[SYSCALL_ARG2];

#if DBG_PRINTS
  fprintf(stderr, "(dta-execve) execve: %s (@%p)\n", filename, filename);
#endif

  check_string_taint(filename, "execve command");
  while(args && *args) {
#if DBG_PRINTS
    fprintf(stderr, "(dta-execve) arg: %s (@%p)\n", *args, *args);
#endif
    check_string_taint(*args, "execve argument");
    args++;
  }
  while(envp && *envp) {
#if DBG_PRINTS
    fprintf(stderr, "(dta-execve) env: %s (@%p)\n", *envp, *envp);
#endif
    check_string_taint(*envp, "execve environment parameter");
    envp++;
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

  syscall_set_post(&syscall_desc[__NR_socketcall], post_socketcall_hook);
  syscall_set_pre (&syscall_desc[__NR_execve], pre_execve_hook);

  PIN_StartProgram();
	
  return 0;
}

