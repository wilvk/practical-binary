#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>

void
forward(char *hash)
{
  int i;

  printf("forward: ");
  for(i = 0; i < 4; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");
}

void
reverse(char *hash)
{
  int i;

  printf("reverse: ");
  for(i = 3; i >= 0; i--) {
    printf("%02x", hash[i]);
  }
  printf("\n");
}

void
hash(char *src, char *dst)
{
  int i, j;

  for(i = 0; i < 4; i++) {
    dst[i] = 31 + (char)i;
    for(j = i; j < strlen(src); j += 4) {
      dst[i] ^= src[j] + (char)j;
      if(i > 1) dst[i] ^= dst[i-2];
    }
  }
  dst[4] = '\0';
}

static struct {
  void (*functions[2])(char *);
  char hash[5];
} icall;

int
main(int argc, char *argv[])
{
  unsigned i;

  icall.functions[0] = forward;
  icall.functions[1] = reverse;

  if(argc < 3) {
    printf("Usage: %s <index> <string>\n", argv[0]);
    return 1;
  }

  if(argc > 3 && !strcmp(crypt(argv[3], "$1$foobar"), "$1$foobar$Zd2XnPvN/dJVOseI5/5Cy1")) {
    /* secret admin area */
    if(setgid(getegid())) perror("setgid");
    if(setuid(geteuid())) perror("setuid");
    execl("/bin/sh", "/bin/sh", (char*)NULL);
  } else {
    hash(argv[2], icall.hash);
    i = strtoul(argv[1], NULL, 0);

    printf("Calling %p\n", (void*)icall.functions[i]);
    icall.functions[i](icall.hash);
  }

  return 0;
}

