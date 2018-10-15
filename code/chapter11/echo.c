#include <stdio.h>

int
main(int argc, char *argv[])
{
  unsigned i;

  i = 1;
  while(argv[i]) {
    printf(" %s", argv[i]);
    i++;
  }

  return 0;
}

