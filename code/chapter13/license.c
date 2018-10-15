#include <stdio.h>
#include <string.h>

int
check_license(char *serial)
{
  int i;
  unsigned char sum, xor, negxor;

  sum = xor = negxor = 0;
  for(i = 0; i < strlen(serial); i++) {
    sum    +=  serial[i];
    xor    ^=  serial[i];
    negxor ^= ~serial[i];
  }

  printf("sum=0x%02x xor=%02x negxor=%02x\n", sum, xor, negxor);

  return sum == xor == negxor;
}

int
main(int argc, char *argv[])
{
  int i, alnum, ret;
  char *serial;

  if(argc < 2) {
    printf("Usage: %s <serial>\n", argv[0]);
    return 1;
  }
  serial = argv[1];

  if(strlen(serial) != 8) {
    printf("Serial must be 8 characters\n");
    return 1;
  }

  for(i = 0; i < strlen(serial); i++) {
    alnum = (serial[i] >= 'A' && serial[i] <= 'Z') 
            || (serial[i] >= 'a' && serial[i] <= 'z')
            || (serial[i] >= '0' && serial[i] <= '9');
    if(!alnum) {
      printf("Serial must be alphanumeric\n");
      return 1;
    }
  }

  if((ret = check_license(serial))) {
    printf("License check passed\n");
  } else {
    printf("License check failed\n");
  }

  return ret;
}

