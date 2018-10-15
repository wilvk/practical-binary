#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

void
die(char const *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);

  exit(1);
}

int
main(int argc, char *argv[])
{
  FILE *f;
  char *infile, *outfile;
  unsigned char *key, *buf;
  size_t i, j, n;

  if(argc != 4)
    die("Usage: %s <in file> <out file> <key>\n", argv[0]);

  infile  = argv[1];
  outfile = argv[2];
  key     = (unsigned char*)argv[3];

  f = fopen(infile, "rb");
  if(!f) die("Failed to open file '%s'\n", infile);

  fseek(f, 0, SEEK_END);
  n = ftell(f);
  fseek(f, 0, SEEK_SET);

  buf = malloc(n);
  if(!buf) die("Out of memory\n");

  if(fread(buf, 1, n, f) != n)
    die("Failed to read file '%s'\n", infile);

  fclose(f);

  j = 0;
  for(i = 0; i < n-1; i++) { /* Oops! An off-by-one error! */
    buf[i] ^= key[j];
    j = (j+1) % strlen(key);
  }

  f = fopen(outfile, "wb");
  if(!f) die("Failed to open file '%s'\n", outfile);

  if(fwrite(buf, 1, n, f) != n)
    die("Failed to write file '%s'\n", outfile);

  fclose(f);

  return 0;
}

