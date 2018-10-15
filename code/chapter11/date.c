#include <stdio.h>
#include <time.h>

int
main(int argc, char *argv[])
{
  time_t now;
  struct tm *tm;
  char datestr[128];

  if(argc < 2) {
    printf("Usage: %s <format>\n", argv[0]);
    return 1;
  }

  now = time(NULL);
  tm  = localtime(&now);

  strftime(datestr, sizeof(datestr), argv[1], tm);
  printf("%s\n", datestr);

  return 0;
}

