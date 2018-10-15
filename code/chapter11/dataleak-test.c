#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>

int
open_socket(const char *node, const char *service)
{
  struct addrinfo hints, *res;
  int sockfd;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags    = AI_PASSIVE;
  if(getaddrinfo(NULL, "9999", &hints, &res) != 0) {
    return -1;
  }

  if((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
    return -1;
  }
  if(bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
    return -1;
  }

  return sockfd;
}

size_t
split_filenames(char *buf, char *filenames[], size_t max_fcount)
{
  size_t fcount, i, n;

  n = strlen(buf);
  fcount = 0;
  for(i = 0; i < n; i++) {
    if(fcount >= max_fcount-1) break;
    filenames[fcount++] = &buf[i];
    while(buf[i] != ' ' && buf[i] != '\n' && i < n) {
      i++;
    }
    buf[i] = '\0';
  }
  filenames[fcount] = NULL;

  return fcount;
}

int
main(int argc, char *argv[])
{
  size_t i;
  FILE *fp[10];
  char buf[4096], *filenames[10];
  size_t fcount;
  socklen_t addrlen;
  struct sockaddr_storage addr;

  srand(time(NULL));

  int sockfd = open_socket("localhost", "9999");
  if(sockfd < 0) {
    fprintf(stderr, "(dataleak-test) failed to open socket\n");
    return 1;
  }

  addrlen = sizeof(addr);
  if(recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&addr, &addrlen) < 0) {
    fprintf(stderr, "(dataleak-test) recvfrom failed\n");
    return 1;
  }

  fcount = split_filenames(buf, filenames, 10);

  for(i = 0; i < fcount; i++) {
    fp[i] = fopen(filenames[i], "r");
  }

  i = rand() % fcount;
  while(fgets(buf, sizeof(buf), fp[i])) {
    sendto(sockfd, buf, strlen(buf)+1, 0, (struct sockaddr*)&addr, addrlen);
  }

  for(i = 0; i < fcount; i++) {
    fclose(fp[i]);
  }

  return 0;
}

