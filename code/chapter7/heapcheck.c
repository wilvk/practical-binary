#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>

void* (*orig_malloc)(size_t);
void  (*orig_free)(void*);
char* (*orig_strcpy)(char*, const char*);

typedef struct {
  uintptr_t addr;
  size_t    size;
} alloc_t;

#define MAX_ALLOCS 1024

alloc_t allocs[MAX_ALLOCS];
unsigned alloc_idx = 0;

void*
malloc(size_t s)
{
  if(!orig_malloc) orig_malloc = dlsym(RTLD_NEXT, "malloc");

  void *ptr = orig_malloc(s);
  if(ptr) {
    allocs[alloc_idx].addr = (uintptr_t)ptr;
    allocs[alloc_idx].size = s;
    alloc_idx = (alloc_idx+1) % MAX_ALLOCS;
  }

  return ptr;
}

void
free(void *p)
{
  if(!orig_free) orig_free = dlsym(RTLD_NEXT, "free");

  orig_free(p);
  for(unsigned i = 0; i < MAX_ALLOCS; i++) {
    if(allocs[i].addr == (uintptr_t)p) {
      allocs[i].addr = 0;
      allocs[i].size = 0;
      break;
    }
  }
}

char*
strcpy(char *dst, const char *src)
{
  if(!orig_strcpy) orig_strcpy = dlsym(RTLD_NEXT, "strcpy");

  for(unsigned i = 0; i < MAX_ALLOCS; i++) {
    if(allocs[i].addr == (uintptr_t)dst) {
      if(allocs[i].size <= strlen(src)) {
        printf("Bad idea! Aborting strcpy to prevent heap overflow\n");
        exit(1);
      }
      break;
    }
  }

  return orig_strcpy(dst, src);
}

