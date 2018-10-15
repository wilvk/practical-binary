#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <map>
#include <vector>
#include <algorithm>

#include "pin.H"

typedef struct mem_access {
  mem_access()                                  : w(false), x(false), val(0) {}
  mem_access(bool ww, bool xx, unsigned char v) : w(ww)   , x(xx)   , val(v) {}
  bool w;
  bool x;
  unsigned char val;
} mem_access_t;

typedef struct mem_cluster {
  mem_cluster()                                             : base(0), size(0), w(false), x(false) {}
  mem_cluster(ADDRINT b, unsigned long s, bool ww, bool xx) : base(b), size(s), w(ww), x(xx)       {}
  ADDRINT       base;
  unsigned long size;
  bool          w;
  bool          x;
} mem_cluster_t;

FILE *logfile;
std::map<ADDRINT, mem_access_t> shadow_mem;
std::vector<mem_cluster_t> clusters;
ADDRINT saved_addr;

KNOB<string> KnobLogFile(KNOB_MODE_WRITEONCE, "pintool", "l", "unpacker.log", "log file");


/*****************************************************************************
 *                             Analysis functions                            *
 *****************************************************************************/
void
fsize_to_str(unsigned long size, char *buf, unsigned len)
{
  int i;
  double d;
  const char *units[] = {"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};

  i = 0;
  d = (double)size;
  while(d > 1024) {
    d /= 1024;
    i++;
  }

  if(!strcmp(units[i], "B")) {
    snprintf(buf, len, "%.0f%s", d, units[i]);
  } else {
    snprintf(buf, len, "%.1f%s", d, units[i]);
  }
}


static void
mem_to_file(mem_cluster_t *c, ADDRINT entry)
{
  FILE *f;
  char buf[128];

  fsize_to_str(c->size, buf, 128);
  fprintf(logfile, "extracting unpacked region 0x%016jx (%9s) %s%s entry 0x%016jx\n", 
          c->base, buf, c->w ? "w" : "-", c->x ? "x" : "-", entry);

  snprintf(buf, sizeof(buf), "unpacked.0x%jx-0x%jx_entry-0x%jx", 
           c->base, c->base+c->size, entry);

  f = fopen(buf, "wb");
  if(!f) {
    fprintf(logfile, "failed to open file '%s' for writing\n", buf);
  } else {
    for(ADDRINT i = c->base; i < c->base+c->size; i++) {
      if(fwrite((const void*)&shadow_mem[i].val, 1, 1, f) != 1) {
        fprintf(logfile, "failed to write unpacked byte 0x%jx to file '%s'\n", i, buf);
      }
    }
    fclose(f);
  }
}


static void
set_cluster(ADDRINT target, mem_cluster_t *c)
{
  ADDRINT addr, base;
  unsigned long size;
  bool w, x;
  std::map<ADDRINT, mem_access_t>::iterator i, j;

  j = shadow_mem.find(target);
  assert(j != shadow_mem.end());

  /* scan back to base of cluster */
  base = target;
  w    = false;
  x    = false;
  for(i = j; ; i--) {
    addr = i->first;
    if(addr == base) {
      /* this address is one less than the previous one, so this is still the
       * same cluster */
      if(i->second.w) w = true;
      if(i->second.x) x = true;
      base--;
    } else {
      /* we've reached the start of the cluster but overshot it by one byte */
      base++;
      break;
    }
    if(i == shadow_mem.begin()) {
      base++;
      break;
    }
  }

  /* scan forward to end of cluster */
  size = target-base;
  for(i = j; i != shadow_mem.end(); i++) {
    addr = i->first;
    if(addr == base+size) {
      if(i->second.w) w = true;
      if(i->second.x) x = true;
      size++;
    } else {
      break;
    }
  }

  c->base = base;
  c->size = size;
  c->w    = w;
  c->x    = x;
}


static bool
in_cluster(ADDRINT target)
{
  mem_cluster_t *c;

  for(unsigned i = 0; i < clusters.size(); i++) {
    c = &clusters[i];
    if(c->base <= target && target < c->base+c->size) {
      return true;
    }
  }

  return false;
}


static void
check_indirect_ctransfer(ADDRINT ip, ADDRINT target)
{
  mem_cluster_t c;

  shadow_mem[target].x = true;
  if(shadow_mem[target].w && !in_cluster(target)) {
    /* control transfer to a once-writable memory region, suspected transfer
     * to original entry point of an unpacked binary */
    set_cluster(target, &c);
    clusters.push_back(c);
    /* dump the new cluster containing the unpacked region to file */
    mem_to_file(&c, target);
    /* we don't stop here because there might be multiple unpacking stages */
  }
}


static void
queue_memwrite(ADDRINT addr)
{
  saved_addr = addr;
}


static void
log_memwrite(UINT32 size)
{
  ADDRINT addr = saved_addr;
  for(ADDRINT i = addr; i < addr+size; i++) {
    shadow_mem[i].w = true;
    PIN_SafeCopy(&shadow_mem[i].val, (const void*)i, 1);
  }
}


/*****************************************************************************
 *                         Instrumentation functions                         *
 *****************************************************************************/
static void
instrument_mem_cflow(INS ins, void *v)
{
  if(INS_IsMemoryWrite(ins) && INS_hasKnownMemorySize(ins)) {
    INS_InsertPredicatedCall(
      ins, IPOINT_BEFORE, (AFUNPTR)queue_memwrite, 
      IARG_MEMORYWRITE_EA,
      IARG_END
    );
    if(INS_HasFallThrough(ins)) {
      INS_InsertPredicatedCall(
        ins, IPOINT_AFTER, (AFUNPTR)log_memwrite, 
        IARG_MEMORYWRITE_SIZE, 
        IARG_END
      );
    }
    if(INS_IsBranchOrCall(ins)) {
      INS_InsertPredicatedCall(
        ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)log_memwrite, 
        IARG_MEMORYWRITE_SIZE,
        IARG_END
      );
    }
  }
  if(INS_IsIndirectBranchOrCall(ins) && INS_OperandCount(ins) > 0) {
    INS_InsertCall(
      ins, IPOINT_BEFORE, (AFUNPTR)check_indirect_ctransfer, 
      IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR,  
      IARG_END
    );
  }
}


/*****************************************************************************
 *                               Other functions                             *
 *****************************************************************************/
static bool
cmp_cluster_size(const mem_cluster_t &c, const mem_cluster_t &d)
{
  return c.size > d.size;
}


static void
print_clusters()
{
  ADDRINT addr, base;
  unsigned long size;
  bool w, x;
  unsigned j, n, m;
  char buf[32];
  std::vector<mem_cluster_t> clusters;
  std::map<ADDRINT, mem_access_t>::iterator i;

  /* group shadow_mem into consecutive clusters */
  base = 0;
  size = 0;
  w    = false;
  x    = false;
  for(i = shadow_mem.begin(); i != shadow_mem.end(); i++) {
    addr = i->first;
    if(addr == base+size) {
      if(i->second.w) w = true;
      if(i->second.x) x = true;
      size++;
    } else {
      if(base > 0) {
        clusters.push_back(mem_cluster_t(base, size, w, x));
      }
      base  = addr;
      size  = 1;
      w     = i->second.w;
      x     = i->second.x;
    }
  }

  /* find largest cluster */
  size = 0;
  for(j = 0; j < clusters.size(); j++) {
    if(clusters[j].size > size) {
      size = clusters[j].size;
    }
  }

  /* sort by largest cluster */
  std::sort(clusters.begin(), clusters.end(), cmp_cluster_size);

  /* print cluster bar graph */
  fprintf(logfile, "******* Memory access clusters *******\n");
  for(j = 0; j < clusters.size(); j++) {
    n = ((float)clusters[j].size/size)*80;
    fsize_to_str(clusters[j].size, buf, 32);
    fprintf(logfile, "0x%016jx (%9s) %s%s: ", 
            clusters[j].base, buf,
            clusters[j].w ? "w" : "-", clusters[j].x ? "x" : "-");
    for(m = 0; m < n; m++) {
      fprintf(logfile, "=");
    }
    fprintf(logfile, "\n");
  }
}


static void
fini(INT32 code, void *v)
{
  print_clusters();
  fprintf(logfile, "------- unpacking complete -------\n");
  fclose(logfile);
}


int
main(int argc, char *argv[])
{
  if(PIN_Init(argc, argv) != 0) {
    fprintf(stderr, "PIN_Init failed\n");
    return 1;
  }

  logfile = fopen(KnobLogFile.Value().c_str(), "a");
  if(!logfile) {
    fprintf(stderr, "failed to open '%s'\n", KnobLogFile.Value().c_str());
    return 1;
  }
  fprintf(logfile, "------- unpacking binary -------\n");

  INS_AddInstrumentFunction(instrument_mem_cflow, NULL);
  PIN_AddFiniFunction(fini, NULL);

  PIN_StartProgram();
    
  return 1;
}

