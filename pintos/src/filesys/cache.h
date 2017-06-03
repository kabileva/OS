#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H
#include "threads/synch.h"

#include "devices/block.h"

// #define 64 64;



void cache_init(void);
void cache_read(struct block*, block_sector_t, void*, unsigned, int);
void cache_write(struct block*, block_sector_t, void*, unsigned, int);

#endif /* filesys/cache.h */
