#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H
#include "threads/synch.h"

#include "devices/block.h"


enum cache_flags {
	CLEAN = 0x00,
	ACCESSED = 0x01,
    DIRTY	= 0x02
};

struct cache_block
{
	struct block* block;
	block_sector_t sector;
	enum cache_flags flags;
	uint8_t data[BLOCK_SECTOR_SIZE];
	struct lock lock;
	int64_t last_access_time;
};

void cache_init(void);
void cache_read(struct block*, block_sector_t, void*, unsigned, int);
void cache_write(struct block*, block_sector_t, void*, unsigned, int);

#endif /* filesys/cache.h */
