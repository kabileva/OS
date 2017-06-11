#include "filesys/cache.h"
#include "vm/page.h"		// flag_t
#include "threads/synch.h"
#include "threads/malloc.h"
#include "devices/timer.h"

#include "string.h"


static struct cache_block cache[64];
static struct lock cache_lock;
static int cache_find_block(struct block*, block_sector_t);

void cache_init(void)
{
	lock_init(&cache_lock);
	int i = 0;
	for(; i < 64; i++)
	{
		cache[i].block = NULL;
		cache[i].flags = CLEAN;
		cache[i].last_access_time = 0;
		lock_init(&cache[i].lock);
	}
}

/* Function for finding the given block. If it's not found in cache,
take it from the disk */
static int cache_find_block(struct block* block, block_sector_t sector)
{
	lock_acquire(&cache_lock);
	int i = 0;
	/* find the block */
	for(; i < 64; i++)
	{
		if (cache[i].block == block && cache[i].sector == sector)
		{
			lock_acquire(&cache[i].lock);
			lock_release(&cache_lock);
			return i;
		}
	}

	/* evict another if not found */
	
	i = cache_evict();
	/*save old block's values */
	struct block* old_block = cache[i].block;
	block_sector_t old_sector = cache[i].sector;
	cache[i].block = block;
		
	if(cache[i].flags & DIRTY)
	{
		block_write(old_block, old_sector, &cache[i].data);
	}
		
	cache[i].sector = sector;
	cache[i].flags = CLEAN;

	block_read(block, sector, &cache[i].data);

	lock_release(&cache_lock);

	return i;
}


/*
 * reads size bytes of data from the given block at offset.
 */
void cache_read(struct block* block, block_sector_t sector, void* data, unsigned offset, int size)
{
	ASSERT(block != NULL);
	ASSERT(data != NULL);
	ASSERT(offset + size <= BLOCK_SECTOR_SIZE);
	/* Find block. Evict and store another if not found */
	int idx = cache_find_block(block, sector);

	cache[idx].last_access_time = timer_ticks();	// store time of the last access

	uint8_t* addr = (uint8_t*)((unsigned)(&cache[idx].data) + offset);
	memcpy(data, addr, size);	// read data

	cache[idx].flags |= ACCESSED;		

	lock_release(&cache[idx].lock);	
}

/*
 * writes size bytes of data from the given block at offset.
 */
void cache_write(struct block* block, block_sector_t sector, void* data, unsigned offset, int size)
{

	ASSERT(block != NULL);
	ASSERT(data != NULL);
	ASSERT(offset + size <= BLOCK_SECTOR_SIZE);

	/* the function is the same as cache_read. just we store data, rather than read it */
	int idx = cache_find_block(block, sector);

	cache[idx].last_access_time = timer_ticks();	// reduce probability of waiting during eviction

	uint8_t* addr = (uint8_t*)((unsigned)(&cache[idx].data) + offset);
	memcpy(addr, data, size);

	cache[idx].flags |= ACCESSED | DIRTY;

	lock_release(&cache[idx].lock);
}

/* Writes cach back to disk when shutting down */
void cache_write_back(void)
{
	int i = 0;
	for(; i < 64; ++i)
	{
		if (cache[i].flags & DIRTY)
		{
			block_write(cache[i].block, cache[i].sector, &cache[i].data);
		}
	}
}

/* LRU Eviction  */
static int cache_evict()
{
	int ret = -1;
	while (ret == -1)
	{
		int i = 0;
		/* try find empty block */
		for(; i < 64; i++)
		{
			lock_acquire(&cache[i].lock);
			ret = i;	
			if(cache[i].block == NULL)
				return ret;
			break;
		}

		i++;	
		
		for(; i < 64; i++)
		{
			lock_acquire(&cache[i].lock);
			if(cache[i].last_access_time < cache[ret].last_access_time)
				{
					/* release previously evicted */
					lock_release(&cache[ret].lock);
					ret = i;
				} 
			else
				lock_release(&cache[i].lock);
		}
	}

	return ret;
}
