#include <bitmap.h>
#include "vm/swap.h"
#include "devices/block.h"


/* Initialize swap block. */
void swap_init (void)
{
	/* Get swap block. */
	swap_block = block_get_role (BLOCK_SWAP);
	/* Initialize swap bitmap to be able to quickly retrieve free spots in
	   swap block. Initialize it with number size of block divided by number
	   of sectors per page, so that each index in bitmap has sectors per page
	   spots in it. Set all indexes to false (unaccessed). */ 
	swap_bitmap = bitmap_create (block_size (swap_block)/ SECTORS_PER_PAGE);
	bitmap_set_all (swap_bitmap, false);

	/* Since swap block is all for all processes, we need to synchronize, so
	   use lock for it. */
	lock_init (&swap_lock);
}

/* Swap given SPT entry out to swap block. Update its flags, and set the swap
   idx to entry at swap bitmap. NOTE: Given SPT entry should have valid frame entry
   linked to it. */
void swap_out (struct spte *spte)
{
	lock_acquire (&swap_lock);
	
	ASSERT (spte->fe != NULL);

	/* Find entries in bitmap. */
	size_t swap_idx = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
	struct frame_entry *fe = spte->fe;

	/* If not free entries, then SWAP block run out of memory. */
	if (swap_idx == BITMAP_ERROR)
		PANIC ("Run out of space in SWAP block.");

	/* Write to SWAP block. */
	size_t i = 0;
	for (; i < SECTORS_PER_PAGE; i++)
	{
		block_write (swap_block, 
					swap_idx * SECTORS_PER_PAGE + i, 
					fe->kpage + i * BLOCK_SECTOR_SIZE);
	}

	/* Change the status of SPT entry by assigning index at SWAP block. */

	spte->swap_idx = swap_idx;

	lock_release (&swap_lock);
}

/* Swap in the memory at SWAP block indexed at swap idx to given frame entry. */
void swap_in (struct spte *spte)
{
	lock_acquire (&swap_lock);

	
	/* Read to frame entry of SPTE. */
	struct frame_entry *fe = spte->fe;
	size_t i = 0;
	for (;i < SECTORS_PER_PAGE; i++)
	{
		block_read (swap_block,
					spte->swap_idx * SECTORS_PER_PAGE + i,
					fe->kpage + i * BLOCK_SECTOR_SIZE);
		
	}

	/* Empty the index for read memory in SWAP bitmap. */
	bitmap_set (swap_bitmap, spte->swap_idx, false);

	/* Set the swap index to indicate that it is loaded. */
	spte->swap_idx = LOADED;

	lock_release (&swap_lock);
}

void swap_free (size_t swap_idx)
{
	lock_acquire (&swap_lock);

	bitmap_set (swap_bitmap, swap_idx, false);

	lock_release (&swap_lock);	
}
