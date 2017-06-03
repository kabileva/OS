#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "vm/page.h"
#include "vm/frame.h"
#include "threads/vaddr.h"


#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

struct bitmap *swap_bitmap;
struct block *swap_block;
struct lock swap_lock; 

void swap_init (void);
void swap_out (struct spte *spte);
void swap_in (struct spte *spte);
void swap_free (size_t swap_idx);

#endif
