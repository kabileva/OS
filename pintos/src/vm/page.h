#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <bitmap.h>
#include "threads/thread.h"
#include "filesys/file.h"
#include "vm/frame.h"

enum spte_flags
{
	WRITABLE = 0x1,		/* Indicates if current can be written upon. */
	SWAP = 0x2,			/* Indicates if this page is swapped. */
	FILE = 0x4,			/* Indicates if this page is associated with file. */
	PINNED = 0x8,		/* Indicates if this page is pinned. Used to avoid
						   race condition in allocating frame while loading
						   page in load page function. */
	MMAP = 0x7,
};

#define MAX_STACK_SIZE (1 << 23)
#define LOADED BITMAP_ERROR

/* SPT entry. */
struct spte
{
	void *upage;				/* Virtual address of process page. */
	enum palloc_flags flags;	/* Flags, assoctiated with page allocation. */
	enum spte_flags status;		/* Flags that explicitly indicates page status
								   like if it is writable, or swapped. */
	struct frame_entry *fe;		/* Frame entry to whic SPTE is linked to, 
								   if any. */

	size_t swap_idx;			/* If current SPTE has been swapped, the
								   index of swap bitmap. */

	 struct file *file;			/* File that that is associated with page,
								   if any. */
	off_t ofs;					/* Offset in file. */
	uint32_t read_bytes;		/* Read bytes in file. */
	uint32_t zero_bytes;		/* Zero bytes in file. */
	bool hash_error;
	struct hash_elem elem;		/* Hash element to manipulate hash SPT. */
	int mmap_id;
};
struct mmap_file {
  struct spte *spte;
  int mmap_id;
  struct list_elem elem;
};


void spt_init (void);
void* create_page (void *, enum palloc_flags, enum spte_flags);
struct spte *get_page (void *);
bool load_page (struct spte *);
void free_page (struct spte *);
void spt_destroy (void);
void* page_add_mmap(struct file *file, int32_t ofs, uint8_t *upage,
                  uint32_t read_bytes, uint32_t zero_bytes);

#endif
