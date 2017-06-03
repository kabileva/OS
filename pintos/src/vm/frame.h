#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "vm/page.h"

/* List entry for frame. */
struct frame_entry
{
	struct spte *spte;			/* Corresponding SPT entry that is linked to
								   this frame entry. */
	void *kpage;				/* Physical address of memory that is linked
								   to current frame. */
	struct thread *thread;		/* Thread to which this frame is allocated. */
	struct list_elem elem;		/* List elem for the frame table list. */
};

void frame_init (void);
void *frame_alloc (struct spte *);
void frame_free (struct frame_entry *);

#endif
