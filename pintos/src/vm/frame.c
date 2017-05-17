#include <list.h>
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"


struct list frame_table;	/* Table for holding frame entries. */
struct lock frame_lock;	/* Lock to synchronize operations over frame
							   table, since frame table is available for
							   all user threads. */

static void *frame_evict (enum palloc_flags flags);

/* Initialization of frame table for all threads. Should be called in
   thread system initialization function. */
void frame_init (void)
{
	list_init (&frame_table);
	lock_init (&frame_lock);
}

/* Whenever thread asks for page, this function should be involved in.
   Basically, it creates frame entry and links it to Supplementary
   Page Table entry of that virtual address of thread. */
void *frame_alloc (struct spte *spte)
{
	lock_acquire (&frame_lock);
	/* Allocate page from memory. */
	uint8_t *kpage = palloc_get_page(spte->flags);
	
	struct frame_entry *fe;
	
	/* If allocation failed, then swap the frame from frame table.
	   Since every it is needed to update the status of Supplementary
	   Page Table Entry of evicted frame, there should be some way
	   to update SPTE of that frame, either by passing SPTE, or
	   attaching SPTE pointer to frame entry structure, which will
	   be decided later. TODO: Come up with the way to update SPTE
	   of evicted frame. */
	if (kpage == NULL)
	{
		fe = frame_evict (spte->flags);
		kpage = fe->kpage;
	}
	else 
	{
		/* Allocate frame entry if no page was allocated from pool. */
		fe = malloc (sizeof (struct frame_entry));
		fe->kpage = kpage;	
	}

	/* Set link of physical address of SPTE and link the SPTE and frame entry. */
	fe->thread = thread_current ();
	fe->spte = spte;
	spte->fe = fe;

	/* Add frame entry to frame table. */
	list_push_back (&frame_table, &fe->elem);

	/* Return frame entry. NOTE: Just guessed return type, for now
	   not sure if we need to return at all. TODO: Come up with proper
	   return. */
	lock_release (&frame_lock);

	return fe;
}

/* Remove frame from frame table. */
void *frame_free (struct frame_entry *fe)
{
	lock_acquire (&frame_lock);

	list_remove (&fe->elem);

	lock_release (&frame_lock);
}


/* Choose frame to evict frame table, swap it out and return freed
   frame as new frame. */
static void *frame_evict (enum palloc_flags flags)
{
	/* Set up variable for looping through list of frames. */
	struct list_elem *le = list_begin (&frame_table);
	struct frame_entry *fe = NULL;
	struct thread *t = NULL;
	struct spte *spte = NULL;

	while (true)
	{
		fe = list_entry (le, struct frame_entry, elem);
		t = fe->thread;
		spte = fe->spte;
		/* If frame is not pinned - is not being loaded by other process. */
		if (!(spte->status&PINNED))
		{
			if (pagedir_is_accessed (t->pagedir, spte->upage))
				/* If page was accessed, set the access bit to false. */
				pagedir_set_accessed (t->pagedir, spte->upage, false);
			else if (spte->status & FILE||spte->status & SWAP)
			{
				/* If it is, then swap it out. Since frames designated for
				   files will in any case be loaded from file, there is no
				   need to swap the out ot swap area. */
				swap_out (spte);
				break;
			}

			else
				/* If it is not from stack, then just empty the page
				   without swapping. */
				break;
		}

		if (le == list_end (&frame_table))
			le = list_begin (&frame_table);
	}

	/* Remove the frame from the list, since it will be inserted in frame
	   alloc function anyway. */
	list_remove (&fe->elem);

	/* Clear the page of current page, so that next time process accessing
	   this page will rise page fault. */
	pagedir_clear_page (t->pagedir, spte->upage);
	palloc_free_page (fe->kpage);
	/* Get new page from pool. */
	fe->kpage = palloc_get_page (flags);
	/* Since we just freed one page, there shouldn't be problem allocating
	   new page. */
	ASSERT (fe->kpage != NULL);

	return fe;
}



