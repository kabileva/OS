#include <string.h>
#include <stdio.h>
#include "vm/page.h"
#include "vm/swap.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

static unsigned page_hash_func (const struct hash_elem *, 
    void * UNUSED);
static bool page_less_func (const struct hash_elem *, 
    const struct hash_elem *,
    void * UNUSED);
static void page_free_func (struct hash_elem *e,
    void *aux UNUSED);




/* Initialize the hash table that is used as Supplementary Page
   Table. */
void spt_init (void)
{
    hash_init(&thread_current ()->spt, 
        page_hash_func, 
        page_less_func,
        NULL);
}

/* Create virtual page that starts at address given as uaddr. */
void *create_page (void *uaddr,
    enum palloc_flags flags,
    enum spte_flags status)
{
    // printf("created page with p %p in thread %s\n", uaddr, thread_name ());
    struct spte *page = malloc (sizeof (struct spte));
    page->upage = uaddr;
    page->flags = flags;
    page->status = status;
    page->fe = NULL;
    page->swap_idx = LOADED;
    page->file = NULL;
    page->ofs = 0;
    page->read_bytes = 0;
    page->zero_bytes = 0;

    hash_insert (&thread_current ()->spt, &page->h_elem);

    return page;
}

/* Search for SPT entry that of given user virtual address.
   If there is a page with that address, return SPTE. Otherwise
   return NULL. */
struct spte *get_page (void *uaddr)
{
    struct spte spte;

    /* Allign the pointer with paging. */
    spte.upage = pg_round_down (uaddr);
    
    /* Try to find the STP entry corresponding to the uaddr. */
    struct hash_elem *he = hash_find (&thread_current ()->spt, 
        &spte.h_elem);

    /* If the page was found, return the page, otherwise NULL. */
    return he == NULL ? NULL : hash_entry (he, struct spte, h_elem);
}

/* Load page. */
bool load_page (struct spte *spte)
{
    /* Set the status of page as pinned, so that the frame 
       associated is not candidate for eviction when other
       processes request for frame eviction. */
    spte->status |= PINNED;

    /* Allocate a frame for current SPTE. */
    struct frame_entry *fe = frame_alloc (spte);

    // printf("allocating frame for page %p with fe %p\n", spte, fe);
    if (!fe)
        return false;

    if (spte->swap_idx != LOADED)
    {
        /* If page is associated with file, then load the file into
           memory. */
        if (spte->status & FILE)
        {
        /* NOTE: do we need to lock the filesys_lock? */
            if (file_read_at (spte->file, 
                fe->kpage, 
                spte->read_bytes, 
                spte->ofs) != (int) spte->read_bytes)
            {
                free_page (spte);
                return false;
            }
            memset (fe->kpage + spte->read_bytes, 0, spte->zero_bytes);
            spte->swap_idx = LOADED;
        }
        /* If page is in swap area, then load it. */
        else
        {
        // printf("loading page from swap\n");
            swap_in (spte);
        }
    }

    spte->status &= ~PINNED;

    return install_page (spte->upage, 
        fe->kpage, 
        spte->status & WRITABLE);
}

/* Free page and associated memory with it. */
void free_page (struct spte *spte)
{
    /* In the process exit, the pagedir_destroy(...) actually deallocates
       all the pages linked to current process, so there is no need to
       manually deallocate all the pages, just need to set bits in swap
       bitmap so that it is available for other processes. */
    if (spte->swap_idx == LOADED)
    {
        ASSERT (spte->fe != NULL);
        struct thread *t = spte->fe->thread;
        /* Unmap the page. */
        pagedir_clear_page (t->pagedir, spte->upage);    
        frame_free (spte->fe);
    }
    else if (!(spte->status & FILE))
    {
        swap_free (spte->swap_idx);
    }
    hash_delete (&thread_current ()->spt, &spte->h_elem);
    free (spte);    
}

/* Function for unmapping the file mapped page(s). If the argument is
   -1 then unmaps all the file mapped pages. */
void page_unmap (int mmap_id)
{
    /* NOTE: Spent pretty big time to debug this part - need to
       play with the pointers all the time. At first, it was like:
            struct list l = thread_current ()->spte_files;
       Basically, I created a copy of the list, then tried to play
       with this list, instead I should have played with the list
       of the thread spte_files. */
    struct list *l = &thread_current ()->spte_files;
    struct list_elem *e;

    for (e = list_begin (l); e != list_end (l); e = list_next(e))
    {
        struct spte *spte = list_entry (e, struct spte, l_elem);
        if (mmap_id == -1 || spte->mmap_id == mmap_id)
        {
            if (spte->swap_idx == LOADED && 
                pagedir_is_dirty(thread_current ()->pagedir, 
                                                spte->upage))
            {
                lock_acquire (&filesys_lock);
                file_write_at (spte->file, 
                                spte->fe->kpage,
                                spte->read_bytes,
                                spte->ofs);
                lock_release (&filesys_lock);
            }    
            list_remove(&spte->l_elem);
            /* Since the element will erased, need to created
               physical copy of the elem. */
            struct list_elem next = *e;
            free_page (spte);
            e = &next;
        }
    }
}


/* Function that is called when process exits, it simply frees SPT. */
void spt_destroy (void)
{
    hash_destroy (&thread_current ()->spt, page_free_func);
}

/* Hash function for Supplementary Page Table. */
static unsigned page_hash_func (const struct hash_elem *e, 
                                void *aux UNUSED)
{
    struct spte *page = hash_entry (e, struct spte, h_elem);

    return hash_bytes (&page->upage, sizeof (page->upage));
}

/* Comparison function for Hash Table (SPT). */
static bool page_less_func (const struct hash_elem *a, 
                            const struct hash_elem *b,
                            void *aux UNUSED)
{
    struct spte *sa = hash_entry(a, struct spte, h_elem);
    struct spte *sb = hash_entry(b, struct spte, h_elem);

    return sa->upage < sb->upage;
}

/* Helping function for freeing the entries in SPT. */
static void page_free_func (struct hash_elem *e,
                            void *aux UNUSED)
{
    struct spte *s = hash_entry (e, struct spte, h_elem);
    free_page (s);
}

