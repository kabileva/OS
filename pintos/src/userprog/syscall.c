#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);

static int get_arg (void *, void *);
static void check_arg (void *, void *);
static int sys_exec (char *);
static int sys_wait (tid_t);
static bool sys_create (char *, unsigned);
static bool sys_remove (char *);
static int sys_open (char *);
static int sys_filesize (int);
static int sys_read (int, char *, unsigned);
static int sys_write (int, char *, unsigned);
static void sys_seek (int, unsigned);
static unsigned sys_tell (int);
static void sys_close (int);
int mmap (int fd, void *upage);

void
syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	/* Get the syscall code. */
	int code = get_arg (f->esp, f->esp);
	switch (code) {
		case SYS_HALT:
		{
			/* Halt the system. */
			shutdown_power_off ();
			break;
		}
		case SYS_EXIT:
		{	
			/* Get first argument. */
			int status = get_arg (f->esp + WORD_SIZE, f->esp);
			sys_exit (status);
			break;
		}
		case SYS_EXEC:
		{
			/* Get first argument. */
			char *file_name = (char *) get_arg (f->esp + WORD_SIZE, f->esp);

			/* Check the pointer. */
			check_arg (file_name, f->esp);

			/* I was looking in the for the information as to where save
			   return value from the sys_call. Couldn't find any except
			   in internet. Seems like f->eax is place where we should
			   store the return value. Keep in mind that we should store
			   there the return value as int, right in the memory. NOTE:
			   Read online and found that in IAx32 systems, the return
			   scheme differs based on the return type - integral type or
			   pointer will be stored in eax register | floating-point and
			   structures will be stored in floating point register and on
			   stack correspondigly, but seemingly, we don't have to deal
			   with two latter cases here. So just store the return value
			   in f->eax. */
			f->eax = sys_exec (file_name);
			break;
		}
		case SYS_WAIT:
		{
			/* NOTE: used tid_t instead of pid_t. I don't see any problem
			   that it could cause. */

			/* Get first argument. */
			tid_t tid = get_arg (f->esp + WORD_SIZE, f->esp);

			f->eax = sys_wait (tid);
			break;
		}
		case SYS_CREATE:
		{
			/* Get arguments. */
			char *file = (char *) get_arg (f->esp + WORD_SIZE, f->esp);
			unsigned init_size = (unsigned) get_arg (f->esp + 
												2 * WORD_SIZE, f->esp);

			/* Check the pointer. */
			check_arg (file, f->esp);			

			lock_acquire (&filesys_lock);
			f->eax = sys_create (file, init_size);
			lock_release (&filesys_lock);
			break;
		}
		case SYS_REMOVE:
		{
			/* Get first argument. */
			char *file = (char *) get_arg (f->esp + WORD_SIZE, f->esp);

			/* Check the pointer. */
			check_arg (file, f->esp);			

			lock_acquire (&filesys_lock);
			f->eax = sys_remove (file);
			lock_release (&filesys_lock);
			
			break;
		}
		case SYS_OPEN:
		{
			/* Get first argument. */
			char *file = (char *) get_arg (f->esp + WORD_SIZE, f->esp);

			/* Check the pointer. */
			check_arg (file, f->esp);			

			lock_acquire (&filesys_lock);
			f->eax = sys_open (file);
			lock_release (&filesys_lock);
			break;	
		}
		case SYS_FILESIZE:
		{
			/* Get first argument. */
			int fd = get_arg (f->esp + WORD_SIZE, f->esp);
			
			lock_acquire (&filesys_lock);
			f->eax = sys_filesize (fd);
			lock_release (&filesys_lock);
			break;
		}
		case SYS_READ:
		{
			/* Get arguments. */

			int fd = get_arg (f->esp + WORD_SIZE, f->esp);

			char *buf = (char *) get_arg (f->esp + 2 * WORD_SIZE, f->esp);
			
			unsigned size = (unsigned) get_arg (f->esp + 3 * WORD_SIZE, f->esp);
			
			/* Check the pointer. */
			check_arg (buf, f->esp);
						
			lock_acquire (&filesys_lock);
			f->eax = sys_read (fd, buf, size);
			lock_release (&filesys_lock);
			break;
		}
		case SYS_WRITE:
		{	
			/* Get arguments. */
			int fd = get_arg (f->esp + WORD_SIZE, f->esp);
			char *buf =  (char *) get_arg (f->esp + 2 * WORD_SIZE, f->esp);
			unsigned size = (unsigned) get_arg (f->esp + 3 * WORD_SIZE, f->esp);
			/* Check the pointer. */
			check_arg (buf, f->esp);			
			lock_acquire (&filesys_lock);
			f->eax = sys_write (fd, buf, size);
			lock_release (&filesys_lock);
			break;
		}
		case SYS_SEEK:
		{
			/* Get arguments. */
			int fd = get_arg (f->esp + WORD_SIZE, f->esp);
			unsigned pos = (unsigned) get_arg (f->esp + 2 * WORD_SIZE, f->esp);
			
			lock_acquire (&filesys_lock);
			sys_seek (fd, pos);
			lock_release (&filesys_lock);
			break;
		}
		case SYS_TELL:
		{
			/* Get first argument. */
			int fd = get_arg (f->esp + WORD_SIZE, f->esp);
			
			lock_acquire (&filesys_lock);
			f->eax = sys_tell (fd);
			lock_release (&filesys_lock);
			break;
		}
		case SYS_CLOSE:
		{	
			/* Get first argument. */
			int fd = get_arg (f->esp + WORD_SIZE, f->esp);
			
			lock_acquire (&filesys_lock);
			sys_close (fd);
			lock_release (&filesys_lock);
			break;
		}

		case SYS_MMAP:
      	{
	      	int fd = get_arg (f->esp + WORD_SIZE, f->esp);
	      	int arg = get_arg (f->esp + 2*WORD_SIZE, f->esp);
	        f->eax = mmap(fd,arg);
	        break;
	     }

	    case SYS_MUNMAP:
	    {
	        check_arg(f->esp+ WORD_SIZE,f->esp);
	        munmap();
	        break;
	    }

		// case SYS_CHDIR:
		// {
		// 	break;
		// }
		// case SYS_MKDIR:
		// {
		// 	break;
		// }         
		// case SYS_READDIR:
		// {
		// 	break;
		// }         
		// case SYS_ISDIR:
		// {
		// 	break;
		// }
		// case SYS_INUMBER:
		// {
		// 	break;
		// }
	} 

}

/* Check if given address belongs to user virtual address and is from
   current thread's page directory. If not, then exit with error. */
void
check_arg (void *p, void *esp)
{
	if (!is_user_vaddr (p) || p < ((void *) 0x08048000))
    	sys_exit (ERROR);
   
    struct spte *spte = get_page (esp);

    if (!spte)
    	sys_exit (ERROR);

    spte = get_page (p);
    if (spte && spte->swap_idx == LOADED)
    	return;
 
    if (!spte && p >= esp - 32)
    {
		void *page_p = pg_round_down (p);

		if (PHYS_BASE - page_p > MAX_STACK_SIZE)
			sys_exit (ERROR);
		
		spte = create_page (page_p, PAL_USER, WRITABLE | SWAP);
    }
    if (spte && load_page (spte))
    {
    	return;
    }

    sys_exit (ERROR);
}

/* Get the value from stack that is placed as size of integer. Check if 
   the pointer obtained belongs to user virtual address. */
int
get_arg (void *p, void *esp)
{	
	check_arg (p, esp);
	return *((int *) p);
}

/* Function that is called when SYS_EXIT invoked. Exits current thread.
   If parent waits for the thread, status will be returned to parent. */ 
void 
sys_exit (int status)
{
	/* Print exit message. */
	printf ("%s: exit(%d)\n", thread_name (), status);
	/* Set the status of current terminating thread. */
	set_status (status);
	if (lock_held_by_current_thread (&filesys_lock))
	{
		lock_release (&filesys_lock);
	}
	thread_exit ();
}

/* Function that is called when SYS_EXEC invoked. Executes given file. */
int
sys_exec (char *file_name) 
{
	/* Execute the command line given. */
	return process_execute (file_name);
}

/* Function that is called when SYS_WAIT invoked. Wait for given process
   to terminate. */
int
sys_wait (tid_t tid)
{	
	/* Wait for the given tid to terminate. */
	return process_wait (tid);
}

/* Function that is called when SYS_CREATE invoked. Create new file with
   initial size of init_size. Returns true, if successful, false
   otherwise. Does not open the file, although creates it. */
bool
sys_create (char *file, unsigned init_size) 
{
	/* Create file. */
	return filesys_create (file, init_size);
}

/* Function that is called when SYS_REMOVE invoked. Deletes the file
   Returns true if successful, false otherwise. File may be removed
   regardless of whether it is open or closed, and removing an open
   file does not close it. */
bool
sys_remove (char *file) 
{
	/* NOTE: Currently, I didn't figure out whether following function
	   somehow affects the file accessibility, if opened by any other
	   threads, so TODO: figure it out in future. */
	
	/* Remove file. */
	return filesys_remove (file);
}

/* Function that is called when SYS_OPEN invoked. Returns a file
   descriptor (nonnegative integer), or -1 if file couldn't be opened.
   Shouldn't return 0, or 1, which are reserved for console. */
int
sys_open (char *file)
{
	/* NOTE: Currently, I didn't figure out whether following function
	   somehow affects the file accessibility, if opened by any other
	   threads, so TODO: figure it out in future. */
	
	/* Get the file. */
	struct file *f = filesys_open (file);

	/* If openm faile, return error. */
	if (f == NULL)
		return ERROR;

	/* Add the file as opened file to thread, and return fd. */
	return add_file (f);
}  

/* Function that is called when SYS_FILESIZE invoked. Returns size
   of the file, if this thread owns the file, 0 otherwise. NOTE:
   still do not know whether of current thread doesn't own the file
   descriptor given. */
int
sys_filesize (int fd)
{
	/* Get the opened file by current thread. */
	struct file_meta *fm = get_file (fd);

	/* If current thread doesn't own the file, return error. */
	if (fm == NULL)
		return ERROR;
	
	/* Get the size. */
	return file_length (fm->file);
}

/* Function that is called when SYS_READ invoked. Returns the number
   of bytes actually read. */
int
sys_read (int fd, char *buf, unsigned size)
{
	/* If the read from stdin, then read from keyboard. */
	if (fd == STDIN_FILENO)
	{
		unsigned i;

		/* Create local buffer with uint8_t to map the input_getc
		   function return value. */
		uint8_t *loc = (uint8_t *) buf;
		for (i = 0; i < size; i++) {
			loc[i] = input_getc ();
		}

		/* Return the number of bytes written. */
		return size;
	}

	/* If the read from stdout, then return error. */
	if (fd == STDOUT_FILENO)
		sys_exit (ERROR);

	/* Otherwise it is file descriptor. Get the opened file by 
	   current thread. */
	struct file_meta *fm = get_file (fd);


	/* If current thread doesn't own the file, then return 0. */
	if (fm == NULL) 
		sys_exit (ERROR);

	/* Read the file, and return the number of bytes actually read.
	   Might be less than size, if EOF reached. */
	return file_read (fm->file, buf, size);
}



/* Function that is called when SYS_CALL invoked. Returns the number
   of bytes actually written. */
int 
sys_write (int fd, char *buf, unsigned size) 
{
	/* If the write to stdin, then return error. */
	if (fd == STDIN_FILENO)
	{
		sys_exit (ERROR);
	}



	/* If output is for console. */ 
	if (fd == STDOUT_FILENO)
	{
		putbuf(buf, size);
		/* TODO: Implement checking for the actually number of bytes
		   written. */
		return (int) size;
	}
	
	/* Otherwise it is file descriptor. Get the opened file by 
	   current thread. */
	struct file_meta *fm = get_file (fd);

	/* If current thread doesn't own the file, then return error. */
	if (fm == NULL) 
		sys_exit (ERROR);

	return file_write (fm->file, buf, size);
}

/* Function that is called when SYS_SEEK invoked. Changes the next
   byte to be read or written in open file fd to position expressed
   in bytes. */
void 
sys_seek (int fd, unsigned pos) 
{
	/* If the file is stdout or stdin, then return error. */
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
	{
		sys_exit (ERROR);
	}

	/* Otherwise it is file descriptor. Get the opened file by 
	   current thread. */
	struct file_meta *fm = get_file (fd);

	/* If current thread doesn't own the file, then return error. */
	if (fm == NULL) 
		sys_exit (ERROR);

	file_seek (fm->file, pos);
}

/* Function that is called when SYS_TELL invoked. Return the
   position of the next byte to be read or written in open file fd,
   expressed in bytes from the beginning of the file. */
unsigned 
sys_tell (int fd) 
{
	/* If the file is stdout or stdin, then return error. */
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
		sys_exit (ERROR);

	/* Otherwise it is file descriptor. Get the opened file by 
	   current thread. */
	struct file_meta *fm = get_file (fd);

	/* If current thread doesn't own the file, then return error. */
	if (fm == NULL) 
		sys_exit (ERROR);

	return file_tell (fm->file);
}

/* Function that is called when SYS_CLOSE invoked. Closes file
   descriptor fd. */
void
sys_close (int fd) 
{
	/* If the file is stdout or stdin, then return error. */
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
		sys_exit (ERROR);

	/* Otherwise it is file descriptor. Remove the file meta
	   struct. It might be removed before, but that's just fine. */
	struct file *f = remove_file (fd);

	/* If successfull, then close file. */
	file_close (f);
}

/* mmap all pages */
int mmap (int fd, void *upage)
{
  struct file_meta *fm = get_file(fd);
  struct file *file = fm->file;
  if (!file) return -1;
  if (((uint32_t) upage % PGSIZE) != 0 || !is_user_vaddr(upage) || 
      upage < ((void *) 0x08048000))
    return -1;
  struct file *file_reopened = file_reopen(file);
  uint32_t read_bytes = file_length(file_reopened);
  int32_t ofs = 0;
  uint32_t curr_read_bytes;

  thread_current()->mmap_id++;

  for(; read_bytes>0; read_bytes-=curr_read_bytes)
    {
    if (read_bytes<PGSIZE) 
    	curr_read_bytes = read_bytes;
    else 
    	curr_read_bytes = PGSIZE;

    struct spte *page = create_page(upage, PAL_USER, MMAP);
	if(!page) {
	 	munmap();
	 	return -1;
	}
	page->file = file_reopened;
	page->ofs = ofs;
	page->read_bytes = curr_read_bytes;
	page->zero_bytes = PGSIZE - curr_read_bytes;
	page->swap_idx = ~LOADED;
	page->mmap_id = thread_current()->mmap_id;
	list_push_back(&thread_current()->mmap_list, &page->l_elem);
      
    upage += PGSIZE;
    ofs += curr_read_bytes;
    }
  return thread_current()->mmap_id;
}

void munmap ()
{
  struct thread *curr = thread_current();
  struct list_elem *first, *next = list_begin(&curr->mmap_list);
  for (first = list_begin(&curr->mmap_list);
       first != list_end(&curr->mmap_list); first = next)
  {
    struct spte *page = list_entry (first, struct spte, l_elem);
	if(!page->hash_error)
         hash_delete(&curr->spt, &page->elem);
      if (page)
      {
        if (pagedir_is_dirty(curr->pagedir, page->upage))
          file_write_at(page->file, page->upage,
              page->read_bytes, page->ofs);
      }
      list_remove(&page->l_elem);
          next = list_next(first);
  }
}

