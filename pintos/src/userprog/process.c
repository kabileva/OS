#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"

#include "vm/page.h"
#include "vm/frame.h"
#include "userprog/syscall.h"

static thread_func start_process NO_RETURN;
static bool load (const char **parsed_cmdline, 
              void (**eip) (void), void **esp);

static char **parse_args (char *args);

/* Structure to hold avoid racing. Used when parent creates a child
   with allocated args copy, and waits until the child processes the
   args. If child is finished processing the args, then parent
   deallocates the allocated memory for copy of args. */
struct args_sema {
  char **parsed_cmdline;
  struct semaphore block;
  bool success;
};

/* Parses the given args, creating an array of char pointers to
   parsed args. The delimiter is just simply white space. */ 
char **
parse_args (char *args)
{ 
  /* Initial number of args, increment geometrically, if more. */
  int MAX_ARGS = 2;

  /* Allocate array for char pointers. */
  char **args_ret = malloc (sizeof (char **) * MAX_ARGS);

  /* Oth entry will hold the number of parsed args. */
  args_ret[0] = (char *) 0;
  
  char *token, *save_ptr;
  for (token = strtok_r (args, " ", &save_ptr); token != NULL;
    token = strtok_r (NULL, " ", &save_ptr))
  {
    /* If the number of args is MAX_ARGS, reallocated the array
       with MAX_ARGS * 2 char pointers. Inside condition, increment
       the number of args in args_ret[0]. */
    if ((int) ++args_ret[0] == MAX_ARGS) {
      MAX_ARGS *= 2;
      args_ret = realloc (args_ret, sizeof(char *) * MAX_ARGS);
    }
    args_ret[(int) args_ret[0]] = token;
  }

  return args_ret;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Wait for the thread to finish processing the args. Need to allocate
     the variable to be able to use with threads, otherwise there was
     an error. */
  struct args_sema *args = malloc (sizeof (struct args_sema));
  args->parsed_cmdline = parse_args (fn_copy);
  sema_init (&args->block, 0);

  // printf("Process execute %s from thread %s\n", args->parsed_cmdline[1], thread_name ());

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (args->parsed_cmdline[1], PRI_DEFAULT, 
                      start_process, args);

  /* Wait to check for any error in load, and also to be able to free
     the allocated resources. */
  // printf("waiting to process args by process %s\n", thread_name ());
  sema_down (&args->block);
  // printf("finished processing args by process %s\n", thread_name ());
  
  /* If load failed. */
  if (!args->success)
    tid = TID_ERROR;

  /* Deallocate allocated resourses. */
  // printf("free pointer cmdline %p\n", args->parsed_cmdline);
  free (args->parsed_cmdline);
  // printf("free pointer args %p\n", args);
  free (args);
  // printf("free pointer page %p\n", fn_copy);
  palloc_free_page (fn_copy); 
  // printf("freed all resources\n");
  
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *cmdline_)
{
  struct args_sema *cmdline = cmdline_;
  struct intr_frame if_;
  bool success;

#ifdef VM
  spt_init ();
#endif
  
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load ((const char**) cmdline->parsed_cmdline,
                   &if_.eip, &if_.esp);

  cmdline->success = success;


  /* Release the block on the parent process to free the allocated
     memory for copy of command line. */
  sema_up (&cmdline->block);
  
  /* If load failed, quit. */
  if (!success) 
    thread_exit ();  

  // printf("success loading process\n");
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct thread *t = thread_current ();
  /* If was terminated by the kernel, then TID_ERROR. */
  if (child_tid == TID_ERROR) 
    return TID_ERROR;

  /* Check of child_tid is actually is child, otherwise TID_ERROR. */
  if (!is_child (child_tid, t)) 
    return TID_ERROR; 

  struct child_meta *cm = get_child (child_tid, t);
  
  ASSERT (cm != NULL);
  /* If thread with this child_tid has been called with process
     wait, then -1. */
  enum intr_level old_level = intr_disable ();
  if (cm->wait)
  {
    intr_set_level (old_level);
    return TID_ERROR;
  } 
  
  cm->wait = true;
  intr_set_level (old_level);
  
  /* Wait for child to terminate. */
  sema_down (&cm->finished);  

  /* Otherwise return its exit status. */
  return cm->status;
}

/* Free the current process's resources. Basically, this function
   is called when thread_exit() is called with condition that 
   current thread is USER_PROG, so I assume we need to set the
   status of current program here, in process exit. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  remove_mmap();

  /* If parent still exists and, in case parent waits for it 
     free the semaphore. NOTE: Parent sets the parent pointer
     to NULL when terminates. */
  if (cur->parent != NULL) 
  {
    struct child_meta *cm = get_child (cur->tid, cur->parent);
    
    /* If child meta still exists, free its lock. NOTE: Some 
       SPAGHETTI code, actually cm should never be null if 
       parent exists. */
    if (cm != NULL) {
      if (sema_try_down (&cm->finished)) 
        sema_up (&cm->finished);
      else
        sema_up (&cm->finished);

      /* Set the child pointer of thread child meta information
         for parent thread to indicate that child thread has
         terminated. */
      cm->child = NULL;
    }

    /* NOTE: No need to delete meta information of current
       thread in parent process, since parent process might
       need it, when it calls process wait for tid later. */
  }

  /* Allow write to file. */
  lock_acquire (&filesys_lock);
  if (thread_current ()->execfile != NULL)
    file_allow_write (thread_current ()->execfile);
  file_close (thread_current ()->execfile);
  lock_release (&filesys_lock);
  
  /* Deallocate all the child meta information of current thread. */
  clear_children ();

  /* Deallocate all the files meta information of current thread. */
  clear_files ();

  spt_destroy ();
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
  {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate (NULL);
    pagedir_destroy (pd);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half    e_type;
  Elf32_Half    e_machine;
  Elf32_Word    e_version;
  Elf32_Addr    e_entry;
  Elf32_Off     e_phoff;
  Elf32_Off     e_shoff;
  Elf32_Word    e_flags;
  Elf32_Half    e_ehsize;
  Elf32_Half    e_phentsize;
  Elf32_Half    e_phnum;
  Elf32_Half    e_shentsize;
  Elf32_Half    e_shnum;
  Elf32_Half    e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off  p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char **parsed_fn);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
  uint32_t read_bytes, uint32_t zero_bytes,
  bool writable);


/* Loads an ELF executable from CMDLINE into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char **parsed_cmdline, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Get the filename and set the token to arguments, if any. */
  char *fn = (char *) parsed_cmdline[1];

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (fn);
  if (file == NULL) 
  {
    printf ("load: %s: open failed\n", fn);
    goto done; 
  }

  /* Deny write to exectutable file. NOTE: Been looking for this BUG
     for ages. Basically, my file_deny_write didn't work. Been trying
     to compare the pointers of file to make sure that we are dealing
     with the same file. Been trying to understand how the inode
     behind the file structure work. So, there can be many files open
     at time instance, but all of them share same inode, which is
     related with writing and modifying the real file. When file
     created, the same inode with new file structure is given. Inode
     has counts on how many processes have called deny write and
     allow write. So, the problem here was that, in end of the
     current function, file_close (...) was called, which discards
     file_deny_write (...) function. We had to remove that function
     and put it when execution finished. */
  lock_acquire (&filesys_lock);
  thread_current ()->execfile = file;
  file_deny_write (thread_current ()->execfile); 
  lock_release (&filesys_lock);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
    || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
    || ehdr.e_type != 2
    || ehdr.e_machine != 3
    || ehdr.e_version != 1
    || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
    || ehdr.e_phnum > 1024) 
  {
    printf ("load: %s: error loading executable\n", fn);
    goto done; 
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
  {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length (file))
      goto done;
    file_seek (file, file_ofs);

    if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) 
    {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
          /* Ignore this segment. */
      break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
      goto done;
      case PT_LOAD:
      if (validate_segment (&phdr, file)) 
      {
        bool writable = (phdr.p_flags & PF_W) != 0;
        uint32_t file_page = phdr.p_offset & ~PGMASK;
        uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
        uint32_t page_offset = phdr.p_vaddr & PGMASK;
        uint32_t read_bytes, zero_bytes;
        if (phdr.p_filesz > 0)
        {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
          read_bytes = page_offset + phdr.p_filesz;
          zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
            - read_bytes);
        }
        else 
        {
                  /* Entirely zero.
                     Don't read anything from disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
        }
        if (!load_segment (file, file_page, (void *) mem_page,
         read_bytes, zero_bytes, writable))
          goto done;
      }
      else
        goto done;
      break;
    }
  }

  /* Set up stack. */
  if (!setup_stack (esp, parsed_cmdline))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

  done:
  
  /* We arrive here whether the load is successful or not. No need
     to close file, instead close it when the process terminates
  
  file_close (file);

     in process_exit(...) function. */

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();
//printf("installing\n");
  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
    && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
  uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
  {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

#ifdef VM

    /* Allocate a virtual page for current process of type file. */
    struct spte *spte = create_page (upage, PAL_USER, FILE |writable);
    /* Set the SPT entry with information about the file and file read
       offset position. */
    spte->file = file;
    spte->ofs = ofs;
    spte->read_bytes = page_read_bytes;
    spte->zero_bytes = page_zero_bytes;
    /* Allocate physical frame. */
    struct frame_entry *fe = frame_alloc (spte);

    /* If allocation failed, return false. */
    if (fe == NULL)
      return false;

    /* Copy file to memory. */
    if (file_read_at (file, fe->kpage, page_read_bytes, ofs)
                     != (int) page_read_bytes)
    {
      free_page (spte);
      return false;
    }
    memset (fe->kpage + page_read_bytes, 0, page_zero_bytes);

    if (!install_page (spte->upage, fe->kpage, spte->status & WRITABLE))
    {
      free_page (spte);
      return false;
    }

    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    ofs += page_read_bytes;
    upage += PGSIZE;

#else

      /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page (PAL_USER);
    if (kpage == NULL)
      return false;

      /* Load this page. */
    if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
    {
      palloc_free_page (kpage);
      return false; 
    }
    memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
    if (!install_page (upage, kpage, writable)) 
    {
      palloc_free_page (kpage);
      return false; 
    }

      /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;

#endif
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char **parsed_fn) 
{
  /* SPT entry for stack. */
  struct spte *spte = NULL;
  bool success = false;

  /* Create SPT entry for stack with virtual address PHYS_BASE - PGSIZE, and other
     other options. */
  spte = create_page (PHYS_BASE - PGSIZE, PAL_USER | PAL_ZERO, WRITABLE | SWAP);
  /* If SPT entry allocation success. */
  if (spte != NULL) 
  {
    /* Load the page into the memory, i.e. link a frame to it. */
    success = load_page (spte);
    
    if (success) {
      
      *esp = PHYS_BASE;

      /* Get the number of args that is saved as a pointer (little
         hack). */
      int temp = (int) parsed_fn[0];

      /* For each argument, decrement the esp for length of a argument added
         null terminator, and then copy the argument with null included into
         esp. Store the address of esp into the argument address instead. */ 
      for (; temp > 0; temp--) {
        *esp -= (strlen (parsed_fn[temp]) + 1);
        memcpy(*esp, parsed_fn[temp], strlen (parsed_fn[temp]) + 1);
        parsed_fn[temp] = (char *) *esp;
      }

      /* Make sure we keep the alignment. */
      *esp -= ((unsigned) *esp) % WORD_SIZE;
      
      /* Null pointer sentinel. */
      *esp -= WORD_SIZE;
      
      /* For each address of arguments passed, decrement the esp for a length
         of char address and copy the address of argemnts into the esp. */
      for (temp = (int) parsed_fn[0]; temp > 0; temp--) {
        *esp -= sizeof (char *);
        memcpy (*esp,  &parsed_fn[temp], sizeof (char *));
      }

      /* If there are arguments. */
      temp = (int) *esp;
      *esp -= sizeof (char *);
      memcpy (*esp, &temp, sizeof (char *));
      
      /* Push the number of arguments into the stack. Since our array holds the
         total number of args including the filename, we should subtract on from
         the number of args. */      
      *esp -= sizeof (int);
      temp = (int) parsed_fn[0];
      memcpy (*esp, &(temp), sizeof (int));
      
      /* Push fake return address into the stack. */
      temp = 0;
      *esp -= sizeof (void *);
      memcpy (*esp, &temp, sizeof (void *));      
      
      /* hex_dump ((uintptr_t) *esp, *esp, (unsigned) PHYS_BASE - (unsigned) *esp, true);

        Outputs just exactly like in example - 3.5.1 if following command is run:
         pintos -v -k -T 60 --qemu  --filesys-size=2 -p tests/userprog/args-multiple -a args-multiple -- -q  -f run 'args-multiple /bin/ls -l foo bar'.

      bfffffc0                                      00 00 00 00 |            ....|
      bfffffd0  04 00 00 00 d8 ff ff bf-ed ff ff bf f5 ff ff bf |................|
      bfffffe0  f8 ff ff bf fc ff ff bf-00 00 00 00 00 2f 62 69 |............./bi|
      bffffff0  6e 2f 6c 73 00 2d 6c 00-66 6f 6f 00 62 61 72 00 |n/ls.-l.foo.bar.|
      */
    }
    else {
      free_page (spte);
      return success;
    }
  }

  return success;
}

