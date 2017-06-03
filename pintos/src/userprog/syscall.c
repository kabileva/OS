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
static int sys_mmap (int, void *);
static void sys_munmap (int);



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

    // printf("syscall %d in thread %s\n", code, thread_name ());
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

            // printf("fd %d buf %s with pointer %p and size %d\n", fd, buf, buf, size);

            /* Check the pointer. */
            check_arg (buf, f->esp);            

            // printf("%s\n", buf);

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
            /* Get arguments. */
            int fd = get_arg (f->esp + WORD_SIZE, f->esp);
            void *ptr = (void *) get_arg (f->esp + 2 * WORD_SIZE, f->esp);

            /* Check the pointer. */
            // check_arg (ptr, f->esp);

            f->eax = sys_mmap (fd, ptr);
            break;
        }
        case SYS_MUNMAP:
        {
            int mmap_id = get_arg (f->esp + WORD_SIZE, f->esp);
            sys_munmap(mmap_id);
            break;
        }
        // case SYS_CHDIR:
        // {
        //  break;
        // }
        // case SYS_MKDIR:
        // {
        //  break;
        // }         
        // case SYS_READDIR:
        // {
        //  break;
        // }         
        // case SYS_ISDIR:
        // {
        //  break;
        // }
        // case SYS_INUMBER:
        // {
        //  break;
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

    // printf("check arg in spte %p with spte->upage %p in process %s\n", spte, spte->upage, thread_name ());

    if (!spte)
        sys_exit (ERROR);

    spte = get_page (p);

    // printf("spte %p for p %p with spte->upage %p, spte loaded %d\n", spte, p, spte->upage/*, p*/, spte->swap_idx);


    if (spte && spte->swap_idx == LOADED)
        return;

    if (!spte && p >= esp - 32)
    {
        void *page_p = pg_round_down (p);

        if (PHYS_BASE - page_p > MAX_STACK_SIZE)
            sys_exit (ERROR);
        
        // printf("create stack page in process %s\n", thread_name ());
        spte = create_page (page_p, PAL_USER | PAL_ZERO, WRITABLE | SWAP);
    }

    if (spte && load_page (spte))
    {
        // printf("success in loading page %p with upage %p\n", spte, spte->upage);
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

/* Function that is called when SYS_MMAP invoked. Creates a SPT
   entry for the file of file descriptor fd. */
int
sys_mmap (int fd, void *upage)
{
    /* Check the pointer for user page - if it page aligned, if
       it is from user virtual address space, or if it is less
       than the start of the paging address. */
    if ((uint32_t) upage % PGSIZE != 0 || 
        !is_user_vaddr (upage) ||
        upage < (void *) 0x08048000)
        return ERROR;

    // printf("%p\n", upage);


    /* Get the file from file descriptor. If no such file exists
       within this thread's opened files list, then return error. */
    struct file_meta *fm = get_file (fd);
    if (!fm || file_length(fm->file) == 0) return ERROR;

    /* Make sure that meta file has file linked to it. */
    ASSERT(fm->file != NULL);

    /* Get the file. Have to reopen it in case it has been closed by
       process. */
    struct file *file = file_reopen (fm->file);

    /* Initialize attributes for Memory-mapped file SPT entry. */
    uint32_t read_bytes = file_length (file);
    uint32_t page_read_bytes = 0;
    uint32_t page_zero_bytes = 0;
    uint32_t ofs = 0;
    int mmap_id = thread_current ()->mmap_id++;
   // printf("ID: %s\n", thread_current()->mmap_id );
    /* Unless we finish reading whole file. */
    while (read_bytes > 0) 
    {
        page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        page_zero_bytes = PGSIZE - page_read_bytes;

        /* If the page that mapping tries to map exists, then 
           return fail. */
        if (get_page (upage))
            return ERROR;

        /* Create page for the file. */
        struct spte *spte = create_page (upage, PAL_USER, FILE | WRITABLE);

        spte->file = file;
        spte->read_bytes = page_read_bytes;
        spte->zero_bytes = page_zero_bytes;
        spte->ofs = ofs;
        /* By default, when we create page, it indicates that it is
           loaded, but in this case it should be not loaded. */
        spte->swap_idx = NOT_LOADED;
        spte->mmap_id = mmap_id;
        list_push_back (&thread_current ()->spte_files, &spte->l_elem);

        read_bytes -= page_read_bytes;
        ofs += page_read_bytes;
        upage += PGSIZE;
    }

    return mmap_id;
}

/* Function that is called when SYS_MMAP invoked. Creates a SPT
   entry for the file of file descriptor fd. */
void 
sys_munmap (int mmap_id)
{   
    page_unmap (mmap_id);
}

