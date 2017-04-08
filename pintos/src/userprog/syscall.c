#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include <lib/kernel/console.h>
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static int get_user(const uint8_t* uaddr);

static int ptr_to_int(const void*);
static void sys_exit(int);
static void sys_write(struct intr_frame *f);
static int sys_filesize(int fd);
static void syscall_handler (struct intr_frame *);
static void sys_create(struct intr_frame *f);
static void sys_open(struct intr_frame *f);
static void sys_read(struct intr_frame *f);
static void sys_remove(struct intr_frame *f);
static int get_arg (void *);
static void sys_exit (int);
static int sys_exec (char *);
static int sys_wait (struct intr_frame* f);
static int push_file(struct file* file);
static void sys_close(struct intr_frame *f);
static void sys_seek(int, unsigned);
static unsigned sys_tell(int);
static struct fd* find_file(struct list* files, int file_descriptor);
static struct lock files_lock;

#define WORD_SIZE 4


static struct fd {
	struct file* file;
	int descriptor;
	struct list_elem elem;
};

void exit(int code)
{
	sys_exit(code);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&files_lock);

}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int reg = ptr_to_int(f->esp); 
	/* Switch the sys calls according to the value of register*/
	switch(reg)
	{

		case SYS_EXIT:
		{	
			/* Get first argument. */
			int status = ptr_to_int (f->esp + WORD_SIZE);
			sys_exit (status);
			break;
		}
	case SYS_WRITE: 
		sys_write(f); 
		break;

	case SYS_CREATE:
		sys_create(f);
		break;
	case SYS_OPEN:
		sys_open(f);
		break;
	case SYS_CLOSE:
		sys_close(f);
		break;
	case SYS_READ:
		sys_read(f);
		break;
	case SYS_REMOVE:
		sys_remove(f);
		break;
		case SYS_WAIT:
		{
			f->eax = sys_wait(f);
			break;
		}

	case SYS_EXEC:
		{
			f->eax = sys_exec ((char *) ptr_to_int (f->esp + WORD_SIZE));
			break;
		}
	case SYS_FILESIZE: f->eax = sys_filesize(ptr_to_int(f->esp+WORD_SIZE));
			break;
	case SYS_SEEK: sys_seek(ptr_to_int(f->esp+4), (unsigned)ptr_to_int(f->esp+8));
			break;
	case SYS_TELL: f->eax = (unsigned) sys_tell(ptr_to_int(f->esp+4));
			break;

	case SYS_HALT:
			break;
			
	default:
		{
 		exit(-1);
		}
	}
}


static void 
sys_exit (int status)
{
	/* Print exit message. */
	printf ("%s: exit(%d)\n", thread_name (), status);
	set_status (status);
	struct fd* fd;
	struct list_elem* e;

	for(e = list_begin(&thread_current()->files);
			e != list_end(&thread_current()->files);)
	{
		fd = list_entry(e, struct fd, elem);
		e = list_remove(e);
		file_close(fd->file);
		free(fd);
	}
	thread_exit ();
	NOT_REACHED ();

}

/* For pushing the file in the list with all filed of the current thread
and uncrementing the fd (needed for open-twice and close-twice test, because every time the file opens 
it should have different fds).
Returns the new fd of a given file */
static int push_file(struct file* file) {
	struct fd* fd = malloc(sizeof(struct fd));
	lock_acquire(&files_lock);
	fd->file = file;

	fd->descriptor = thread_current()->fd;
	thread_current()->fd++;

	list_push_back(&thread_current()->files, &fd->elem);
	lock_release(&files_lock);

	return fd->descriptor;
}

/* Opens the file with the given name. Returns -1 if the file is NULL.
Does nothing if the name is NULL */
static void sys_open(struct intr_frame *f) {
	
	/* Pull arguments from stack */
	char *name = (char*)ptr_to_int(f->esp+WORD_SIZE);
	struct file* file;

	if(name==NULL) return;
	lock_acquire(&files_lock);
	/* Try to open the file */
	file = filesys_open(name);
 	lock_release(&files_lock);
	if(file==NULL) 
		f->eax = -1;
	else 
		f->eax = push_file(file);
	return;
}

static void sys_remove(struct intr_frame *f) {
		lock_acquire(&files_lock);
		const char* name = (const char*)ptr_to_int(f->esp+WORD_SIZE);
		f->eax = filesys_remove(name);
		lock_release(&files_lock);
		return;

}

static void sys_read(struct intr_frame *f) {

	char* buf;
 	size_t size;

 	/* Pull arguments from stack */

	int fd = ptr_to_int(f->esp+WORD_SIZE);
 	size= ptr_to_int(f->esp+3*WORD_SIZE);
 	buf = ptr_to_int(f->esp+2*WORD_SIZE);

 	 /* Validate the pointer */

 	if (buf+size > PHYS_BASE) exit(-1);

 	if (size==0) {
 		f->eax = 0;
 		return;
 	}
 	if (!lock_held_by_current_thread (&files_lock)) 
		lock_acquire(&files_lock);

 	if (fd == 1) {
 		f->eax = size;
 		lock_release(&files_lock);
 		return;
 	}
 	else {
 		struct fd* file_descriptor = find_file(&thread_current()->files, fd);
 		f->eax = file_read(file_descriptor->file, buf, size);
 		lock_release(&files_lock);
 		return;
 	}

 	
}

/* Creates the file with the given name and size;
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails */
static void sys_create(struct intr_frame *f) {
	bool created;
	/* Pull arguments from stack */
	char *file = (char*)ptr_to_int(f->esp+WORD_SIZE);

	int initial_size = (size_t)ptr_to_int(f->esp+2*WORD_SIZE);

	lock_acquire(&files_lock);
	if(file==NULL) exit(-1);
	created = filesys_create (file,initial_size); 
	lock_release(&files_lock);

	f->eax = created;
}

/* Writes either to console or to the file. Returns -1 if failed,
size in bytes of the written text if successfull */
 static void sys_write(struct intr_frame *f)
 {
 	const char* buf;
 	size_t size;

 	size= ptr_to_int(f->esp+3*WORD_SIZE);
 	buf = ptr_to_int(f->esp+2*WORD_SIZE);

 	/*Check the pointer and if it is possible to write the whole text there */
 	if(buf+size > PHYS_BASE ) exit(-1);
 	if(size<=0) {
 		f->eax = 0;
 		return; 
 	} 
 	int fd = ptr_to_int(f->esp+WORD_SIZE);

 	/* Return an error */
 	if (fd==0) 
 		f->eax=-1;
 	/*Write to console */
 	else if (fd==1) {
 	
 		putbuf(buf, size);

		f->eax = size;
	}
	/*Write to file */
	else {
		/*Find the file and if it exists write to it */
		struct fd* file_descriptor = find_file(&thread_current()->files, fd);
		lock_acquire(&files_lock);
		f->eax = file_write(file_descriptor->file, buf, size);
		lock_release(&files_lock);		
	}
}	

static void sys_close(struct intr_frame *f)
{
	int file_descriptor = ptr_to_int(f->esp+WORD_SIZE);
	/* find such fd */
	struct fd* fd = find_file(&thread_current()->files, file_descriptor);

	if(fd)
	{
		lock_acquire(&files_lock);
		file_close(fd->file);
		lock_release(&files_lock);
		list_remove(&fd->elem);
		free(fd);
	}
}

/* Function for findint the file desctiptor in the list of files of the current
thread. Returns NULL if nothing was found, struct fd if the descriptor was found */
static struct fd* find_file(struct list* files, int file_descriptor) {
	struct fd* fd = NULL;
	struct fd* tmp = malloc(sizeof(struct fd));

	struct list_elem* e;
	for(e = list_begin(&thread_current()->files);
			e != list_end(&thread_current()->files);
			e = list_next(e))
	{
		tmp = list_entry(e, struct fd, elem);
		if (tmp->descriptor == file_descriptor )
		{
			fd = tmp;
			break;
		}
	}
	return fd;
}



int
sys_wait (struct intr_frame* f) 
{	
	/* NOTE: Read 3.3.4 about this system call. */

	/* Wait for the given tid to terminate. */

	tid_t tid = ptr_to_int(f->esp+WORD_SIZE);

	return process_wait (tid);
}

   
/* Executes the file with a given file_name*/
int
sys_exec (char *file_name) 
{

	return process_execute (file_name);
}


/* Returns the file_length of the file with given fd (size in bytes),
returns -1 if the file doesn't exist */
static int sys_filesize(int fd)
{

	struct fd* file_descriptor = find_file(&(thread_current()->files), fd);
	if (file_descriptor)
	{
		return file_length(file_descriptor->file);
	}
	return -1;
}

/* Sets the current position in file with given fd to position bytes from the
   start of the file. */
static void sys_seek(int fd, unsigned position)
{
	struct fd* file_descriptor = find_file(&thread_current()->files, fd);
	if(file_descriptor)
	{
		lock_acquire(&files_lock);
		file_seek(file_descriptor->file, position);
		lock_release(&files_lock);
	}
}

/* Returns the current position in FILE with given fd as a byte offset from the
   start of the file. */
static unsigned sys_tell(int fd)
{
	struct fd* file_descriptor = find_file(&thread_current()->files, fd);
	unsigned ret = 0;
	if(file_descriptor)
	{
		lock_acquire(&files_lock);
		ret = file_tell(file_descriptor->file);
		lock_release(&files_lock);
	}
	return ret;
}

/* Function for converting esp register to the int value and checking
if it's below the PHYS_BASE */

static int ptr_to_int(const void* ptr)
{
	if (ptr>= PHYS_BASE) exit(-1);
	int i;
	for (i = 0; i < 4; ++i)
	{
		if (get_user(ptr+i) == -1)
			exit(-1);
	}
	return *((int *)ptr);
}

/*Code from the reference */
static int get_user(const uint8_t* uaddr)
{
	int result;
	asm("movl $1f, %0; movzbl %1, %0; 1:"
			: "=&a" (result) : "m" (*uaddr));
	return result;
}

 
