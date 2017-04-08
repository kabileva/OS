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

struct list* files;
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
  list_init(&files);

}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int reg = ptr_to_int(f->esp); 

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
			/* NOTE: used tid_t instead of pid_t. I don't see any problem
			   that it could cause. */

			/* Get first argument. */
			f->eax = sys_wait(f);
			break;
		}

	case SYS_EXEC:
		{
			/* Get first argument. */
			char *file_name = (char *) ptr_to_int (f->esp + WORD_SIZE);
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

static void sys_open(struct intr_frame *f) {
	
	/* Pull arguments from stack */
	char *name = (char*)ptr_to_int(f->esp+4);
	struct file* file;

	if(name==NULL) return;
	lock_acquire(&files_lock);
	/* Try to open the file */
	file = filesys_open(name);
 	lock_release(&files_lock);
	if(file==NULL) {
		f->eax = -1;
	}
	else {
		 f->eax = push_file(file);
     	} 
	return;
}

static void sys_remove(struct intr_frame *f) {
		lock_acquire(&files_lock);
		const char* name = (const char*)ptr_to_int(f->esp+4);
		f->eax = filesys_remove(name);
		lock_release(&files_lock);
		return;

}

static void sys_read(struct intr_frame *f) {

	char* buf;
 	size_t size;
	/*Try to acquire the lock if it's still not held
 	by the current thread */
	
	int fd = ptr_to_int(f->esp+WORD_SIZE);
 	size= ptr_to_int(f->esp+12);
 	buf = ptr_to_int(f->esp+8);
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


static void sys_create(struct intr_frame *f) {
	bool created;
	/* Pull arguments from stack */
	char *file = (char*)ptr_to_int(f->esp+4);

	int initial_size = (size_t)ptr_to_int(f->esp+8);
	lock_acquire(&files_lock);
	if(file==NULL) exit(-1);
	created = filesys_create (file,initial_size); 
	lock_release(&files_lock);

	f->eax = created;
}

 static void sys_write(struct intr_frame *f)
 {
 	const char* buf;
 	size_t size;
 	/*Try to acquire the lock if it's still not held
 	by the current thread */
	if (!lock_held_by_current_thread (&files_lock)) 
		lock_acquire(&files_lock);
	lock_release(&files_lock);

 	size= ptr_to_int(f->esp+12);
 	buf = ptr_to_int(f->esp+8);
 	if(buf+size > PHYS_BASE || get_user(buf) == -1) exit(-1);
 	if(size<=0) {
 		f->eax = 0;
 		return; 
 	} 
 	int fd = ptr_to_int(f->esp+4);

 	if (fd==0) 
 		f->eax=-1;
 	/*Write to console */
 	else if (fd==1) {
 	
 		putbuf(buf, size);

		f->eax = size;
	}
	/*Write to file */
	else {

		struct fd* file_descriptor = find_file(&thread_current()->files, fd);
		if (file_descriptor) {
		lock_acquire(&files_lock);
		f->eax = file_write(file_descriptor->file, buf, size);
		lock_release(&files_lock);
	}	
	else f->eax = 0;
		

	}

	return -1;
}	

static void sys_close(struct intr_frame *f)
{
	int file_descriptor = ptr_to_int(f->esp+WORD_SIZE);
	/* find such fd */
	struct fd* ret = find_file(&thread_current()->files, file_descriptor);

	if(ret)
	{
		lock_acquire(&files_lock);
		file_close(ret->file);
		lock_release(&files_lock);

		list_remove(&ret->elem);
		free(ret);
	}
}

static struct fd* find_file(struct list* files, int file_descriptor) {
	struct fd* ret = NULL;
	struct fd* tmp = malloc(sizeof(struct fd));

	struct list_elem* e;
	for(e = list_begin(&thread_current()->files);
			e != list_end(&thread_current()->files);
			e = list_next(e))
	{
		tmp = list_entry(e, struct fd, elem);
		if (tmp->descriptor == file_descriptor )
		{
			ret = tmp;
			break;
		}
	}
	return ret;
}


/*Code from the reference */
static int get_user(const uint8_t* uaddr)
{
	int result;
	asm("movl $1f, %0; movzbl %1, %0; 1:"
			: "=&a" (result) : "m" (*uaddr));
	return result;
}
int
sys_wait (struct intr_frame* f) 
{	
	/* NOTE: Read 3.3.4 about this system call. */

	/* Wait for the given tid to terminate. */

	tid_t tid = ptr_to_int(f->esp+WORD_SIZE);

	return process_wait (tid);
}

   
/* Function that is called when SYS_EXEC invoked. Executes given file. */
int
sys_exec (char *file_name) 
{
	/* Execute the command line given. */
	if(file_name >= PHYS_BASE || get_user(file_name) == -1) exit(-1);

	int tid = process_execute (file_name);
}

static int sys_filesize(int fd)
{
	/*
	 * try to find fd in the list of fds, which belong to current process
	 * no need to acquire a lock, because no data racing in this list.
	 * only holder can access this list
	 */
	struct fd* file_descriptor = find_file(&(thread_current()->files), fd);
	int ret = -1;
	if (file_descriptor)
	{
		// if there is such fd, return the length of the file.
		lock_acquire(&files_lock);
		ret = file_length(file_descriptor->file);
		lock_release(&files_lock);
	}
	return ret;
}


static void sys_seek(int fd, unsigned position)
{
	/* find such fd */
	struct fd* file_descriptor = find_file(&thread_current()->files, fd);
	if(file_descriptor)
	{
		// if found, seek
		lock_acquire(&files_lock);
		file_seek(file_descriptor->file, position);
		lock_release(&files_lock);
	}
}


static unsigned sys_tell(int fd)
{
	/* find such fd */
	struct fd* file_descriptor = find_file(&thread_current()->files, fd);
	unsigned ret = 0;
	if(file_descriptor)
	{
		// if found, tell
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

 
