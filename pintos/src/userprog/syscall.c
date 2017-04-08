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


static int get_user(const uint8_t* uaddr);

static int ptr_to_int(const void*);
static void sys_exit(int);
static void sys_write(struct intr_frame *f);

static void syscall_handler (struct intr_frame *);
static void sys_create(struct intr_frame *f);
static void sys_open(struct intr_frame *f);
static void sys_read(struct intr_frame *f);
static void sys_remove(struct intr_frame *f);
static int get_arg (void *);
static void sys_exit (int);
static int sys_exec (char *);
static int sys_wait (tid_t);
static int push_file(struct file* file);
static void sys_close(struct intr_frame *f);
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
		sys_write(f); break;
	case SYS_CREATE:
		sys_create(f);
		break;
	case SYS_OPEN:
		sys_open(f);
		break;
	case SYS_CLOSE:
		//sys_close(f);
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
			tid_t tid = ptr_to_int (f->esp + WORD_SIZE);

			f->eax = sys_wait (tid);
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
	// printf("finish\n");
	thread_exit ();
}

static int push_file(struct file* file) {
	struct fd* fd = malloc(sizeof(struct fd));
	fd->file = file;
	fd->descriptor = thread_current()->fd;
	thread_current()->fd++;
	list_push_back(&thread_current()->files, &fd->elem);
	return fd->descriptor;
}

static void sys_open(struct intr_frame *f) {
	
	/* Pull arguments from stack */
	char *name = (char*)ptr_to_int(f->esp+4);
	struct file* file;

	if(name==NULL) return;
	int tmp_fd;
	if(tmp_fd<2) tmp_fd = 2;
	else tmp_fd = 1;
	//printf("%d\n", tmp_fd );
	lock_acquire(&files_lock);
	/* Try to open the file */
	file = filesys_open(name);
 	
	if(file==NULL) {
		//printf("NULL \n");

		f->eax = -1;
	}
	else {
		//f->eax = push_file(file);
     	} 
    lock_release(&files_lock);
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
	if (!lock_held_by_current_thread (&files_lock)) 
		lock_acquire(&files_lock);
 	size= ptr_to_int(f->esp+12);
 	buf = ptr_to_int(f->esp+8);

 	 /* Validate the pointer */

 	if (buf+size > PHYS_BASE) exit(-1);

 	if (size==0) {
 		f->eax = 0;
 		return;
 	}

 	lock_release(&files_lock);
 	f->eax = size;
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

	/*Implement using file_write */	

	}

	return -1;
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
sys_wait (tid_t tid)
{	
	/* NOTE: Read 3.3.4 about this system call. */

	/* Wait for the given tid to terminate. */
	return process_wait (tid);
}

   
/* Function that is called when SYS_EXEC invoked. Executes given file. */
int
sys_exec (char *file_name) 
{
	/* Execute the command line given. */
	return process_execute (file_name);
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

 
