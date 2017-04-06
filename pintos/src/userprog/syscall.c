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

static struct lock files_lock;
struct list* files;

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

switch(reg)
	{
 	case SYS_EXIT: sys_exit(ptr_to_int(f->esp+4));
		break;
	case SYS_WRITE: 
		sys_write(f); break;
	case SYS_CREATE:
		sys_create(f);
		break;
	case SYS_OPEN:
		sys_open(f);
		break;
	case SYS_CLOSE:

		break;
	case SYS_READ:

		sys_read(f);
		break;
	case SYS_REMOVE:
		sys_remove(f);
		break;
	default:
		{
 		exit(-1);
		}
	}
}


static void sys_exit(int code) {

	printf( "%s: exit(%d)\n", thread_name(), code);
	thread_exit ();
	NOT_REACHED ();
}
static void sys_open(struct intr_frame *f) {
	
	/* Pull arguments from stack */
	char *name = (char*)ptr_to_int(f->esp+4);
	if(name==NULL) return;
	struct fd* fd;

	lock_acquire(&files_lock);
	/* Try to open the file */
	struct file* file;
	file = filesys_open(name);
	lock_release(&files_lock);
 
	if(file==NULL) {
		f->eax = -1;
		return;
	}
	else {
		/*Somehow store or change file descriptor */
	} 

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
 	int fd = ptr_to_int(f->esp+4);
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

	lock_release(&files_lock);
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

 
