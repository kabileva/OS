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

static int ptr_to_int(const void*);
static void sys_exit(int);
static void sys_write(struct intr_frame *f);

static void syscall_handler (struct intr_frame *);
static void sys_create(struct intr_frame *f);
static void sys_open(struct intr_frame *f);
static void sys_read(struct intr_frame *f);

static struct lock files_lock;


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

	lock_acquire(&files_lock);
	/* Try to open the file */
	if(filesys_open(name)==NULL) f->eax=-1; 
	lock_release(&files_lock);

}

static void sys_read(struct intr_frame *f) {
	const char* buf;
 	size_t size;

 	size= ptr_to_int(f->esp+12);
 	buf = ptr_to_int(f->esp+8);
 	/* Validate the pointer */
 	if (buf+size-1 >= PHYS_BASE) exit(-1);

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

 	size= ptr_to_int(f->esp+12);
	
 	int fd = ptr_to_int(f->esp+4);

 	if (fd==0) 
 		f->eax=-1;
 	else if (fd==1) {
 	
 	memcpy(&buf, f->esp + 8, 4);
 	memcpy(&size, f->esp + 12, 4);

 	putbuf(buf, size);

	f->eax = size;
	}

	return -1;
}	

/* Function for converting esp register to the int value */

static int ptr_to_int(const void* ptr)
 
   {
    if (ptr>= PHYS_BASE) exit(-1);
	
	return *((int *)ptr);
}

 
