#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include <lib/kernel/console.h>
#include "threads/synch.h"

static int get_int_32(const void*);
static int get_user(const uint8_t*);
static void sys_exit(int);
static void sys_write(struct intr_frame *f);

static void syscall_handler (struct intr_frame *);

static struct lock file_sys_lock;


void exit(int code)
{
	sys_exit(code);
}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_sys_lock);

}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int reg = get_int_32(f->esp); 

switch(reg)
	{
 	case SYS_EXIT: sys_exit(get_int_32(f->esp+4));
			break;
	case SYS_WRITE: 
			sys_write(f); break;

	
	default:
	{
 		exit(-1);
	}
}
		
  //thread_exit ();
}

static void sys_exit(int code) {

	printf( "%s: exit(%d)\n", thread_name(), code);
	thread_exit ();
	NOT_REACHED ();
}

 static void sys_write(struct intr_frame *f)
 {
 	const char* buf;
 	size_t size;

 	size= get_int_32(f->esp+12);
	
 	int fd = get_int_32(f->esp+4);
 	
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

static int get_user(const uint8_t* uaddr)
{
	int result;
	asm("movl $1f, %0; movzbl %1, %0; 1:"
			: "=&a" (result) : "m" (*uaddr));
	return result;
}

static int get_int_32(const void* ptr_)
 
   {
   	if (ptr_ >= PHYS_BASE) exit(-1);
	uint8_t *ptr = ptr_;
	int i;
	for (i = 0; i < 4; ++i)
	{
		if (get_user(ptr+i) == -1)
			exit(-1);
	}
	return *((int *)ptr);
}

 
