#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include <lib/kernel/console.h>


static int get_int_32(const void*);
static int get_user(const uint8_t*);
static void sys_exit(int);
static void sys_write(struct intr_frame *f);

static void syscall_handler (struct intr_frame *);

void exit(int code)
{
	sys_exit(code);
}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	//intr_dump_frame(f);
	int reg = get_int_32(f->esp); 
	//printf ("ESP: %d \n", reg);

//printf ("system call!\n");
switch(reg)
	{
 	case SYS_EXIT: sys_exit(get_int_32(f->esp+4));
			//printf("SYS EXIT \n");
			break;
	case SYS_WRITE: 
			sys_write(f); break;
	
	default:
	{
		//printf ("ESP: %d \n", reg);
 		//thread_exit ();
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
 	//test argument passing. write to console
 	const char* buf;
 	size_t size;
 
 	memcpy(&buf, f->esp + 8, 4);
 	memcpy(&size, f->esp + 12, 4);
 
 	putbuf(buf, size);

	f->eax = size;
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

 
