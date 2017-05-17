#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

#define ERROR -1          /* Unsuccessful execution. */
void sys_exit (int);
void remove_mmap ();

#endif /* userprog/syscall.h */
