#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "devices/input.h"

/* syscall handler -- to distribute different syscall to 
  different syscall functions */
static void syscall_handler (struct intr_frame *);
/* functions to deal with syscall */
static void syscall_halt(struct intr_frame *f);
static void syscall_exit(struct intr_frame *f);
static void syscall_write(struct intr_frame *f);
static void syscall_wait(struct intr_frame *f);
static void syscall_execute(struct intr_frame *f);
static void syscall_create(struct intr_frame *f);
static void syscall_remove(struct intr_frame *f);
static void syscall_open(struct intr_frame *f);
static void syscall_filesize(struct intr_frame *f); 
static void syscall_read(struct intr_frame *f);
static void syscall_seek(struct intr_frame *f);
static void syscall_tell(struct intr_frame *f);
static void syscall_close(struct intr_frame *f);

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* check read pointer address */
static void*
read_ptrCheck(const void* pointer, size_t size){
  if(!is_user_vaddr(pointer)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  for(unsigned i=0;i<size;i++){
    if(get_user((unsigned char*)pointer+i) == -1){
      thread_current()->exit_code = -1;
      thread_exit();
    }
  }
  return (void*)pointer;
}

/* check write pointer address */
static void*
write_ptrCheck(const void* pointer, size_t size){
  if(!is_user_vaddr(pointer)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  for(unsigned i=0;i<size;i++){
    if(put_user((unsigned char*)pointer+i, 0) == false){
      thread_current()->exit_code = -1;
      thread_exit();
    }
  }
  return (void*)pointer;
}

/* check string provided by user */
static char*
string_check(const char* str){
  if(!is_user_vaddr(str)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  uint8_t* str_modify = (uint8_t*)str;
  while(1){
    int tag = get_user(str_modify);
    if(tag == -1){
      thread_current()->exit_code = -1;
      thread_exit();
    }else if(tag == '\0'){
      return (char*)str;
    }
    str_modify++;
  }
}

static struct file_entry*
fdtofile(int fd){
  struct thread* cur = thread_current();
  struct list_elem* e;
  for(e = list_begin(&cur->open_file); e != list_end(&cur->open_file); e = list_next(e)){
    struct file_entry* f = list_entry(e, struct file_entry, elem);
    if(f->fd == fd){
      return f;
    }
  }
  return NULL;

}

/* initialize syscall */
void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f ) 
{
  int syscall_number = *(int*)read_ptrCheck(f->esp,sizeof(int));
  switch(syscall_number)
  {
    case SYS_HALT:
      syscall_halt(f);
      break;
    case SYS_EXIT:
      syscall_exit(f);
      break;
    case SYS_WAIT:
      syscall_wait(f);
      break;
    case SYS_EXEC:
      syscall_execute(f);
      break;
    case SYS_WRITE:
      syscall_write(f);
      break;
    case SYS_CREATE:
      syscall_create(f);
      break;
    case SYS_REMOVE:
      syscall_remove(f);
      break;
    case SYS_OPEN:
      syscall_open(f);
      break;
    case SYS_FILESIZE:
      syscall_filesize(f);
      break;
    case SYS_READ:
      syscall_read(f);
      break;
    case SYS_SEEK:
      syscall_seek(f);
      break;
    case SYS_TELL:
      syscall_tell(f);
      break;
    case SYS_CLOSE:
      syscall_close(f);
      break;
    default:
      NOT_REACHED();
  }
}

static void
syscall_halt(struct intr_frame *f UNUSED)
{
  shutdown_power_off();
}

static void
syscall_exit(struct intr_frame *f)
{
  int exit_code = *(int*)read_ptrCheck(f->esp + 4,sizeof(int));
  thread_current()->exit_code = exit_code;
  thread_exit();
}

static void
syscall_write(struct intr_frame *f)
{
  int fd = *(int*)read_ptrCheck(f->esp + 4,sizeof(int));
  char* buffer = *(char**)read_ptrCheck(f->esp + 8,sizeof(char*));
  unsigned size = *(unsigned*)read_ptrCheck(f->esp + 12,sizeof(unsigned));
  read_ptrCheck(buffer, size);
  if(fd == 0){
    f->eax = -1;
    return;
  }
  if(fd == 1){
    putbuf(buffer, size);
    f->eax = size;
    return;
  }
  struct file_entry* file = fdtofile(fd);
  if(file == NULL ){
    f->eax = -1;
    return;
  }
  lock_acquire(&file_lock);
  f->eax = file_write(file->fptr, buffer, size);
  lock_release(&file_lock);
}

static void
syscall_wait(struct intr_frame *f)
{
  tid_t tid = *(tid_t*)read_ptrCheck(f->esp + 4,sizeof(tid_t));
  f->eax = process_wait(tid);
}

static void
syscall_execute(struct intr_frame *f)
{
  char* cmd_line = *(char**)read_ptrCheck(f->esp + 4,4);
  string_check(cmd_line);/* important! check for if cmdline valid */
  f->eax = process_execute(cmd_line);
}

static void
syscall_create(struct intr_frame *f)
{
  char* name = *(char**)read_ptrCheck(f->esp + 4,sizeof(char*));
  string_check(name);
  unsigned initial_size = *(unsigned*)read_ptrCheck(f->esp + 8,sizeof(unsigned));
  lock_acquire(&file_lock);
  bool success = filesys_create(name, initial_size);
  f->eax = success;
  lock_release(&file_lock);
}

static void
syscall_open(struct intr_frame* f){
  char* name = *(char**)read_ptrCheck(f->esp + 4,sizeof(char*));
  string_check(name);

  lock_acquire(&file_lock);
  struct file* file = filesys_open(name);
  if(file == NULL){
    lock_release(&file_lock);
    f->eax = -1;
    return;
  }
  lock_release(&file_lock);

  struct thread* cur = thread_current();
  struct file_entry* new_entry = (struct file_entry*)malloc(sizeof(struct file_entry));
  new_entry->fptr = file;
  new_entry->fd = cur->fd_num;
  cur->fd_num++;
  list_push_back(&cur->open_file, &new_entry->elem);
  f->eax = new_entry->fd;
}

static void
syscall_remove(struct intr_frame* f){
  char* name = *(char**)read_ptrCheck(f->esp + 4,sizeof(char*));
  string_check(name);
  lock_acquire(&file_lock);
  bool success = filesys_remove(name);
  if(!success){
    lock_release(&file_lock);
    f->eax = -1;
    return;
  }
  lock_release(&file_lock);
  f->eax = success;
}

static void
syscall_filesize(struct intr_frame* f){
  int fd = *(int*)read_ptrCheck(f->esp + 4,sizeof(int));
  struct file_entry* file = fdtofile(fd);
  if(file == NULL){
    f->eax = -1;
    return;
  }
  lock_acquire(&file_lock);
  f->eax = file_length(file->fptr);
  lock_release(&file_lock);
}

static void
syscall_read(struct intr_frame* f){
  int fd = *(int*)read_ptrCheck(f->esp + 4,sizeof(int));
  char* buffer = *(char**)read_ptrCheck(f->esp + 8,sizeof(char*));
  unsigned size = *(unsigned*)read_ptrCheck(f->esp + 12,sizeof(unsigned));
  write_ptrCheck(buffer, size);
  if(fd == 0){
    for(unsigned i=0;i<size;i++){
      buffer[i] = input_getc();
    }
    f->eax = size;
    return;
  }
  if(fd == 1){
    f->eax = -1;
    return;
  }
  struct file_entry* file = fdtofile(fd);
  if(file == NULL){
    f->eax = -1;
    return;
  }
  lock_acquire(&file_lock);
  f->eax = file_read(file->fptr, buffer, size);
  lock_release(&file_lock);
}

static void
syscall_seek(struct intr_frame* f){
  int fd = *(int*)read_ptrCheck(f->esp + 4,sizeof(int));
  unsigned position = *(unsigned*)read_ptrCheck(f->esp + 8,sizeof(unsigned));
  struct file_entry* file = fdtofile(fd);
  if(file == NULL){
    return;
  }
  lock_acquire(&file_lock);
  file_seek(file->fptr, position);
  lock_release(&file_lock);
}

static void
syscall_tell(struct intr_frame* f){
  int fd = *(int*)read_ptrCheck(f->esp + 4,sizeof(int));
  struct file_entry* file = fdtofile(fd);
  if(file == NULL){
    f->eax = -1;
    return;
  }
  lock_acquire(&file_lock);
  f->eax = file_tell(file->fptr);
  lock_release(&file_lock);
}

static void
syscall_close(struct intr_frame* f){
  int fd = *(int*)read_ptrCheck(f->esp + 4,sizeof(int));
  struct file_entry* file = fdtofile(fd);
  if(file == NULL){
    return;
  }
  lock_acquire(&file_lock);
  file_close(file->fptr);
  list_remove(&file->elem);
  free(file);
  lock_release(&file_lock);
}