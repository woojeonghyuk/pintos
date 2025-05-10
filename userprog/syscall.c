#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/pte.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "threads/pte.h"

#define STDIN_FILENO 0
#define STDOUT_FILENO 1


void halt(void);
void exit(int status);
int wait(int pid);
int write(int fd, const void *buffer, unsigned size);
static int allocate_fd(void);

static bool create(const char *file_name, unsigned initial_size);
static bool remove(const char *file_name);
static int open(const char *file_name);
static int filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);
static void close_open_file(int fd);

struct file_descriptor {
  int fd_num;                 
  tid_t owner;                
  struct file *file_struct;   
  struct list_elem elem;      
};

static struct list open_files;
static struct lock fs_lock;
static int fd_count = 2;

static void syscall_handler(struct intr_frame *f);
static bool is_valid_ptr(const void *ptr);

static int
allocate_fd(void) {
    return fd_count++;  
}

void
syscall_init (void) 
{
  list_init(&open_files);
  lock_init(&fs_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f) 
{
  if (!is_valid_ptr(f->esp))
    exit(-1);

  int syscall_num = *(int *)(f->esp);

  switch (syscall_num)
  {
      case SYS_CREATE: {
        const char *file_name = *((const char **)(f->esp + 4));
        unsigned initial_size = *((unsigned *)(f->esp + 8));
        f->eax = create (file_name, initial_size);
        break;
    }
    case SYS_REMOVE: {
        const char *file_name = *((const char **)(f->esp + 4));
        f->eax = remove (file_name);
        break;
    }
    case SYS_OPEN: {
        const char *file_name = *((const char **)(f->esp + 4));
        f->eax = open (file_name);
        break;
    }
    case SYS_FILESIZE: {
        int fd = *((int *)(f->esp + 4));
        f->eax = filesize (fd);
        break;
    }
    case SYS_READ: {
        int fd = *((int *)(f->esp + 4));
        void *buffer = *((void **)(f->esp + 8));
        unsigned size = *((unsigned *)(f->esp + 12));
        f->eax = read (fd, buffer, size);
        break;
    }
    case SYS_SEEK: {
        int fd = *((int *)(f->esp + 4));
        unsigned position = *((unsigned *)(f->esp + 8));
        seek (fd, position);
        break;
    }
    case SYS_TELL: {
        int fd = *((int *)(f->esp + 4));
        f->eax = tell (fd);
        break;
    }
    case SYS_CLOSE: {
        int fd = *((int *)(f->esp + 4));
        close (fd);
        break;
    }
    case SYS_HALT:
      halt();
      break;

    case SYS_EXIT:
      if (!is_valid_ptr(f->esp + 4))
        exit(-1);
      int status = *(int *)(f->esp + 4);
      exit(status);
      break;

    case SYS_WAIT:
      if (!is_valid_ptr(f->esp + 4))
        exit(-1);
      int pid = *(int *)(f->esp + 4);
      f->eax = wait(pid);
      break;

    case SYS_WRITE: {
      int fd = *((int*) (f->esp + 4));
      void *buffer = *((void**) (f->esp + 8));
      unsigned size = *((unsigned*) (f->esp + 12));
    
      f->eax = write(fd, buffer, size);
      break;
    }

    default:
      exit(-1);
  }
}

bool is_valid_ptr(const void *usr_ptr) {
  struct thread *cur = thread_current();
  return usr_ptr != NULL &&
         is_user_vaddr(usr_ptr) &&
         pagedir_get_page(cur->pagedir, usr_ptr) != NULL;
}

void
halt(void)
{
  shutdown_power_off();
}

void
exit(int status)
{
  struct thread *cur = thread_current();
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}

int
wait(int pid)
{
  return process_wait(pid);
}

static struct file_descriptor *
get_open_file(int fd) {
    struct list_elem *e;
    for (e = list_begin(&open_files); e != list_end(&open_files); e = list_next(e)) {
        struct file_descriptor *f = list_entry(e, struct file_descriptor, elem);
        if (f->fd_num == fd && f->owner == thread_current()->tid) {
            return f;
        }
    }
    return NULL;  
}

int
write(int fd, const void *buffer, unsigned size) {
    int bytes_written = 0;

    if (buffer == NULL || !is_valid_ptr(buffer) || 
        (size > 0 && !is_valid_ptr((uint8_t *) buffer + size - 1))) {
        /* Invalid pointer, terminate the process. */
        exit(-1);
    }
    lock_acquire(&fs_lock);

    if (fd == 1) {
        putbuf(buffer, size);         
        bytes_written = size;         
    } else if (fd == 0) {
        bytes_written = -1;
    } else {
        struct file_descriptor *f = get_open_file(fd);
        if (f == NULL || f->file_struct == NULL) {
            bytes_written = -1;
        } else {
            bytes_written = file_write(f->file_struct, buffer, size);
        }
    }
    lock_release(&fs_lock);
    return bytes_written;
}

bool
create (const char *file_name, unsigned initial_size) {
    if (!is_valid_ptr (file_name))
        exit(-1);

    lock_acquire (&fs_lock);
    bool success = filesys_create (file_name, initial_size);
    lock_release (&fs_lock);

    return success;
}

bool
remove (const char *file_name) {
    if (!is_valid_ptr (file_name))
        exit(-1);

    lock_acquire (&fs_lock);
    bool success = filesys_remove (file_name);
    lock_release (&fs_lock);

    return success;
}

int
open (const char *file_name) {
    if (!is_valid_ptr (file_name))
        exit(-1);

    lock_acquire (&fs_lock);
    struct file *f = filesys_open (file_name);
    if (f == NULL) {
        lock_release (&fs_lock);
        return -1;
    }

    struct file_descriptor *fd_struct = malloc (sizeof *fd_struct);
    if (!fd_struct) {
        file_close (f);
        lock_release (&fs_lock);
        return -1;
    }
    fd_struct->fd_num = allocate_fd ();
    fd_struct->owner = thread_current ()->tid;
    fd_struct->file_struct = f;
    list_push_back (&open_files, &fd_struct->elem);

    lock_release (&fs_lock);
    return fd_struct->fd_num;
}

int
filesize (int fd) {
    struct file_descriptor *fd_struct = get_open_file (fd);
    if (!fd_struct)
        return -1;

    lock_acquire (&fs_lock);
    int size = file_length (fd_struct->file_struct);
    lock_release (&fs_lock);

    return size;
}

int
read (int fd, void *buffer, unsigned size) {
    if (!is_valid_ptr (buffer))
        exit(-1);

    int bytes_read = 0;
    lock_acquire (&fs_lock);

    if (fd == STDIN_FILENO) {
        uint8_t *buf = buffer;
        for (; bytes_read < (int)size; bytes_read++)
            buf[bytes_read] = input_getc (); 
    }
    else {
        struct file_descriptor *fd_struct = get_open_file (fd);
        if (!fd_struct) {
            lock_release (&fs_lock);
            return -1;
        }
        bytes_read = file_read (fd_struct->file_struct, buffer, size);
    }

    lock_release (&fs_lock);
    return bytes_read;
}

void
seek (int fd, unsigned position) {
    struct file_descriptor *fd_struct = get_open_file (fd);
    if (!fd_struct)
        return;

    lock_acquire (&fs_lock);
    file_seek (fd_struct->file_struct, position);
    lock_release (&fs_lock);
}

unsigned
tell (int fd) {
    struct file_descriptor *fd_struct = get_open_file (fd);
    if (!fd_struct)
        return 0;

    lock_acquire (&fs_lock);
    unsigned pos = file_tell (fd_struct->file_struct);
    lock_release (&fs_lock);

    return pos;
}

void
close (int fd) {
    lock_acquire (&fs_lock);
    close_open_file (fd);
    lock_release (&fs_lock);
}

void
close_open_file (int fd) {
    struct file_descriptor *fd_struct = get_open_file (fd);
    if (!fd_struct)
        return;

    file_close (fd_struct->file_struct);
    list_remove (&fd_struct->elem);
    free (fd_struct);
}