#include "config.h"
#if defined(AUDIT_BASH)
#pragma message("Compiling with AUDIT_BASH.")
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#define __USE_BSD
#include <aio.h>
#include <termios.h>
#include <time.h>

#if !defined(AUDIT_FILE_PATH)
#define AUDIT_FILE_PATH "/tmp/bash_audit_XXXXXX.%s"
#endif

#if !defined(AUDIT_SO_PATH)
#define AUDIT_SO_PATH "/lib/libbash_audit.so"
#endif

#if !defined(AUDIT_BUFFER_LEN)
#define AUDIT_BUFFER_LEN 4096
#endif

#define AUDIT_FDM 0
#define AUDIT_FDS 1
#define AUDIT_RC 2
#define TSOURCE 0
#define TDEST 1

#define FDM audit_ptty[AUDIT_FDM]
#define FDS audit_ptty[AUDIT_FDS]
#define RC audit_ptty[AUDIT_RC]

#if defined(AUDIT_DEBUG)
#define AUDIT_LOG syslog
#else
#define AUDIT_LOG audit_null_log
#endif

#if defined(AUDIT_SO_OUTPUT)
#pragma message("Compiling for shared object output.")
typedef void* (*audit_open_fn_t)(const char*, unsigned int);
typedef void (*audit_output_fn_t)(void*, const char*, unsigned int);
typedef void (*audit_close_fn_t)(void*, int);
char* audit_so_path;
void* audit_so_h;
void* audit_h;
audit_open_fn_t audit_open_fn;
audit_output_fn_t audit_output_fn;
audit_close_fn_t audit_close_fn;
#endif // AUDIT_SO_OUTPUT

#if defined(AUDIT_FILE_OUTPUT)
#pragma message("Compiling for file output.")
int audit_fp;
int audit_fp_cmd;
int audit_stop_io;
#endif // AUDIT_FILE_OUTPUT

int last_output;
int last_endio;
int audit_ptty[3];
int audit_pipe_fd[2];
int audit_tty;
int old_stdin;
pthread_t audit_thread;
struct termios audit_ts[2];

extern int last_command_exit_value;

void audit_output(const char* output);

void audit_null_log(int i, const char* fmt, ...)
{
  // Do nothing.
}

void audit_init()
{
#if defined(AUDIT_FILE_OUTPUT)
  audit_fp = 0;
  audit_fp_cmd = 0;
#endif // AUDIT_FILE_OUTPUT
#if defined(AUDIT_SO_OUTPUT)
  if (audit_so_path == 0) {
    audit_so_path = AUDIT_SO_PATH;
  }
  audit_h = 0;
  audit_so_h = 0;
  audit_open_fn = 0;
  audit_output_fn = 0;
  audit_close_fn = 0;
#endif // AUDIT_SO_OUTPUT
  last_output = 0;
  last_endio = 0;
}

void audit_reset()
{
#if defined(AUDIT_FILE_OUTPUT)
  fsync(audit_fp);
  close(audit_fp);
  fsync(audit_fp_cmd);
  close(audit_fp_cmd);
#endif // AUDIT_FILE_OUTPUT
#if defined(AUDIT_SO_OUTPUT)
  if (audit_h != 0 && audit_so_h != 0 && audit_close_fn != 0) {
    audit_close_fn(audit_h, last_command_exit_value);
    audit_h = 0;
  }
  if (audit_so_h != 0) {
    dlclose(audit_so_h);
  }
#endif // AUDIT_SO_OUTPUT
  audit_init();
}

void* audit_stdout(void* tid)
{
  int bytes_read = 0;
  int ret = 0;
  char buffer[AUDIT_BUFFER_LEN];
  struct aiocb cb;
  struct timespec t_req, t_rem;
  memset(&cb, 0, sizeof(cb));
  memset(&t_req, 0, sizeof(t_req));
  memset(&t_rem, 0, sizeof(t_rem));
  cb.aio_buf = buffer;
  cb.aio_fildes = FDM;
  cb.aio_nbytes = AUDIT_BUFFER_LEN;
  cb.aio_offset = 0;
  AUDIT_LOG(LOG_DEBUG, "audit_stdout called.");
  while (FDM > 0) {
    ret = aio_read(&cb);
    if (ret < 0) {
      AUDIT_LOG(LOG_DEBUG, "failed aio_read.");
      break;
    }
    while ((ret = aio_error(&cb)) == EINPROGRESS && FDM > 0) {
      t_req.tv_nsec = 10000;
      nanosleep(&t_req, &t_rem);
    }
    if (FDM > 0 && (ret = aio_return(&cb)) > 0) {
      buffer[ret] = 0;
      audit_output(buffer);
    }
  }
  AUDIT_LOG(LOG_DEBUG, "audit_stdout ended.");
  pthread_exit(0);
}

void audit_resize_win()
{
  struct winsize size;
  char rows[10];
  char cols[10];
  memset(rows, 0, 10);
  memset(cols, 0, 10);
  AUDIT_LOG(LOG_DEBUG, "audit_resize_win called.");
  if (FDS != -1) {
    if (ioctl(old_stdin, TIOCGWINSZ, &size) == 0) {
      sprintf(rows, "%d", size.ws_row);
      sprintf(cols, "%d", size.ws_col);
      AUDIT_LOG(LOG_DEBUG, "setting LINES=%s, COLUMNS=%s", rows, cols);
      setenv("LINES", rows, 1);
      setenv("COLUMNS", cols, 1);
      ioctl(FDS, TIOCSWINSZ, &size);
      ioctl(FDM, TIOCSWINSZ, &size);
    }
  }
}

int audit_openptty()
{
  int result = -1;
  int savedErrno = 0;
  char* p = 0;
  struct winsize size;
  audit_ptty[0] = audit_ptty[1] = audit_ptty[2] = -1;
  AUDIT_LOG(LOG_DEBUG, "audit_openptty called");
  AUDIT_LOG(LOG_DEBUG, "calling posix_openpt(O_RDWR)");
  FDM = posix_openpt(O_RDWR);
  if (FDM >= 0) {
    AUDIT_LOG(LOG_DEBUG, "calling grantpt(FDM)");
    RC = grantpt(FDM);
    if (RC == 0) {
      AUDIT_LOG(LOG_DEBUG, "calling unlockpt(FDM)");
      RC = unlockpt(FDM);
      if (RC == 0) {
        AUDIT_LOG(LOG_DEBUG, "acquiring ptsname(FDM).");
        p = ptsname(FDM);
        if (p != 0) {
          AUDIT_LOG(LOG_DEBUG, "opening %s: O_RDWR", p);
          FDS = open(p, O_RDWR);
          AUDIT_LOG(LOG_DEBUG, "tcgetattr(FDS, TSOURCE)");
          RC = tcgetattr(FDS, &audit_ts[TSOURCE]);
          if (RC == 0) {
            audit_ts[TDEST] = audit_ts[TSOURCE];
            // audit_orig_shell_tty = shell_tty;
            AUDIT_LOG(LOG_DEBUG, "tcsetattr(FDS, TCSANOW, TDEST)");
            tcsetattr(FDS, TCSANOW, &audit_ts[TDEST]);
            old_stdin = fileno(stdin);
            // shell_tty = fileno(stderr);
            AUDIT_LOG(LOG_DEBUG, "calling audit_resize_win()");
            audit_resize_win();
          }
        } else {
          savedErrno = errno;
          AUDIT_LOG(LOG_WARNING, "Failed psname: %d", savedErrno);
          close(FDM);
          errno = savedErrno;
        }
      } else {
        savedErrno = errno;
        AUDIT_LOG(LOG_WARNING, "Failed unlockpt: %d", savedErrno);
        close(FDM);
        errno = savedErrno;
      }
    } else {
      savedErrno = errno;
      AUDIT_LOG(LOG_WARNING, "Failed grantpt: %d", savedErrno);
      close(FDM);
      errno = savedErrno;
    }
  } else {
    AUDIT_LOG(LOG_WARNING, "Failed posix_openpt: %d", errno);
  }
  return result;
}

void audit_tee()
{
  int ret;
  audit_thread = 0;
  audit_tty = 0;
  AUDIT_LOG(LOG_DEBUG, "audit_tee called.");
  audit_tty = open("/dev/tty", O_APPEND | O_WRONLY | O_NDELAY);
  if (audit_tty == -1) {
    AUDIT_LOG(LOG_WARNING, "Unable to open /dev/tty");
    audit_tty = 0;
  }
  audit_openptty();
  if (FDS != -1 && FDM != -1) {
    dup2(FDS, STDOUT_FILENO);
    dup2(FDS, STDERR_FILENO);
    AUDIT_LOG(LOG_DEBUG, "calling pthread_create.");
    ret = pthread_create(&audit_thread, 0, audit_stdout, 0);
    if (ret) {
      AUDIT_LOG(LOG_WARNING, "Unable to create thread to audit output.");
    }
  }
}

void audit_start()
{
  audit_init();
#if defined(AUDIT_SO_OUTPUT)
  dlerror();
  audit_so_h = dlopen(audit_so_path, RTLD_LAZY | RTLD_LOCAL);
  if (audit_so_h != 0) {
    AUDIT_LOG(LOG_DEBUG, "audit_so_h created from: %s.", audit_so_path);
    dlerror();
    audit_open_fn = (audit_open_fn_t)dlsym(audit_so_h, "bash_audit_open");
    if (audit_open_fn == 0) {
      AUDIT_LOG(LOG_DEBUG, "failed to acquire audit_open_fn: %s.", dlerror());
    }
    dlerror();
    audit_output_fn = (audit_output_fn_t)dlsym(audit_so_h, "bash_audit_output");
    if (audit_output_fn == 0) {
      AUDIT_LOG(LOG_DEBUG, "failed to acquire audit_output_fn: %s.", dlerror());
    }
    dlerror();
    audit_close_fn = (audit_close_fn_t)dlsym(audit_so_h, "bash_audit_close");
    if (audit_close_fn == 0) {
      AUDIT_LOG(LOG_DEBUG, "failed to acquire audit_close_fn: %s.", dlerror());
    }
  } else {
    AUDIT_LOG(LOG_DEBUG, "audit_so_h was not loaded from %s: %s.", audit_so_path, dlerror());
  }
#endif // AUDIT_SO_OUTPUT
#if defined(AUDIT_FILE_OUTPUT)
  char* filepath;
  unsigned int p_size;
  unsigned int i;
  audit_fp = 0;
  audit_stop_io = 1;
  p_size = strlen(AUDIT_FILE_PATH) + 4;
  filepath = calloc(p_size, 1);
  if (filepath) {
    for (i = 0; i < p_size; ++i) {
      filepath[i] = 0;
    }
    sprintf(filepath, AUDIT_FILE_PATH, "out");
    audit_fp = mkstemps(filepath, 4);

    free(filepath);
  }
  filepath = calloc(p_size, 1);
  if (filepath) {
    for (i = 0; i < p_size; ++i) {
      filepath[i] = 0;
    }
    sprintf(filepath, AUDIT_FILE_PATH, "cmd");
    audit_fp_cmd = mkstemps(filepath, 4);

    free(filepath);
  }
#endif //AUDIT_FILE_OUTPUT
  audit_tee();
}

void audit_stop()
{
  AUDIT_LOG(LOG_DEBUG, "audit_stop called.");
  audit_reset();
  fsync(FDM);
  close(FDM);
  fsync(FDS);
  close(FDS);
  FDM = -1;
  FDS = -1;
}

void audit_cmd(const char* cmd)
{
  AUDIT_LOG(LOG_DEBUG, "audit_cmd called.");
  last_endio = last_output;
  if (cmd != 0) {
    AUDIT_LOG(LOG_DEBUG, "audit_cmd called with: %s", cmd);
    unsigned int len = strlen(cmd);
#if defined(AUDIT_SO_OUTPUT)
    if (audit_so_h != 0 && audit_open_fn != 0) {
      if (audit_h != 0 && audit_close_fn != 0) {
        AUDIT_LOG(LOG_DEBUG, "calling audit_close_fn.");
        audit_close_fn(audit_h, last_command_exit_value);
        audit_h = 0;
      }
      AUDIT_LOG(LOG_DEBUG, "calling audit_open_fn.");
      audit_h = audit_open_fn(cmd, len);
    } else {
      if (audit_so_h == 0) {
        AUDIT_LOG(LOG_DEBUG, "audit_so_h is NULL.");
      }
      if (audit_open_fn == 0) {
        AUDIT_LOG(LOG_DEBUG, "audit_open_fn is NULL.");
      }
    }
#endif // AUDIT_SO_OUTPUT
#if defined(AUDIT_FILE_OUTPUT)
    if (audit_fp_cmd) {
      audit_stop_io = 0;
      if (write(audit_fp_cmd, cmd, len) == -1) {
        AUDIT_LOG(LOG_WARNING, "Unable to write to audit log for cmd %s, len %d.\n", cmd, len);
      } else {
        write(audit_fp_cmd, "\n", 1);
      }
    } else {
      AUDIT_LOG(LOG_WARNING, "Unable to write to audit log: audit_fp == %d, cmd == %s.\n", audit_fp, cmd);
    }
#endif // AUDIT_FILE_OUTPUT
  }
}

void audit_endio()
{
  AUDIT_LOG(LOG_DEBUG, "audit_endio called.");
  struct timespec t;
  t.tv_sec = 0;
  t.tv_nsec = 100000; // 1/100th of a second.
  int count = 0;
  if (last_output == last_endio) {
    AUDIT_LOG(LOG_DEBUG, "will sleep a bit.");
  }
  while (last_output == last_endio && count < 100) {
    // sleep a bit.
    nanosleep(&t, 0);
    ++count;
  }
#if defined(AUDIT_SO_OUTPUT)
  if (audit_so_h != 0 && audit_close_fn != 0) {
    AUDIT_LOG(LOG_DEBUG, "calling audit_close_fn.");
    audit_close_fn(audit_h, last_command_exit_value);
    audit_h = 0;
  }
#endif // AUDIT_SO_OUTPUT
#if defined(AUDIT_FILE_OUTPUT)
  audit_stop_io = 1;
#endif // AUDIT_FILE_OUTPUT
  last_endio = last_output;
}

void audit_output(const char* output)
{
  AUDIT_LOG(LOG_DEBUG, "audit_output(%s) called.", output);
  unsigned int len = 0;
  if (output != 0) {
    len = strlen(output);
#if defined(AUDIT_SO_OUTPUT)
    if (audit_so_h != 0 && audit_output_fn != 0 && audit_h != 0) {
      AUDIT_LOG(LOG_DEBUG, "Sending output to so.");
      audit_output_fn(audit_h, output, len);
    }
#endif // AUDIT_SO_OUTPUT
#if defined(AUDIT_FILE_OUTPUT)
    if (audit_fp && audit_stop_io == 0) {
      if (write(audit_fp, output, len) == -1) {
        AUDIT_LOG(LOG_WARNING, "Unable to write to audit log for output len %d.\n", len);
      }
    }
#endif // AUDIT_FILE_OUTPUT
    if (audit_tty != 0) {
      write(audit_tty, output, len);
    }
  }
  ++last_output;
}
#endif // AUDIT_BASH
