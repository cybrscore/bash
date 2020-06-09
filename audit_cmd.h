#include "config.h"

#if defined AUDIT_BASH
#if !defined AUDIT_CMD_H_AA0982F76FC7481CAFDC6DB3DD07F81B
#define AUDIT_CMD_H_AA0982F76FC7481CAFDC6DB3DD07F81B

#if !defined(AUDIT_FILE_PATH)
#define AUDIT_FILE_PATH "/tmp/bash_audit_XXXXXX.%s"
#endif

#if !defined(AUDIT_SO_PATH)
#define AUDIT_SO_PATH "/lib/libbash_audit.so"
#endif

#if !defined(AUDIT_BUFFER_LEN)
#define AUDIT_BUFFER_LEN 4096
#endif


extern void audit_start();
extern void audit_stop();
extern void audit_cmd(const char* cmd);
extern void audit_endio();
extern void audit_resize_win();
extern const char* audit_info();

#endif // AUDIT_CMD_H_AA0982F76FC7481CAFDC6DB3DD07F81B
#endif // AUDIT_BASH
