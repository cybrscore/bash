/* execute_cmd.h - functions from execute_cmd.c. */

/* Copyright (C) 1993-2017 Free Software Foundation, Inc.

   This file is part of GNU Bash, the Bourne Again SHell.

   Bash is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   Bash is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Bash.  If not, see <http://www.gnu.org/licenses/>.
*/

#if !defined(_EXECUTE_CMD_H_)
#define _EXECUTE_CMD_H_

#include "../variables.h"
#include "stdc.h"

#if defined(ARRAY_VARS)
struct func_array_state {
  ARRAY* funcname_a;
  SHELL_VAR* funcname_v;
  ARRAY* source_a;
  SHELL_VAR* source_v;
  ARRAY* lineno_a;
  SHELL_VAR* lineno_v;
};
#endif

/* Placeholder for later expansion to include more execution state */
/* XXX - watch out for pid_t */
struct execstate {
  pid_t pid;
  int subshell_env;
};

/* Variables delared in execute_cmd.c, used by many other files */
extern int return_catch_flag;
extern int return_catch_value;
extern volatile int last_command_exit_value;
extern int last_command_exit_signal;
extern int builtin_ignoring_errexit;
extern int executing_builtin;
extern int executing_list;
extern int comsub_ignore_return;
extern int subshell_level;
extern int match_ignore_case;
extern int executing_command_builtin;
extern int funcnest, funcnest_max;
extern int evalnest, evalnest_max;
extern int sourcenest, sourcenest_max;
extern int stdin_redir;
extern int line_number_for_err_trap;

extern char* the_printed_command_except_trap;

extern char* this_command_name;
extern SHELL_VAR* this_shell_function;

/* Functions delared in execute_cmd.c, used by many other files */

extern struct fd_bitmap* new_fd_bitmap __P((int));
extern void dispose_fd_bitmap __P((struct fd_bitmap*));
extern void close_fd_bitmap __P((struct fd_bitmap*));
extern int executing_line_number __P((void));
extern int execute_command __P((COMMAND*));
extern int execute_command_internal __P((COMMAND*, int, int, int, struct fd_bitmap*));
extern int shell_execve __P((char*, char**, char**));
extern void setup_async_signals __P((void));

extern void undo_partial_redirects __P((void));
extern void dispose_partial_redirects __P((void));
extern void dispose_exec_redirects __P((void));

extern int execute_shell_function __P((SHELL_VAR*, WORD_LIST*));

extern struct coproc* getcoprocbypid __P((pid_t));
extern struct coproc* getcoprocbyname __P((const char*));

extern void coproc_init __P((struct coproc*));
extern struct coproc* coproc_alloc __P((char*, pid_t));
extern void coproc_dispose __P((struct coproc*));
extern void coproc_flush __P((void));
extern void coproc_close __P((struct coproc*));
extern void coproc_closeall __P((void));
extern void coproc_reap __P((void));
extern pid_t coproc_active __P((void));

extern void coproc_rclose __P((struct coproc*, int));
extern void coproc_wclose __P((struct coproc*, int));
extern void coproc_fdclose __P((struct coproc*, int));

extern void coproc_checkfd __P((struct coproc*, int));
extern void coproc_fdchk __P((int));

extern void coproc_pidchk __P((pid_t, int));

extern void coproc_fdsave __P((struct coproc*));
extern void coproc_fdrestore __P((struct coproc*));

extern void coproc_setvars __P((struct coproc*));
extern void coproc_unsetvars __P((struct coproc*));

#if defined(PROCESS_SUBSTITUTION)
extern void close_all_files __P((void));
#endif

#if defined(ARRAY_VARS)
extern void restore_funcarray_state __P((struct func_array_state*));
#endif

#endif /* _EXECUTE_CMD_H_ */
