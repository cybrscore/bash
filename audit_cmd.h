#if defined AUDIT_BASH
#if !defined AUDIT_CMD_H_AA0982F76FC7481CAFDC6DB3DD07F81B
#define AUDIT_CMD_H_AA0982F76FC7481CAFDC6DB3DD07F81B

void audit_start();
void audit_stop();
void audit_cmd(const char* cmd);
void audit_endio();
void audit_resize_win();

#endif // AUDIT_CMD_H_AA0982F76FC7481CAFDC6DB3DD07F81B
#endif // AUDIT_BASH
