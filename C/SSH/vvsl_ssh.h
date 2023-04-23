#ifndef _VVSL_SSH_H_
#define _VVSL_SSH_H_

#include <errno.h>
#include <libssh/libssh.h>
#include <stdio.h>
#include <string.h>
//#include <glib-2.0/glib.h>
//#include <glib-2.0/glib/gstdio.h>
#define clean_errno() (errno == 0 ? "None" : strerror(errno))
#define log_error(M, ...) fprintf(stderr, "ERR   " M " at %s (%s:%d) errno:%s\n", ##__VA_ARGS__, __func__, __FILE__, __LINE__, clean_errno())
#define log_warn(M, ...) fprintf(stderr, "WARN  " M " at %s (%s:%d) errno:%s\n", ##__VA_ARGS__, __func__, __FILE__, __LINE__, clean_errno())
#define log_info(M, ...) fprintf(stderr, "INFO  " M " at %s (%s:%d)\n", ##__VA_ARGS__, __func__, __FILE__, __LINE__)

#endif  //_VVSL_SSH_H_