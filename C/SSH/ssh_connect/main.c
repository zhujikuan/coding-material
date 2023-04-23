#include "ssh_network.h"
#include <errno.h>
#define clean_errno() (errno == 0 ? "None" : strerror(errno))
  #define log_error(M, ...) fprintf(stderr,  "ERR   " M " at %s (%s:%d) errno:%s\n", ##__VA_ARGS__, __func__, __FILE__, __LINE__, clean_errno())
  #define log_warn(M, ...) fprintf(stderr, "WARN  " M " at %s (%s:%d) errno:%s\n", ##__VA_ARGS__, __func__, __FILE__, __LINE__, clean_errno())
  #define log_info(M, ...) fprintf(stderr, "INFO  " M " at %s (%s:%d)\n", ##__VA_ARGS__, __func__, __FILENAME__, __LINE__)

int main(int argc, char *argv[]) {
    const char *hostname = 0;
    int port = 22;
    if (argc < 2) {
        fprintf(stderr, "Usage: ssh_connect hostname port\n");
        return EXIT_FAILURE;
    }

    hostname = argv[1];
   log_error("hostname:%s,port:%d",hostname,port);
    if (argc > 2) {
        port = atol(argv[2]);
    }

    ssh_session ssh = ssh_new();
    if (ssh == NULL) {
        fprintf(stderr, "ssh_new() failed.\n");
        return EXIT_FAILURE;
    }

    ssh_options_set(ssh, SSH_OPTIONS_HOST, hostname);
    ssh_options_set(ssh, SSH_OPTIONS_PORT, &port);

    int verbosity = SSH_LOG_PROTOCOL;
    ssh_options_set(ssh, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    int ret = ssh_connect(ssh);
    if (ret != SSH_OK) {
        fprintf(stderr, "ssh_connect() failed.\n%s\n", ssh_get_error(ssh));
        return EXIT_FAILURE;
    }

    printf("Connected to '%s' on port '%d.'\n", hostname, port);
    printf("Banner:\n%s\n", ssh_get_serverbanner(ssh));

    ssh_disconnect(ssh);
    ssh_free(ssh);

    return EXIT_SUCCESS;
}
