#include "vvsl_ssh.h"

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>

typedef struct my_str_s{
    char *data;
    size_t size;
    size_t capacity;
    size_t head;
    size_t tail;
} my_str_t;

void my_str_init(my_str_t *str, size_t capacity) {
    str->data = malloc(capacity);
    str->size = 0;
    str->capacity = capacity;
    str->head = 0;
    str->tail = 0;
}

void my_str_append(my_str_t *str, const char *data, size_t size) {
    if (str->tail + size > str->capacity) {
        size_t first_chunk = str->capacity - str->tail;
        size_t second_chunk = size - first_chunk;
        memcpy(str->data + str->tail, data, first_chunk);
        memcpy(str->data, data + first_chunk, second_chunk);
        str->tail = second_chunk;
    } else {
        memcpy(str->data + str->tail, data, size);
        str->tail += size;
    }
    str->size += size;
}

void my_str_free(my_str_t *str) {
    free(str->data);
    str->data = NULL;
    str->size = 0;
    str->capacity = 0;
    str->head = 0;
    str->tail = 0;
}

char* get_real_str(my_str_t *str) {
    char* real_str = malloc(str->size + 1);
    if (real_str == NULL) {
        return NULL;
    }
    if (str->tail > str->head) {
        memcpy(real_str, str->data + str->head, str->tail - str->head);
    } else {
        size_t first_chunk = str->capacity - str->head;
        size_t second_chunk = str->tail;
        memcpy(real_str, str->data + str->head, first_chunk);
        memcpy(real_str + first_chunk, str->data, second_chunk);
    }
    real_str[str->size] = '\0';
    return real_str;
}

/**
 * @brief connect sshserver use given host:port
 * @naslparm
 * - @host: target ip
 * - @port: target port
 * - @timeout: seconds
 * - @loglevel: 0-4
 *
 * @return 0 or pointer
 */

static void *__ssh_connect(char *server_ip, int port, int loglevel, long timeout) {  // lex_ctxt *lexic
    ssh_session session;
    int port_tmp = port;
    long timeout_tmp = timeout;  // in seconds
    int loglevel_tmp = loglevel;

    session = ssh_new();
    if (!session) {
        log_error("ssh_new failed!!!\n");
        goto ret_null;
    }

    if (loglevel > SSH_LOG_NOLOG) {
        ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &loglevel);
    }

    if (*server_ip != 0) {
        if (ssh_options_set(session, SSH_OPTIONS_HOST, server_ip)) {
            log_error("failed to set ssh hostname '%s':'%s'", server_ip, ssh_get_error(session));
            goto ret_free;
        }
    } else {
        goto ret_free;
    }

    if (port) {
        unsigned int my_port = port;
        if (ssh_options_set(session, SSH_OPTIONS_PORT, &my_port)) {
            log_error("Failed to set SSH port for '%s' to %d: %s", server_ip, port, ssh_get_error(session));
            goto ret_free;
        }
    } else {
        goto ret_free;
    }

    if (timeout > 0) {
        if (ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout)) {
            log_error("ssh_options_set timeout failed:%s\n", ssh_get_error(session));
            goto ret_free;
        }
    }

    if (ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, "/dev/null")) {
        log_error("Failed to disable SSH known_hosts: %s", ssh_get_error(session));
        goto ret_free;
    }

    // if (key_type && ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, key_type)) {
    //     log_error("Failed to set SSH key type '%s': %s", key_type, ssh_get_error(session));
    //     goto ret_free;
    // }

    // if (csciphers && ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, csciphers)) {
    //     log_error("Failed to set SSH client to server ciphers '%s': %s", csciphers, ssh_get_error(session));
    //     goto ret_free;
    // }
    // if (scciphers && ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, scciphers)) {
    //     log_error("Failed to set SSH server to client ciphers '%s': %s", scciphers, ssh_get_error(session));
    //     goto ret_free;
    // }

    if (ssh_connect(session) == SSH_OK) {
        log_info("connected to SSH server '%s':%d", server_ip, port);
    } else {
        goto ret_free;
    }

    return session;
ret_free:
    ssh_free(session);
ret_null:
    return NULL;
}

static void __ssh_disconnect(void *session) {
    ssh_disconnect((ssh_session)session);
    ssh_free((ssh_session)session);
}

/**
 * @brief // This function generates a brief for the __ssh_exec_cmd function
// It takes in a ssh_session, a command to execute, a compatibility mode, and flags for stdout and stderr
// It returns an integer indicating success or failure of the execution of the command.
 *
 */
static int __ssh_userauth(void *s, char *username, char *password, char *privatekey, char *passphrase) {
    int rc;
    ssh_session session = s;
    char *privkeystr = privatekey;
    char *privkeypass = passphrase;

    if (username && *username && ssh_options_set(session, SSH_OPTIONS_USER, username)) {
        log_error("Function %s Failed to set SSH username '%p':%s %s", __func__, username, *username ? username : "NULL", ssh_get_error(session));
        return SSH_ERROR;
    }

    if (password) {
        rc = ssh_userauth_password(session, NULL, password);
        if (rc == SSH_AUTH_SUCCESS) {
            return SSH_OK;
        }
        log_error("SSH password authentication failed %s", ssh_get_error(session));
    }

    /* If we have a private key, try public key authentication.  */
    if (privkeystr && *privkeystr) {
        ssh_key key = NULL;

        if (ssh_pki_import_privkey_base64(privkeystr, privkeypass, NULL, NULL, &key)) {
            log_error("SSH public key authentication failed: %s", "Error converting provided key");

        } else if (ssh_userauth_try_publickey(session, NULL, key) != SSH_AUTH_SUCCESS) {
            log_error("SSH public key authentication failed: %s", "Server does not want our key");
        } else if (ssh_userauth_publickey(session, NULL, key) == SSH_AUTH_SUCCESS) {
            ssh_key_free(key);
            return SSH_OK;
        }
        ssh_key_free(key);
    }

    log_error("SSH authentication failed  %s", "No more authentication methods to try");

    return SSH_ERROR;
}

char *read_file(char *filename) {
    char *buffer = 0;
    long length;
    FILE *f = fopen(filename, "r");

    if (f) {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        printf("%ld\n", length);
        fseek(f, 0, SEEK_SET);
        buffer = malloc(length + 10);
        if (buffer) {
            fread(buffer, 1, length, f);
        }
        fclose(f);
    }
    buffer[length + 1] = 0;
    printf("[%ld]:%s\n", strlen(buffer), buffer);
    return buffer;
}
static int __ssh_exec_cmd(ssh_session session, char *cmd, int compat_mode, int to_stdout, int to_stderr) {
    int rc = 1;
    ssh_channel channel;
    char buffer[4096];
    char *response="";
    my_str_t res;
    my_str_init(&res,4096);

    /* Work-around for LibSSH calling poll() with an infinite timeout. */
    // signal(SIGALRM, exec_ssh_cmd_alarm);
    // alarm(30);
    if ((channel = ssh_channel_new(session)) == NULL) {
        log_error("ssh_channel_new failed: %s", ssh_get_error(session));
        return SSH_ERROR;
    }

    if (ssh_channel_open_session(channel)) {
        log_error("ssh_channel_open_session failed: %s", ssh_get_error(session));
        ssh_channel_free(channel);
        return SSH_ERROR;
    }

    if (ssh_channel_request_pty(channel)) log_error("ssh_channel_request_pty failed: %s", ssh_get_error(session));

    if (ssh_channel_request_exec(channel, cmd)) {
        log_error("ssh_channel_request_exec failed for '%s': %s", cmd, ssh_get_error(session));
        ssh_channel_free(channel);
        return SSH_ERROR;
    }
    // alarm(0);
    // signal(SIGALRM, _exit);
    while (rc > 0) {
        if ((rc = ssh_channel_read_timeout(channel, buffer, sizeof(buffer), 1, 15000)) > 0) {
            my_str_append(&res,buffer,rc);
        }
        if (rc == SSH_ERROR) goto exec_err;
    }
    rc = 1;
    while (rc > 0) {
        if ((rc = ssh_channel_read_timeout(channel, buffer, sizeof(buffer), 0, 15000)) > 0) {
            my_str_append(&res,buffer,rc);
        }
        if (rc == SSH_ERROR) goto exec_err;
    }
    get_real_str(&res);
    printf("%s\n",get_real_str(&res));
    my_str_free(&res);
    rc = SSH_OK;
    printf("result: \n%s\n",response);
exec_err:
    ssh_channel_free(channel);
    return rc;
}


int main(int argc, char *argv[]) {
    int ret;

    char *ip = "192.168.133.146";
    int port = 22;
    long timeout = 10;
    long loglevel = 1;
    void *session = __ssh_connect(ip, port, loglevel, timeout);
    log_info("vvsl_ssh_connect ret=%p", session);
    if (!session) {
        return 0;
    }

    char *username = "xiang";
    char *password = "a";
    char *privatekey = NULL;  // read_file("/home/xiang/.ssh/id_rsa");
    char *passphrase = NULL;
    if (__ssh_userauth(session, username, password, privatekey, passphrase) != SSH_OK) {
        log_info("ssh login failed");
        goto error;
    }
    log_info("ssh login success");

    __ssh_exec_cmd(session,"ps aux",1,1,1);

error:
    __ssh_disconnect(session);
    return 0;
}
