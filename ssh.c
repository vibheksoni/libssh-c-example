#include "headers/ssh.h"
#include "headers/user.h"

struct server_t *SshConfig(char *host, char *hostkey, int port) {
    struct server_t *server\
                     = malloc(sizeof(struct server_t));
    server->host     = host;
    server->port     = port;
    server->hostkey  = hostkey;
    server->ssh_bind = NULL;

    return server;
}

void SshInit(struct server_t *server) {
    server->ssh_bind = ssh_bind_new();

    // Set the SSH server options
    ssh_bind_options_set(server->ssh_bind, SSH_BIND_OPTIONS_BINDADDR, server->host);
    ssh_bind_options_set(server->ssh_bind, SSH_BIND_OPTIONS_BINDPORT,&server->port);
    ssh_bind_options_set(server->ssh_bind, SSH_BIND_OPTIONS_HOSTKEY,  server->hostkey);
}

void SshStart(struct server_t *server) {
    if (ssh_bind_listen(server->ssh_bind) < 0) {
        fprintf(stderr, "Error listening to socket: %s\n", ssh_get_error(server->ssh_bind));
        exit(1);
    }

    // Thread SSH Handler to handle incoming connections
    pthread_t  ssh_thread;
    pthread_create(&ssh_thread, NULL, (void *)SshConnectionHandler, (void *)server);
}

void SshConnectionHandler(struct server_t *server) {
    while (1) {
        ssh_session session = ssh_new();
        if (ssh_bind_accept(server->ssh_bind, session) == SSH_ERROR) {
            fprintf(stderr, "Error accepting incoming connection: %s\n", ssh_get_error(server->ssh_bind));
            exit(1);
        }

        if (ssh_handle_key_exchange(session) != SSH_OK)
            ssh_disconnect(session);
        else {
            pthread_t ssh_session_thread;
            struct User *user = UserCreate(session);
            pthread_create(&ssh_session_thread, NULL, (void *)ClientHandler, (void *)user);
        }
    }
}

void SshCleanup(struct server_t *server) {
    ssh_bind_free(server->ssh_bind);
}