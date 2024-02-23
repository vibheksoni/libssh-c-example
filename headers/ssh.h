#pragma once

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

struct server_t {
    ssh_bind    ssh_bind;
    ssh_session ssh_session;
    ssh_channel ssh_channel;

    // Server configuration
    char *host;
    char *hostkey;
    int   port;
};

struct server_t *SshConfig(char *host, char *hostkey, int port);
void SshConnectionHandler(struct server_t *server);
void SshCleanup(struct server_t *server);
void SshStart(struct server_t *server);
void SshInit(struct server_t *server);