#pragma once
#define _GNU_SOURCE
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
typedef int bool_t;
#define true 1
#define false 0

#define MAXBUFFER         300
#define SSH_KEY_RESETLINE 0xd
#define SSH_KEY_NEWLINE   0xa
#define SSH_KEY_TAB       0x9
#define SSH_KEY_BACKSPACE 0x7f
#define SSH_KEY_SPACE     0x20
#define CLEAR_SCREEN      "\e\143"

struct User {
    char *username;
    char *password;
    char *ipaddr;
    char *buffer;
    int   buffer_length;
    int   port;
    int   ret;
    bool_t authenticated;

    struct sockaddr_in sockaddr;
    ssh_session session;
    ssh_channel channel;
    socket_t    sock;
    socklen_t   sock_len;
};

struct User *UserCreate();
bool_t UserAuth(struct User *user);
bool_t UserSessionInit(struct User *user);
int  SshRead(struct User *user, int size, bool_t hide);
int  SshDecideKey(struct User *user, char buf, bool_t hide);
void SshPrintf(struct User *user, char *format, ...);
void ClientHandler(struct User *user);
void ClientCleanup(struct User *user);