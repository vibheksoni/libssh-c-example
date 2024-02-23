#include "headers/user.h"

struct User *UserCreate(ssh_session session) {
    struct User *user = malloc(sizeof(struct User));
    user->session     = session;
    return user;
}

bool_t UserAuth(struct User *user) {
    if (strcmp(user->username, "admin") == 0 && strcmp(user->password, "admin") == 0) {
        printf("[SSH] [AUTH] [SUCCESS]: %s\n", user->username);
        user->authenticated = true;
        return true;
    }
    return false;
}

bool_t UserSessionInit(struct User *user) {
    ssh_message message;

    do {
        message = ssh_message_get(user->session);
        if (message == NULL) break;

        switch (ssh_message_type(message)) {
            case SSH_REQUEST_AUTH:
                switch (ssh_message_subtype(message)) {
                    case SSH_AUTH_METHOD_PASSWORD:
                        if (ssh_message_auth_user(message) != NULL) {
                            user->username = strdup(ssh_message_auth_user(message));
                            user->password = strdup(ssh_message_auth_password(message));
                            if (UserAuth(user)) {
                                ssh_message_auth_reply_success(message, 0);
                            }
                            else {
                                ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
                                ssh_message_reply_default(message);
                            }   
                        }
                        break;
                    default:
                        ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
                        ssh_message_reply_default(message);
                        break;
                }
                break;
            default:
                ssh_message_reply_default(message);
                break;
        }
        ssh_message_free(message);
    } while (!user->authenticated);
    do {
        message = ssh_message_get(user->session);
        if (message == NULL) break;

        switch (ssh_message_type(message)) {
            case SSH_REQUEST_CHANNEL_OPEN:
                if (ssh_message_subtype(message) == SSH_CHANNEL_SESSION)
                    user->channel = ssh_message_channel_request_open_reply_accept(message);
                
                break;
            default:
                ssh_message_reply_default(message);
                break;
        }

        ssh_message_free(message);
    } while (message && !user->channel);

    ssh_channel_set_blocking(user->channel, 0);

    user->sock_len  = sizeof(user->sockaddr);
    user->sock      = ssh_get_fd(user->session);
    getpeername(user->sock, (struct sockaddr *)&user->sockaddr, &user->sock_len);
    user->ipaddr    = inet_ntoa(user->sockaddr.sin_addr);
    user->port      = ntohs(user->sockaddr.sin_port);
    user->buffer    = malloc(MAXBUFFER * sizeof(char));
    memset(user->buffer, 0, MAXBUFFER);
    user->buffer_length = 0;
    
    return user->authenticated;
}

void SshPrintf(struct User *user, char *format, ...){ 
    va_list list;
    char *buffer = NULL;

    va_start(list, format);
    int len = vasprintf(&buffer, format, list);
    va_end(list);

    ssh_channel_write(user->channel, buffer, len);
    free(buffer);
}

int SshRead(struct User *user, int size, bool_t hide){ 
    char character;

    for (int i = 0; i < size; i++) {
        user->ret = ssh_channel_read(user->channel, &character, 1, 0);
        
        if (user->ret == SSH_ERROR) return -1;
        else if (user->ret == 0) {
            usleep(100000);
            continue;
        }
        
        if ((user->ret = SshDecideKey(user, character, hide)))  {
            return (user->ret != 2);
        }
    }

    return 0;
}

int SshDecideKey(struct User *user, char buf, bool_t hide){ 
    switch (buf) {
    case SSH_KEY_BACKSPACE:
        if (user->buffer_length > 0) {
            SshPrintf(user, "\x08 \x08");
            user->buffer[--user->buffer_length] = 0;
        }
        break;

    case SSH_KEY_RESETLINE:
        SshPrintf(user, "\r\n");
        return 1;

    case SSH_KEY_NEWLINE:
        SshPrintf(user, "\r\n");
        return 1;

    case 0x03:
        user->buffer_length = 0;
        memset(user->buffer, 0, MAXBUFFER);

        SshPrintf(user, "^C\r\n");
        return 2;

    default:
        if (!hide)
            ssh_channel_write(user->channel, &buf, 1);
        else
            ssh_channel_write(user->channel, "*", 1);
        
        user->buffer[user->buffer_length++] = buf;
    }

    return 0;
}

void ClientHandler(struct User *user) {
    if (UserSessionInit(user)) {
        // User is authenticated
        SshPrintf(user, CLEAR_SCREEN);
        while (1) {
            // Reset Buffer and Length
            memset(user->buffer, 0, MAXBUFFER);
            user->buffer_length = 0;

            // Ssh Prompt
            SshPrintf(user, "%s@%s:~$ ", user->username, user->ipaddr);
            printf("Waiting for command...\n");
            if ((SshRead(user, 256, false)) != -1)
            {
                if (strlen(user->buffer) > 0) {
                    printf("[USERNAME: %s] [SSH] [COMMAND]: %s\n", user->username, user->buffer);
                    if (strcmp(user->buffer, "exit") == 0) break;
                    else if (strcmp(user->buffer, "clear") == 0) SshPrintf(user, CLEAR_SCREEN);
                }
            }
            else {
                printf("[USERNAME: %s] [SSH] [ERROR]: %s\n", user->username, ssh_get_error(user->session));
                break;
            }
        } 
    }
    ClientCleanup(user);
}

void ClientCleanup(struct User *user) {
    ssh_channel_send_eof(user->channel);
    ssh_channel_close(user->channel);
    ssh_disconnect(user->session);
    free(user->buffer);
    free(user);
}