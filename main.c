#include "headers/ssh.h"

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <host> <hostkey> <port>\n", argv[0]);
        exit(1);
    }

    char *host     = argv[1];
    char *hostkey  = argv[2];
    int port       = atoi(argv[3]);

    struct server_t *server = SshConfig(host, hostkey, port);

    SshInit(server);
    SshStart(server);

    while (1) {
        sleep(1);
    }

    SshCleanup(server);
    return 0;   
}