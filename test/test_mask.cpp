#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    if (sigprocmask(SIG_BLOCK, &mask, NULL)) {
        perror("sigprocmask");
        return 1;
    }

    printf("sleep(30)\n");
    sleep(15);
    return 0;
}
