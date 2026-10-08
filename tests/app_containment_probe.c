/* Static headless adversarial probe used only by the disposable Linux fixture. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) return __LINE__; } while (0)
static void *thread_probe(void *value) { return value; }
int main(int argc, char **argv) {
    CHECK(argc == 3);
    alarm(10);
    CHECK(getuid() == 1000 && getgid() == 1000);
    CHECK(getgroups(0, NULL) == 0);
    CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    CHECK(fcntl(200, F_GETFD) == -1 && errno == EBADF);
    CHECK(access(argv[1], F_OK) == -1 && errno == ENOENT);
    CHECK(socket(AF_UNIX, SOCK_STREAM, 0) == -1 && errno == EPERM);
    CHECK(socket(AF_PACKET, SOCK_RAW, 0) == -1 && errno == EPERM);
    CHECK(unshare(CLONE_NEWUSER) == -1 && errno == EPERM);
#ifdef SYS_io_uring_setup
    CHECK(syscall(SYS_io_uring_setup, 0, NULL) == -1 && errno == EPERM);
#endif
#ifdef SYS_pidfd_getfd
    CHECK(syscall(SYS_pidfd_getfd, -1, 0, 0) == -1 && errno == EPERM);
#endif
#ifdef SYS_clone3
    CHECK(syscall(SYS_clone3, NULL, 0) == -1 && errno == ENOSYS);
#endif
    pthread_t thread;
    void *thread_result = NULL;
    CHECK(pthread_create(&thread, NULL, thread_probe, &thread_result) == 0);
    CHECK(pthread_join(thread, &thread_result) == 0 && thread_result == &thread_result);
    FILE *status = fopen("/proc/self/status", "r");
    CHECK(status != NULL);
    char line[512];
    int effective = 0, permitted = 0, bounding = 0;
    while (fgets(line, sizeof line, status)) {
        if (!strncmp(line, "CapEff:", 7)) effective = strtoull(line + 7, NULL, 16) == 0;
        if (!strncmp(line, "CapPrm:", 7)) permitted = strtoull(line + 7, NULL, 16) == 0;
        if (!strncmp(line, "CapBnd:", 7)) bounding = strtoull(line + 7, NULL, 16) == 0;
    }
    fclose(status);
    CHECK(effective && permitted && bounding);
    CHECK(open("/root-write-test", O_WRONLY | O_CREAT, 0600) == -1);
    int scratch = open("/tmp/scratch", O_WRONLY | O_CREAT, 0600);
    CHECK(scratch >= 0);
    close(scratch);
    int stream = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(stream >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(9050)};
    CHECK(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    int connected = connect(stream, (struct sockaddr *)&addr, sizeof addr);
    if (!strcmp(argv[2], "closed")) {
        CHECK(connected == -1);
        close(stream);
        return 0;
    }
    CHECK(connected == 0);
    CHECK(write(stream, "ping", 4) == 4);
    char response[4];
    CHECK(read(stream, response, 4) == 4 && !memcmp(response, "ping", 4));
    close(stream);
    return 0;
}
