#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>

int main() {
    int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (fd < 0) 
    {
        return 1;
    }
    const char *msg = "<6>[poc] initramfs ping\n"; // <6> = INFO
    ssize_t n = write(fd, msg, strlen(msg));
    close(fd);
    if (n < 0) 
    {
        return 1;
    }
    return 0;
}
