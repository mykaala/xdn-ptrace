#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    printf("*****HELLO FROM THE TARGET PROGRAM!*****\n");

    int fd = open("data.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    const char *message = "Hello world!\n";
    ssize_t bytes_written = write(fd, message, 12);
    if (bytes_written < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    // Close the file
    if (close(fd) < 0) {
        perror("close");
        return 1;
    }

    return 0;
}
