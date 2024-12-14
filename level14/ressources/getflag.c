#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>

char *ft_des(char *param_1) {
    char *pcVar2 = strdup(param_1);
    int local_1c = 0;
    size_t local_20 = 0;

    while (local_20 < strlen(pcVar2)) {
        if (local_1c == 6) {
            local_1c = 0;
        }

        if (local_20 % 2 == 0) {
            for (int i = 0; i < "0123456"[local_1c] - '0'; i++) {
                pcVar2[local_20]--;
                if (pcVar2[local_20] < 0x20) {
                    pcVar2[local_20] = 0x7E;
                }
            }
        } else {
            for (int i = 0; i < "0123456"[local_1c] - '0'; i++) {
                pcVar2[local_20]++;
                if (pcVar2[local_20] > 0x7E) {
                    pcVar2[local_20] = 0x20;
                }
            }
        }

        local_20++;
        local_1c++;
    }

    return pcVar2;
}

int isLib(char *line, const char *pattern) {
    char *pos = strstr(line, pattern);
    if (!pos || *(pos + strlen(pattern)) != '-') {
        return 0;
    }

    char *ptr = pos + strlen(pattern) + 1;
    while (*ptr >= '0' && *ptr <= '9') {
        ptr++;
    }

    if (*ptr != '.') {
        return 0;
    }

    ptr++;
    while (*ptr >= '0' && *ptr <= '9') {
        ptr++;
    }

    return strcmp(ptr, "so") == 0;
}

int main(void) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        puts("You should not reverse this");
        return 1;
    }

    char *ld_preload = getenv("LD_PRELOAD");
    if (ld_preload) {
        fprintf(stderr, "Injection Linked lib detected exit..\n");
        return 1;
    }

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "/proc/self/maps is inaccessible, probably a LD_PRELOAD attempt exit..\n");
        return 1;
    }

    char buffer[256];
    int found = 0;
    while (read(fd, buffer, sizeof(buffer)) > 0) {
        if (isLib(buffer, "libc")) {
            found = 1;
            break;
        }
    }

    close(fd);

    if (found) {
        puts("Check flag. Here is your token:");
        uid_t uid = getuid();
        if (uid == 3000) {
            printf("%s\n", ft_des("H8B8h_20B4J43><8>\\ED<;j@3"));
        } else {
            puts("No token for your user ID.");
        }
    } else {
        fprintf(stderr, "LD_PRELOAD detected through memory maps exit..\n");
    }

    return 0;
}