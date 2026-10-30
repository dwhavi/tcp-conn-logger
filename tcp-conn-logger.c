/*
 * tcp-conn-logger.c
 *
 * /proc/net/tcp 와 /proc/net/tcp6 를 주기적으로 폴링해서
 * 시스템 전체의 TCP 접속 중 원격 주소가 지정한 대상 IP 목록과
 * 일치하는 소켓을 감지하고, 로그 파일에 기록한다.
 * (-t 미지정 시 모든 TCP 접속을 로그한다)
 *
 * - root 권한 불필요 (다른 사용자의 프로세스 이름은 권한 때문에 못 볼 수 있음)
 * - 외부 라이브러리 없이 libc 만 사용 (C11)
 * - inode 기반 중복 제거로 같은 접속을 반복해서 로그하지 않음
 *
 * 빌드: gcc -std=c11 -O2 -Wall -Wextra -o tcp-conn-logger tcp-conn-logger.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define MAX_TARGETS      64
#define MAX_SEEN        65536      /* 동시에 추적 가능한 접속(inode) 수 */
#define SEEN_TTL_SEC    3600       /* 추적 항목 만료 시간 (1시간) */
#define PATH_LEN        512
#define LINE_LEN        1024

/* 감지한 접속 1건의 정보 */
typedef struct {
    uint64_t inode;
    char local[64];
    int  local_port;
    char remote[64];
    int  remote_port;
    unsigned int state;            /* TCP 상태 번호 (01=ESTABLISHED 등) */
} conn_t;

/* 이미 로그한 접속 추적 항목 (중복 방지 + TTL) */
typedef struct {
    uint64_t inode;
    time_t   first_seen;
    bool     used;
} seen_t;

static seen_t g_seen[MAX_SEEN];

/* 대상 IP 목록 (문자열 그대로 비교; IPv4/IPv6 모두 지원) */
static char g_targets[MAX_TARGETS][INET6_ADDRSTRLEN];
static int  g_target_count = 0;

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

/* 타임스탬프 문자열: "2026-10-29 09:12:34" */
static void timestamp_now(char *buf, size_t len) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tmv);
}

/* TCP 상태 번호 -> 사람이 읽기 쉬운 이름 */
static const char *state_name(unsigned int st) {
    switch (st) {
        case 0x01: return "ESTABLISHED";
        case 0x02: return "SYN_SENT";
        case 0x03: return "SYN_RECV";
        case 0x04: return "FIN_WAIT1";
        case 0x05: return "FIN_WAIT2";
        case 0x06: return "TIME_WAIT";
        case 0x07: return "CLOSE";
        case 0x08: return "CLOSE_WAIT";
        case 0x09: return "LAST_ACK";
        case 0x0A: return "LISTEN";
        case 0x0B: return "CLOSING";
        default:   return "UNKNOWN";
    }
}

/*
 * /proc/net/tcp 의 주소 필드 파싱.
 * IPv4: "0100007F:1F90" -> 8자리 16진수, 바이트가 리틀엔디안 순서.
 *        즉 "0100007F" 는 127.0.0.1 이다.
 * IPv6: /proc/net/tcp6 는 32자리 16진수(4워드, 각 워드 리틀엔디안) 이지만
 *        inet_pton 으로 정규화해서 문자열 비교하면 되므로,
 *        파싱 후 표준 형식 문자열로 만든다.
 */
static bool parse_ipv4_field(const char *hex, char *out, size_t outlen) {
    unsigned int a, b, c, d;
    if (sscanf(hex, "%2x%2x%2x%2x", &d, &c, &b, &a) != 4) return false;
    /* 리틀엔디안: 파일에 적힌 순서의 역순이 실제 IP */
    snprintf(out, outlen, "%u.%u.%u.%u", a, b, c, d);
    return true;
}

static bool parse_ipv6_field(const char *hex, char *out, size_t outlen) {
    struct in6_addr addr;
    /* 32자리 16진수를 4개의 8자리 워드로 쪼갠다. 각 워드는 리틀엔디안 바이트 순서 */
    for (int w = 0; w < 4; w++) {
        char word[9];
        memcpy(word, hex + w * 8, 8);
        word[8] = '\0';
        unsigned int v;
        if (sscanf(word, "%x", &v) != 1) return false;
        /* 호스트 바이트 순서를 고려해 그대로 4바이트 저장 */
        memcpy(&addr.s6_addr[w * 4], &v, 4);
    }
    if (inet_ntop(AF_INET6, &addr, out, outlen) == NULL) return false;
    return true;
}

/* inode 추적 테이블: 새 inode 면 등록하고 true 반환 */
static bool seen_is_new(uint64_t inode) {
    time_t now = time(NULL);
    int free_slot = -1;

    for (int i = 0; i < MAX_SEEN; i++) {
        if (!g_seen[i].used) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (g_seen[i].inode == inode) return false;  /* 이미 본 접속 */
        /* TTL 만료 정리 */
        if (now - g_seen[i].first_seen > SEEN_TTL_SEC) {
            g_seen[i].used = false;
            if (free_slot < 0) free_slot = i;
        }
    }
    if (free_slot < 0) return false;  /* 테이블이 가득 참: 새 항목으로 취급하지 않음 */
    g_seen[free_slot].inode = inode;
    g_seen[free_slot].first_seen = now;
    g_seen[free_slot].used = true;
    return true;
}

/*
 * 소켓 inode -> 소유 프로세스(PID, 프로세스 이름) 찾기.
 * /proc/<pid>/fd 아래의 심볼릭 링크 "socket:[inode]" 를 뒤진다.
 * 다른 사용자 프로세스는 권한 때문에 못 읽을 수 있다 (빈 문자열 반환).
 */
static void find_owner(uint64_t inode, int *pid_out, char *name_out, size_t name_len) {
    char needle[64];
    snprintf(needle, sizeof(needle), "socket:[%llu]", (unsigned long long)inode);

    *pid_out = -1;
    name_out[0] = '\0';

    DIR *proc = opendir("/proc");
    if (!proc) return;

    struct dirent *de;
    while ((de = readdir(proc)) != NULL) {
        /* 숫자 디렉토리(=PID)만 검사 */
        if (!isdigit((unsigned char)de->d_name[0])) continue;

        char fddir[PATH_LEN];
        snprintf(fddir, sizeof(fddir), "/proc/%s/fd", de->d_name);
        DIR *fd = opendir(fddir);
        if (!fd) continue;  /* 권한 부족 등으로 열 수 없으면 건너뜀 */

        struct dirent *fe;
        char linkbuf[PATH_LEN];
        bool found = false;
        while ((fe = readdir(fd)) != NULL) {
            char fpath[PATH_LEN];
            int w = snprintf(fpath, sizeof(fpath), "%s/%s", fddir, fe->d_name);
            if (w < 0 || (size_t)w >= sizeof(fpath)) continue;  /* 경로가 잘리면 건너뜀 */
            ssize_t n = readlink(fpath, linkbuf, sizeof(linkbuf) - 1);
            if (n <= 0) continue;
            linkbuf[n] = '\0';
            if (strcmp(linkbuf, needle) == 0) { found = true; break; }
        }
        closedir(fd);

        if (found) {
            *pid_out = atoi(de->d_name);
            /* /proc/<pid>/comm 에서 프로세스 이름 읽기 */
            char commpath[PATH_LEN];
            snprintf(commpath, sizeof(commpath), "/proc/%s/comm", de->d_name);
            FILE *cf = fopen(commpath, "r");
            if (cf) {
                if (fgets(name_out, (int)name_len, cf) != NULL) {
                    name_out[strcspn(name_out, "\n")] = '\0';
                }
                fclose(cf);
            }
            break;
        }
    }
    closedir(proc);
}

/* 대상 IP 목록과 일치하는지 검사. 목록이 비어 있으면(-t 미지정) 모든 접속이 대상 */
static bool is_target(const char *ip) {
    if (g_target_count == 0) return true;
    for (int i = 0; i < g_target_count; i++) {
        if (strcmp(g_targets[i], ip) == 0) return true;
    }
    return false;
}

/*
 * /proc/net/tcp(또는 tcp6) 한 파일을 읽어 콜백으로 처리.
 * ipv6 == false 면 IPv4, true 면 IPv6 형식으로 파싱한다.
 * 반환값: 읽은 접속 수 (에러 시 -1)
 */
static int scan_proc_net(const char *path, bool ipv6, FILE *logf) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[LINE_LEN];
    int count = 0;

    /* 첫 줄은 헤더 */
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }

    while (fgets(line, sizeof(line), f)) {
        /*
         * /proc/net/tcp 한 줄 예시:
         *   sl  local_address rem_address   st tx_queue ... inode ...
         *    0: 0100007F:1F90 0200007F:0050 01 00000000:00000000 00:... 12345 ...
         */
        char *tok[20];
        int ntok = 0;
        char *save = NULL;
        for (char *p = strtok_r(line, " \t\n", &save);
             p && ntok < 20;
             p = strtok_r(NULL, " \t\n", &save)) {
            tok[ntok++] = p;
        }
        if (ntok < 10) continue;

        conn_t c;
        memset(&c, 0, sizeof(c));

        /* local_address, rem_address 는 "HEXIP:HEXPORT" 형식 */
        char *colon;
        unsigned int port;

        colon = strchr(tok[1], ':');
        if (!colon) continue;
        *colon = '\0';
        if (ipv6) {
            if (!parse_ipv6_field(tok[1], c.local, sizeof(c.local))) continue;
        } else {
            if (!parse_ipv4_field(tok[1], c.local, sizeof(c.local))) continue;
        }
        if (sscanf(colon + 1, "%x", &port) != 1) continue;
        c.local_port = (int)port;

        colon = strchr(tok[2], ':');
        if (!colon) continue;
        *colon = '\0';
        if (ipv6) {
            if (!parse_ipv6_field(tok[2], c.remote, sizeof(c.remote))) continue;
        } else {
            if (!parse_ipv4_field(tok[2], c.remote, sizeof(c.remote))) continue;
        }
        if (sscanf(colon + 1, "%x", &port) != 1) continue;
        c.remote_port = (int)port;

        c.state = (unsigned int)strtoul(tok[3], NULL, 16);

        /* inode 는 10번째 토큰 (인덱스 9) */
        c.inode = strtoull(tok[9], NULL, 10);
        if (c.inode == 0) continue;

        /* LISTEN 소켓은 아직 성립된 접속이 아니므로 제외 */
        if (c.state == 0x0A) continue;
        /* 아직 접속이 안 된 소켓(remote 0.0.0.0)도 제외 */
        if (strcmp(c.remote, "0.0.0.0") == 0 || strcmp(c.remote, "::") == 0) continue;

        /* 대상 IP 가 아니면 무시 */
        if (!is_target(c.remote)) continue;

        /* 이미 로그한 접속이면 건너뜀 */
        if (!seen_is_new(c.inode)) continue;

        /* 새 접속 감지: 소유 프로세스 찾아서 로그 */
        int pid;
        char pname[128];
        find_owner(c.inode, &pid, pname, sizeof(pname));

        char ts[32];
        timestamp_now(ts, sizeof(ts));

        fprintf(logf,
            "[%s] NEW_CONN remote=%s:%d local=%s:%d state=%s pid=%d proc=%s inode=%llu\n",
            ts, c.remote, c.remote_port, c.local, c.local_port,
            state_name(c.state), pid,
            pname[0] ? pname : "-", (unsigned long long)c.inode);
        /* 매 로그 즉시 디스크에 쓴다 (크래시 시 로그 유실 방지) */
        fflush(logf);

        count++;
    }

    fclose(f);
    return count;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "사용법: %s [옵션]\n"
        "\n"
        "선택:\n"
        "  -t, --target IP     감지할 대상 IP (여러 번 지정 가능, 최대 %d개)\n"
        "                      IPv4/IPv6 모두 가능. 미지정 시 모든 TCP 접속 로그\n"
        "옵션:\n"
        "  -i, --interval MS   폴링 주기 (밀리초, 기본 1000)\n"
        "  -l, --log PATH      로그 파일 경로 (기본 ./tcp-conn-logger.log)\n"
        "  -h, --help          도움말\n"
        "\n"
        "예시:\n"
        "  %s -t 203.0.113.10 -t 8.8.8.8 -i 500 -l /var/log/connwatch.log\n",
        prog, MAX_TARGETS, prog);
}

int main(int argc, char **argv) {
    int interval_ms = 1000;
    const char *log_path = "./tcp-conn-logger.log";

    /* 간단한 수동 인자 파싱 (getopt 없이, --long 옵션도 받도록) */
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if ((strcmp(a, "-t") == 0 || strcmp(a, "--target") == 0) && i + 1 < argc) {
            if (g_target_count >= MAX_TARGETS) {
                fprintf(stderr, "대상 IP 는 최대 %d 개까지 지정할 수 있습니다.\n", MAX_TARGETS);
                return 1;
            }
            strncpy(g_targets[g_target_count], argv[++i], INET6_ADDRSTRLEN - 1);
            g_targets[g_target_count][INET6_ADDRSTRLEN - 1] = '\0';
            g_target_count++;
        } else if ((strcmp(a, "-i") == 0 || strcmp(a, "--interval") == 0) && i + 1 < argc) {
            interval_ms = atoi(argv[++i]);
            if (interval_ms < 50) interval_ms = 50;   /* 너무 빠른 폴링 방지 */
        } else if ((strcmp(a, "-l") == 0 || strcmp(a, "--log") == 0) && i + 1 < argc) {
            log_path = argv[++i];
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "알 수 없는 옵션: %s\n", a);
            usage(argv[0]);
            return 1;
        }
    }

    FILE *logf = fopen(log_path, "a");   /* append 모드: 기존 로그 유지 */
    if (!logf) {
        fprintf(stderr, "로그 파일을 열 수 없습니다: %s (%s)\n", log_path, strerror(errno));
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    char ts[32];
    timestamp_now(ts, sizeof(ts));
    fprintf(logf, "[%s] START targets=%d interval_ms=%d\n", ts, g_target_count, interval_ms);
    for (int i = 0; i < g_target_count; i++) {
        fprintf(logf, "[%s]   target[%d] = %s\n", ts, i, g_targets[i]);
    }
    fflush(logf);

    fprintf(stderr, "tcp-conn-logger 시작 (로그: %s, Ctrl+C 로 종료)\n", log_path);

    while (!g_stop) {
        scan_proc_net("/proc/net/tcp",  false, logf);
        scan_proc_net("/proc/net/tcp6", true,  logf);

        /* 밀리초 단위 sleep, 시그널에 빠르게 반응하도록 쪼개서 잠 */
        struct timespec req = {
            .tv_sec  = interval_ms / 1000,
            .tv_nsec = (long)(interval_ms % 1000) * 1000000L
        };
        nanosleep(&req, NULL);
    }

    timestamp_now(ts, sizeof(ts));
    fprintf(logf, "[%s] STOP\n", ts);
    fflush(logf);
    fclose(logf);
    return 0;
}
