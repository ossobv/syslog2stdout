/* syslog2stdout -- capture syslog and send to stdout, useful for docker
Copyright (C) 2016-2017,2024  Walter Doekes, OSSO B.V.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


What:
  A really bare bones syslog daemon that captures syslog events and
  sends them to stdout. Useful for Dockerized apps that do not provide
  an option to log to stdout. Also useful to spawn a quick syslog daemon
  somewhere.
Example docker usage:
  CMD ./syslog2stdout /dev/log & /app/that/logs/to/syslog
Example standalone usage:
  ./syslog2stdout 514 | while read -r L; do echo "$(date): $L"; done
Source:
  https://github.com/ossobv/syslog2stdout
License:
  GPL-3.0+

*/
#define PERIODIC_STATUS_REPORT 1
#define MAX_CONNECTIONS 512
#ifndef SYSLOG2STDOUT_VERSION
#define SYSLOG2STDOUT_VERSION "vFIXME"
#endif

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef PERIODIC_STATUS_REPORT
#include <signal.h>
#include <time.h>
#endif

#define all(expr, c_str) ({ \
        char const *ch = (c_str); \
        while (*ch != '\0' && (expr)) { \
            ++ch; \
        } \
        (*ch == '\0'); /* all chars matched expr */ \
    })

#define array_size(expr) (sizeof(expr) / sizeof((expr)[0]))

/* epoll FD flags */
const int EFF_MIN = 0x10000;                /* fd must be < EFF_MIN */
const int EFF_NOCLOSE = EFF_MIN;            /* server socket */
const int EFF_ACCEPT = EFF_NOCLOSE << 1;    /* needs accept() */

union sockaddr_any {
    sa_family_t family;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
    struct sockaddr_un un;
};

const char *const facilities[24] = {
    /* https://tools.ietf.org/html/rfc5424#section-6.2.1 */
    "kern",     /*  0  kernel messages */
    "user",     /*  1  user-level messages */
    "mail",     /*  2  mail system */
    "daemon",   /*  3  system daemons */
    "auth",     /*  4  security/authorization messages */
    "syslog",   /*  5  messages generated internally by syslogd */
    "lpr",      /*  6  line printer subsystem */
    "news",     /*  7  network news subsystem */
    "uucp",     /*  8  UUCP subsystem */
    "cron",     /*  9  clock daemon */
    "authpriv", /* 10  security/authorization messages */
    "ftp",      /* 11  FTP daemon */
    "ntp",      /* 12  NTP subsystem */
    "audit",    /* 13  log audit */
    "alert",    /* 14  log alert */
    "cron2",    /* 15  clock daemon (note 2) */
    "local0",   /* 16  local use 0  (local0) */
    "local1",   /* 17  local use 1  (local1) */
    "local2",   /* 18  local use 2  (local2) */
    "local3",   /* 19  local use 3  (local3) */
    "local4",   /* 20  local use 4  (local4) */
    "local5",   /* 21  local use 5  (local5) */
    "local6",   /* 22  local use 6  (local6) */
    "local7",   /* 23  local use 7  (local7) */
};

const char *const priorities[8] = {
    "emerg",    /*  0  Emergency: system is unusable */
    "alert",    /*  1  Alert: action must be taken immediately */
    "crit",     /*  2  Critical: critical conditions */
    "error",    /*  3  Error: error conditions */
    "warn",     /*  4  Warning: warning conditions */
    "notice",   /*  5  Notice: normal but significant condition */
    "info",     /*  6  Informational: informational messages */
    "debug",    /*  7  Debug: debug-level messages */
};

static int process_epoll_events(int epollfd);
static void process_fd_input(int epollfd, int fd, int is_connected);
static void process_fd_accept(int epollfd, int fd);
static void process_fd_close(int epollfd, int fd);

typedef unsigned char mask_t;
#define mask_array_size(n) ((n + sizeof(mask_t) * 8 - 1) / sizeof(mask_t))

#define HIGHEST_FD MAX_CONNECTIONS
mask_t connected_fds[mask_array_size(HIGHEST_FD)] = {0};

#define mask_count(mask) mask_count_(mask, sizeof(mask))
inline static int mask_count_(const mask_t* mask, unsigned max_size)
{
    int ret = 0;
    int idx;
    for (idx = 0; idx < max_size; ++idx) {
        int i;
        mask_t value = mask[idx];
        for (i = 0; i < sizeof(mask_t) * 8; ++i, value >>= 1) {
            ret += (value & 1);
        }
    }
    return ret;
}

#define mask_highest(mask) mask_highest_(mask, sizeof(mask))
inline static int mask_highest_(const mask_t* mask, unsigned max_size)
{
    int idx;
    for (idx = max_size - 1; idx >= 0; --idx) {
        int i;
        mask_t value = mask[idx];
        for (i = sizeof(mask_t) * 8 - 1; i >= 0; --i) {
            if (value >> i) {
                return (idx * sizeof(mask_t) * 8) + i;
            }
        }
    }
    return 0;
}

inline static void mask_set(mask_t* mask, int value)
{
    mask[value / (sizeof(mask_t) * 8)] |= (
        1 << (value % (sizeof(mask_t) * 8)));
}

inline static void mask_unset(mask_t* mask, int value)
{
    mask[value / (sizeof(mask_t) * 8)] &= ~(
        1 << (value % (sizeof(mask_t) * 8)));
}

#ifdef PERIODIC_STATUS_REPORT
static void periodic_handler(int sig, siginfo_t *si, void *uc)
{
    char buf[50 + 50 + HIGHEST_FD * 3 / 8];
    char *p = buf;
    int space_idx;
    int block_idx;
    int last_used_block = 0;

    buf[0] = '\0';
    strncat(p, "syslog2stdout " SYSLOG2STDOUT_VERSION, 50);
    p += strlen(buf);

    for (last_used_block = sizeof(connected_fds) - 1;
            last_used_block >= 0 && !connected_fds[last_used_block];
            --last_used_block); /* might become -1 */
    if (last_used_block >= 0) {
        /* This will write:
         * "connect fd mask: " when nothing is connected
         * "connect fd mask: 0fffffff 1" when fds 4 through 32 are all
         * connected */
        strncat(p, " [connected fd mask:", 50);
        p += strlen(p);

        for (block_idx = 0, space_idx = 0;
                block_idx <= last_used_block; ++block_idx) {
            int i;
            uint32_t block = connected_fds[block_idx];;
            for (i = 0; i < sizeof(mask_t) * 2 && (
                        block_idx < last_used_block || block); ++space_idx, ++i) {
                mask_t m = block & 0xf;
                block >>= 4;
                if ((space_idx % 8) == 0) {
                    *p++ = ' ';
                }
                if (m < 10) {
                    *p++ = '0' + m;
                } else {
                    *p++ = 'a' + m - 10;
                }
            }
        }
        *p++ = ']';
    }
    *p++ = '\n';
    *p = '\0';
    assert(p <= (buf + sizeof(buf)));

    /* Technically, using printf() to write to stderr is not safe from a
     * signal handler. However, we write so little stuff to stderr that
     * this has a high chance of succeeding and not intermixing with
     * other data. */
    fprintf(stderr, "%s", buf);
}
#endif

int listen_on_tcp_port(const int port)
{
    int sockfd;
    struct sockaddr_in6 in6 = {0};
    int reuse = 1;

    sockfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0) {
        return -1;
    }
    in6.sin6_family = AF_INET6;
    in6.sin6_port = htons(port);

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0) {
        int temp_errno = errno;
        perror("setsockopt(SO_REUSEADDR)");
        close(sockfd);
        errno = temp_errno;
        return -1;
    }
    if (bind(sockfd, (const struct sockaddr*)&in6, sizeof(in6)) < 0) {
        int temp_errno = errno;
        close(sockfd);
        errno = temp_errno;
        return -1;
    }
    if (listen(sockfd, 100) < 0) {
        int temp_errno = errno;
        close(sockfd);
        errno = temp_errno;
        return -1;
    }

    return sockfd;
}

static int listen_on_udp_port(const int port)
{
    int sockfd;
    struct sockaddr_in6 in6 = {0};

    sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        return -1;
    }
    in6.sin6_family = AF_INET6;
    in6.sin6_port = htons(port);
    if (bind(sockfd, (const struct sockaddr*)&in6, sizeof(in6)) < 0) {
        int temp_errno = errno;
        close(sockfd);
        errno = temp_errno;
        return -1;
    }

    return sockfd;
}

static int listen_on_unixdgram(const char *filename)
{
    int ret;
    struct stat st;
    int sockfd;
    struct sockaddr_un un = {0};

    /* Clean up before access */
    ret = stat(filename, &st);
    if ((ret == 0 || errno != ENOENT) &&
            !(ret == 0 && S_ISSOCK(st.st_mode) && unlink(filename) == 0)) {
        if (errno == 0) {
            errno = EACCES;
        }
        return -1;
    }

    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, filename, sizeof(un.sun_path) - 1);
    if (bind(sockfd, (const struct sockaddr*)&un, sizeof(un)) < 0) {
        int temp_errno = errno;
        close(sockfd);
        errno = temp_errno;
        return -1;
    }
    if (chmod(filename, 0666) < 0) {
        int temp_errno = errno;
        close(sockfd);
        errno = temp_errno;
        return -1;
    }

    return sockfd;
}

static const char *sockaddr_human(
        const union sockaddr_any *sa, char *buf, size_t buflen)
{
    int written;
    if (sa->family == AF_INET) {
        char inet4[INET_ADDRSTRLEN + 1];
        inet4[INET_ADDRSTRLEN] = '\0';
        inet_ntop(AF_INET, &sa->in.sin_addr, inet4, INET_ADDRSTRLEN);
        written = snprintf(
            buf, buflen, "%s:%hu", inet4, ntohs(sa->in.sin_port));
    } else if (sa->family == AF_INET6) {
        char inet6[INET6_ADDRSTRLEN + 1];
        inet6[INET6_ADDRSTRLEN] = '\0';
        inet_ntop(AF_INET6, &sa->in6.sin6_addr, inet6, INET6_ADDRSTRLEN);
        if (strncmp(inet6, "::ffff:", 7) != 0) {
            written = snprintf(
                buf, buflen, "[%s]:%hu", inet6, ntohs(sa->in6.sin6_port));
        } else {
            written = snprintf(
                buf, buflen, "%s:%hu", inet6 + 7, ntohs(sa->in6.sin6_port));
        }
    } else if (sa->family == AF_UNIX) {
        written = snprintf(buf, buflen, "\"%s\"", sa->un.sun_path);
    } else {
        written = -1;
    }
    if (written < 0 || written >= buflen) {
        buf[0] = '\0'; /* (would) overflow */
    }
    return buf;
}

static const char *from_syslog(
        char *start_buf, char *start_msg, int msg_length,
        const char *origin, int *out_length)
{
    int prival;
    char *priend;
    char *newbuf;
    char *newbufp;
    int originlen = strlen(origin);
    const char *facility;
    int facilitylen;
    const char *priority;
    int prioritylen;

    /* https://tools.ietf.org/html/rfc3164#section-4.1.2

    EXAMPLE FROM logger(1) OVER UNIX:

        "<191>Dec 20 13:28:57 walter: test"

    The HEADER contains two fields called the TIMESTAMP and the HOSTNAME.
    The TIMESTAMP will immediately follow the trailing ">" from the PRI
    part and single space characters MUST follow each of the TIMESTAMP
    and HOSTNAME fields.  HOSTNAME will contain the hostname, as it knows
    itself.

    (Ergo, something like this: HEADER = PRI TIMESTAMP SP HOSTNAME SP MSG)
    (Timestamp is in "Dec  8 12:34:56" format, and hostname is missing
    in the wild.)

    */

    /* https://tools.ietf.org/html/rfc5424#section-6.1

    EXAMPLE FROM logger(1) OVER UDP:

        "<191>1 2016-12-20T13:29:49.464902+01:00 walter-desktop walter - - "
        "[timeQuality tzKnown=\"1\" isSynced=\"1\" syncAccuracy=\"325323\"] "
        "test"

    SYSLOG-MSG      = HEADER SP STRUCTURED-DATA [SP MSG]

    HEADER          = PRI VERSION SP TIMESTAMP SP HOSTNAME
                      SP APP-NAME SP PROCID SP MSGID
    PRI             = "<" PRIVAL ">"
    PRIVAL          = 1*3DIGIT ; range 0 .. 191
    VERSION         = NONZERO-DIGIT 0*2DIGIT
    HOSTNAME        = NILVALUE / 1*255PRINTUSASCII

    APP-NAME        = NILVALUE / 1*48PRINTUSASCII
    PROCID          = NILVALUE / 1*128PRINTUSASCII
    MSGID           = NILVALUE / 1*32PRINTUSASCII

    TIMESTAMP       = NILVALUE / FULL-DATE "T" FULL-TIME
    FULL-DATE       = DATE-FULLYEAR "-" DATE-MONTH "-" DATE-MDAY
    DATE-FULLYEAR   = 4DIGIT
    DATE-MONTH      = 2DIGIT  ; 01-12
    DATE-MDAY       = 2DIGIT  ; 01-28, 01-29, 01-30, 01-31 based on
                              ; month/year
    FULL-TIME       = PARTIAL-TIME TIME-OFFSET
    PARTIAL-TIME    = TIME-HOUR ":" TIME-MINUTE ":" TIME-SECOND
                      [TIME-SECFRAC]
    TIME-HOUR       = 2DIGIT  ; 00-23
    TIME-MINUTE     = 2DIGIT  ; 00-59
    TIME-SECOND     = 2DIGIT  ; 00-59
    TIME-SECFRAC    = "." 1*6DIGIT
    TIME-OFFSET     = "Z" / TIME-NUMOFFSET
    TIME-NUMOFFSET  = ("+" / "-") TIME-HOUR ":" TIME-MINUTE


    STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT
    SD-ELEMENT      = "[" SD-ID *(SP SD-PARAM) "]"
    SD-PARAM        = PARAM-NAME "=" %d34 PARAM-VALUE %d34
    SD-ID           = SD-NAME
    PARAM-NAME      = SD-NAME
    PARAM-VALUE     = UTF-8-STRING ; characters '"', '\' and
                                   ; ']' MUST be escaped.
    SD-NAME         = 1*32PRINTUSASCII
                      ; except '=', SP, ']', %d34 (")

    MSG             = MSG-ANY / MSG-UTF8
    MSG-ANY         = *OCTET ; not starting with BOM
    MSG-UTF8        = BOM UTF-8-STRING
    BOM             = %xEF.BB.BF

    */
    start_buf[0] = 'E';
    start_buf[1] = 'R';
    start_buf[2] = 'R';
    start_buf[3] = '\n';
    start_buf[4] = '\0';
    *out_length = 4;

    if (start_msg[0] != '<') {
        return start_buf;
    }

    prival = atoi(&start_msg[1]);
    if (prival < 0 || prival > 191) {
        return start_buf;
    }
    facility = facilities[prival >> 3];
    facilitylen = strlen(facility);
    priority = priorities[prival & 7];
    prioritylen = strlen(priority);

    priend = strchr(start_msg, '>');
    if (priend == NULL) {
        return start_buf;
    }
    ++priend; /* after the '>' */

    /* Skip past timestamp if old-style is found. Use the separator
     * characters as a 99% heuristic. */
    if (msg_length - (priend - start_msg) >= 16) { /* "Dec  7 12:34:56 " */
        if (priend[3] == ' ' && priend[6] == ' ' && priend[9] == ':' &&
                priend[12] == ':' && priend[15] == ' ') {
            priend += 16; /* skip past TIMESTAMP */
        }
    }

    /* Prepend origin and named priority */
    newbuf = priend - facilitylen - prioritylen - 3; /* .:SP */

    /* If this is sent over UDP, we'll want to know from where. If it's
     * sent over an UNIX socket, there usually is no source, so this
     * will be empty. */
    if (originlen) {
        int originmax = originlen > 32 ? 32 : originlen;
        newbuf -= (originlen + 2); /* :SP */
        /* assert(newbuf>=start_buf) */
        memcpy(newbuf, origin, originmax);
        newbufp = newbuf + originmax;
        *newbufp++ = ':';
        *newbufp++ = ' ';
    } else {
        newbufp = newbuf;
    }

    memcpy(newbufp, facility, facilitylen);
    newbufp += facilitylen;
    *newbufp++ = '.';
    memcpy(newbufp, priority, prioritylen);
    newbufp += prioritylen;
    *newbufp++ = ':';
    *newbufp++ = ' ';

    /* Recalculate length */
    *out_length = msg_length + (start_msg - newbuf);
    return newbuf;
}

int main(const int argc, const char *const *argv)
{
#ifdef PERIODIC_STATUS_REPORT
    timer_t timerid;
    struct sigaction   sa = {0};
    struct sigevent sev;
    struct itimerspec its;
#endif
    int argi;
    int ret;
    int epollfd;

    if (argc < 2 || argc > 10) {
        fprintf(
            stderr,
            "syslog2stdout " SYSLOG2STDOUT_VERSION "\n"
            "Usage: syslog2stdout LISTENADDR...\n"
            "Where LISTENADDR is one of '/dev/log' or '514' or 'tcp/514'\n");
        exit(1);
    }

    /* Create epoll fd */
    epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (epollfd == -1) {
        perror("epoll_create1");
        exit(1);
    }

#ifdef PERIODIC_STATUS_REPORT
    /* Set handler for periodic updates */
    sa.sa_flags = 0; SA_SIGINFO;
    sa.sa_sigaction = periodic_handler;
    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        perror("sigaction(SIGALARM)");
        exit(1);
    }

    /* Create and start timer for periodic updats */
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGALRM; /* do not care that it does not queue up */
    sev.sigev_value.sival_ptr = &timerid;
    if (timer_create(CLOCK_REALTIME, &sev, &timerid) == -1) {
        perror("timer_create");
        exit(1);
    }
    its.it_value.tv_sec = 1;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 3600; /* every hour */
    its.it_interval.tv_nsec = 0;
    if (timer_settime(timerid, 0, &its, NULL) == -1) {
        perror("timer_settime");
        exit(1);
    }
#endif

    for (argi = 1; argi < argc; ++argi) {
        struct epoll_event ev = {0};
        int fd;
        int fd_flags;

        /* Try opening a listening socket */
        if (strncmp(argv[argi], "tcp/", 4) == 0 &&
                strlen(argv[argi] + 4) &&
                all(*ch >= '0' && *ch <= '9', argv[argi] + 4)) {
            const int portno = atoi(argv[argi] + 4);
            fd = listen_on_tcp_port(portno);
            if (fd < 0) {
                fprintf(
                    stderr, "listening on TCP port %d failed: %s\n",
                    portno, strerror(errno));
                exit(1);
            }
            fd_flags = EFF_NOCLOSE | EFF_ACCEPT;
        } else if (strlen(argv[argi]) &&
                all(*ch >= '0' && *ch <= '9', argv[argi])) {
            const int portno = atoi(argv[argi]);
            fd = listen_on_udp_port(portno);
            if (fd < 0) {
                fprintf(
                    stderr, "listening on UDP port %d failed: %s\n",
                    portno, strerror(errno));
                exit(1);
            }
            fd_flags = EFF_NOCLOSE;
        } else {
            const char *listenaddr = argv[argi];
            fd = listen_on_unixdgram(listenaddr);
            if (fd < 0) {
                fprintf(
                    stderr, "listening on UNIX DGRAM path %s failed: %s\n",
                    listenaddr, strerror(errno));
                exit(1);
            }
            fd_flags = EFF_NOCLOSE;
        }

        /* Add to poll events */
        assert(fd < EFF_MIN);
        ev.data.fd = fd | fd_flags;
        ev.events = EPOLLIN;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
            perror("epoll_ctl");
            exit(1);
        }

        /* Used fds will be:
         * 0 = stdin, 1 = stdout, 2 = stderr, 3 = epollfd
         * 4 = server socket 1, ...
         * That leaves us with plenty of fds until we're out. */
        assert(fd < HIGHEST_FD);
    }

    /* Run and listen */
    ret = process_epoll_events(epollfd);

    /* Cleanup */
    close(epollfd);
    {
        /* This list does not contain our listening sockets. Don't care.
         * They will be closed upon exit anyway. */
        int fd = mask_highest(connected_fds);
        while (fd >= 0) {
            close(fd);
            --fd;
        }
    }

    return ret;
}

static int process_epoll_events(int epollfd)
{
    /* NOTE: Max events being too low could cause us to never process
     * events on higher FDs if we keep getting traffic on the low ones.
     * Not a concern now. */
#define MAX_EVENTS 100
    struct epoll_event events[MAX_EVENTS];
    int nfds;

    /* Go into infinite loop */
    while (1) {
        int i;

        nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("epoll_wait");
            close(epollfd);
            return -1;
        }

        for (i = 0; i < nfds; ++i) {
            int fd = events[i].data.fd & (EFF_MIN - 1);
#if 0
            fprintf(
                    stderr, "epoll [%d, 0x%x, 0x%x]\n", i,
                    events[i].data.fd, events[i].events);
#endif
            if (events[i].data.fd & EFF_ACCEPT) {
                process_fd_accept(epollfd, fd);
            } else {
                /* Is this a connected socket? */
                const int is_connected = !(events[i].data.fd & EFF_NOCLOSE);
                process_fd_input(epollfd, fd, is_connected);
            }
        }
    }

    /* We should not get here.. */
    return -1;
}

static void process_fd_input(int epollfd, int fd, int is_connected)
{
    ssize_t size;
    /* All transport receiver implementations SHOULD be able to
     * accept messages of up to and including 2048 octets in
     * length.  Transport receivers MAY receive messages larger
     * than 2048 octets in length. */
    size_t buflen = 8192;
    const size_t bufprefix = 64; /* MUST be enough for "fac.prio: " */
    char fullbuf[bufprefix + buflen + 2];
    char *buf = fullbuf + bufprefix;
    union sockaddr_any src_addr = {0};
    socklen_t addrlen = sizeof(src_addr);

    char originbuf[256];
    const char *outbuf;
    int outlen;

    if (is_connected) {
        /* We might get multiple packets here for STREAM sockets. We
         * expect the messages to be LF-terminated. Reading it twice,
         * using MSG_PEEK allows us to keep no state about the socket.
         * This does make TCP sockets slightly less performant. So be it. */
        const int flags = MSG_PEEK;
        const char *p;

        size = recvfrom(
            fd, buf, buflen, flags,
            (struct sockaddr*)&src_addr, &addrlen);
        if (size < 0) {
            perror("recvfrom(MSG_PEEK)");
            return;
        }
        p = memchr(buf, '\n', size);
        if (p != NULL) {
            assert(p < buf + buflen);
            buflen = (p - buf + 1);
        }
    }

    size = recvfrom(
        fd, buf, buflen, 0,
        (struct sockaddr*)&src_addr, &addrlen);
    if (size < 0) {
        perror("recvfrom");
        return;
    }

    if (addrlen == 0) {
        /* Connected sockets do not get the address populated by recvfrom().
         * Forcefully get it anyway by using getpeername(). */
        addrlen = sizeof(src_addr);
        if (getpeername(fd, (struct sockaddr*)&src_addr, &addrlen) < 0) {
            perror("getpeername");
        }
    }

    sockaddr_human(&src_addr, originbuf, sizeof(originbuf));
#if 0
    fprintf(
        stderr, "got msg with fam %d, addrlen %d, size %zd: %s\n",
        src_addr.family, addrlen, size, originbuf);
#endif

    if (size == 0) {
        if (is_connected) {
            process_fd_close(epollfd, fd);
#if 0
            fprintf(
                stderr, "(fd %d did empty read, closed, now %d connected)\n",
                fd, mask_count(connected_fds));
#endif
        }
        return;
    }

    if (buf[size - 1] != '\n') {
        buf[size++] = '\n';
    }
    buf[size] = '\0'; /* just in case */

    outbuf = from_syslog(fullbuf, buf, size, originbuf, &outlen);
    if (write(STDOUT_FILENO, outbuf, outlen) < 0) {
        perror("write");
        exit(2); /* this is bad */
    }

    /* NOTE: Better to close invalid messages immediately than to try
     * and handle them gracefully. This could be a partial read. If we
     * have to handle those, we'll have to handle slowloris style
     * attacks. See if closing is fine. */
    if (strcmp(outbuf, "ERR\n") == 0 && is_connected) {
        process_fd_close(epollfd, fd);
        fprintf(
            stderr, "(fd %d did garbage read, closed, now %d connected)\n",
            fd, mask_count(connected_fds));
    }
}

static void process_fd_accept(int epollfd, int server_fd)
{
    struct epoll_event ev = {0};
    union sockaddr_any src_addr = {0};
    socklen_t socklen = sizeof(src_addr);
    char originbuf[256];
    int fd;

    fd = accept(server_fd, (struct sockaddr*)&src_addr, &socklen);
    if (fd < 0) {
        perror("accept");
        return;
    }
    sockaddr_human(&src_addr, originbuf, sizeof(originbuf));
#if 0
    fprintf(
            stderr, "(connection on fd %d from %s)\n",
            fd, originbuf);
#endif
    if (fd >= HIGHEST_FD || fd >= EFF_MIN) {
        fprintf(
            stderr, "(cannot handle fd as high as %d, closing)\n",
            fd);
        close(fd);
        return;
    }

    ev.events = EPOLLIN | EPOLLHUP;
    ev.data.fd = fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        perror("epoll_ctl: EPOLL_CTL_ADD");
        /* NOTE: This should not happen. Unsure what is up. Better just
         * die. */
        exit(1);
    }

    mask_set(connected_fds, fd);
}

static void process_fd_close(int epollfd, int fd)
{
    mask_unset(connected_fds, fd);

    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL) == -1) {
        perror("epoll_ctl: EPOLL_CTL_DEL");
    }
    close(fd);
}

/* vim: set ts=8 sw=4 sts=4 et ai: */
