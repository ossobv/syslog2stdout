/* syslog2stdout, Walter Doekes, OSSO B.V., 2016 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>


#define all(expr, c_str) ({ \
        char const *i = (c_str); \
        while (*i != '\0' && (expr)) { \
            ++i; \
        } \
        (*i == '\0'); /* all chars matched expr */ \
    })

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

int listen_on_udp_port(const int port)
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

int listen_on_unixdgram(const char *filename)
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

const char *sockaddr_human(
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
        written = snprintf(
            buf, buflen, "[%s]:%hu", inet6, ntohs(sa->in6.sin6_port));
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

const char *from_syslog(
        char *start_buf, char *start_msg, int msg_length, int *out_length)
{
    int prival;
    char *priend;
    char *newbuf;
    const char *facility;
    int facilitylen;
    const char *priority;
    int prioritylen;

    /* https://tools.ietf.org/html/rfc3164#section-4.1.2

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

    /* Prepend named priority */
    newbuf = priend - facilitylen - prioritylen - 3; /* .:SP */
    memcpy(newbuf, facility, facilitylen);
    newbuf[facilitylen] = '.';
    memcpy(newbuf + facilitylen + 1, priority, prioritylen);
    newbuf[facilitylen + prioritylen + 1] = ':';
    newbuf[facilitylen + prioritylen + 2] = ' ';

    /* Recalculate length */
    *out_length = msg_length + (start_msg - newbuf);
    return newbuf;
}

int main(const int argc, const char *const *argv)
{
    const char *listentype;
    int listenfd;

    if (argc != 2) {
        fprintf(
            stderr,
            "Usage: syslog2stdoutd LISTENADDR\n"
            "Where LISTENADDR is one of '/dev/log' or '514'\n");
        exit(1);
    }

    if (strlen(argv[1]) && all(*i >= '0' && *i <= '9', argv[1])) {
        const int portno = atoi(argv[1]);
        listentype = "udp";
        listenfd = listen_on_udp_port(portno); 
    } else {
        const char *listenaddr = argv[1];
        listentype = "unix";
        listenfd = listen_on_unixdgram(listenaddr);
    }
    if (listenfd < 0) {
        fprintf(
            stderr, "listening on %s addr %s failed: %s\n",
            listentype, argv[1], strerror(errno));
        exit(1);
    }

    while (1) {
        ssize_t size;
        /* All transport receiver implementations SHOULD be able to
         * accept messages of up to and including 2048 octets in
         * length.  Transport receivers MAY receive messages larger
         * than 2048 octets in length. */
        const size_t buflen = 8192;
        const size_t bufprefix = 64; /* MUST be enough for "fac.prio: " */
        char fullbuf[bufprefix + buflen + 2];
        char *buf = fullbuf + bufprefix;
        int flags = 0;
        union sockaddr_any src_addr = {0};
        socklen_t addrlen = sizeof(src_addr);

        const char *outbuf;
        int outlen;

        size = recvfrom(
            listenfd, buf, buflen, flags,
            (struct sockaddr*)&src_addr, &addrlen);
        if (size < 0) {
            perror("recvfrom");
            continue;
        }
#if 0
        {
            char namebuf[256];
            fprintf(
                stderr, "got msg with fam %d, addrlen %d, size %zd: %s\n",
                src_addr.family, addrlen, size,
                sockaddr_human(&src_addr, namebuf, sizeof(namebuf)));
        }
#endif
        if (size == 0) {
            continue;
        }

        if (buf[size - 1] != '\n') {
            buf[size++] = '\n';
        }
        buf[size] = '\0'; /* just in case */

        outbuf = from_syslog(fullbuf, buf, size, &outlen);
        if (write(STDOUT_FILENO, outbuf, outlen) < 0) {
            perror("write");
            break; /* this is bad */
        }
    }

    /* We never get here, unless write failed. */
    close(listenfd);
    exit(1);
}

/* vim: set ts=8 sw=4 sts=4 et ai: */
