void *memcpy(void *dest, const void *src, size_t n);
int32_t memcmp(void const* s1, void const* s2, size_t len);
int32_t realloc(void* oldmem, size_t bytes);
int32_t malloc(size_t bytes);
void* memset(void* s, int32_t c, uint32_t n);
char* strstr(char const* haystack, char const* needle);
int32_t strcmp(char const* p1, char const* p2);
int32_t strcasecmp(uint8_t const* p1, char const* s2);
char* strcat(char* dest, char const* src);
char* strcpy(char* dest, char const* src);
char *strncpy(char *dest, const char *src, size_t n);

int32_t __fxstat(int32_t vers, int32_t fd, struct stat* buf);

char const* strchr(char const* s, int32_t c_in);
char* strtok(char* s, char const* delim);
char* strtok_r(char* s, char const* delim, char** save_ptr);
int32_t strncmp(char const* s1, char const* s2, size_t n);
size_t strlen(const char *s);
void *memmove(void *dest, const void *src, size_t n);

int32_t strtol(char const* nptr, char** endptr, int32_t base);
int64_t strtoll(char const* nptr, char** endptr, int32_t base);
uint32_t strtoul(char const* nptr, char** endptr, int32_t base);
uint64_t strtoull(char const* nptr, char** endptr, int32_t base);
float strtof(char const* nptr, char** endptr);
double strtod(char const* nptr, char** endptr);

int printf(const char *format, ...);
int fprintf(FILE *stream, const char *format, ...);
int dprintf(int fd, const char *format, ...);
int sprintf(char *str, const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);
int vprintf(const char *format, va_list ap);
int vfprintf(FILE *stream, const char *format, va_list ap);
int vdprintf(int fd, const char *format, va_list ap);
int vsprintf(char *str, const char *format, va_list ap);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);

int socket(int domain, int type, int protocol);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int shutdown(int sockfd, int how);
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int32_t connect(int32_t fd);
in_addr_t inet_addr(char const* cp);
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);
int inet_pton(int af, const char *src, void *dst);

uint32_t htonl(uint32_t hostlong);
uint16_t htons(uint16_t x);
uint32_t ntohl(uint32_t netlong);
uint16_t ntohs(uint16_t netshort);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

typedef int32_t __clockid_t;

typedef __clockid_t clockid_t;

typedef int32_t __time_t;

typedef int32_t __syscall_slong_t;

struct timespec
{
    __time_t tv_sec;
    __syscall_slong_t tv_nsec;
};

int clock_getres(clockid_t clockid, struct timespec *res);
int clock_gettime(clockid_t clockid, struct timespec *tp);
int clock_settime(clockid_t clockid, const struct timespec *tp);

typedef int32_t __fd_mask;

struct fd_set
{
    __fd_mask fds_bits[32];
};

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);

typedef uint32_t nfds_t;

int poll(struct pollfd *fds, nfds_t nfds, int timeout);
int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask);
int epoll_create(int size);
int epoll_create1(int flags);

typedef union epoll_data {
    void        *ptr;
    int          fd;
    uint32_t     u32;
    uint64_t     u64;
} epoll_data_t;

struct epoll_event {
    uint32_t     events;
    epoll_data_t data;
};

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

typedef unsigned int mode_t;

int open(const char *pathname, ...);
int creat(const char *pathname, mode_t mode);
int openat(int dirfd, const char *pathname, ...);
int openat2(int dirfd, const char *pathname, const struct open_how *how, size_t size);
ssize_t write(int32_t fd, size_t nbytes);
ssize_t read(int32_t fd, size_t nbytes);
off_t lseek(int32_t fd, off_t offset, int32_t whence);
int unlink(const char *pathname);
int unlinkat(int dirfd, const char *pathname, int flags);
int32_t fcntl(int32_t fd, int32_t arg2, int32_t cmd, ...);
int32_t fdatasync(int32_t fd);
void sync(void);
int syncfs(int fd);
int fsync(int fd);
int fseek(FILE *stream, long offset, int whence);
long ftell(FILE *stream);
void rewind(FILE *stream);

int chdir(const char *path);
int fchdir(int fd);
int chmod(const char *pathname, mode_t mode);
int fchmod(int fd, mode_t mode);
int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);

int rename(const char *oldpath, const char *newpath);
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);


typedef struct _G_fpos_t
{
  __off_t __pos;
  __mbstate_t __state;
} __fpos_t;

typedef __fpos_t fpos_t;

int fgetpos(FILE *stream, fpos_t *pos);
int fsetpos(FILE *stream, const fpos_t *pos);
int ioctl(int fd, unsigned long request, ...);

typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler);
int kill(pid_t pid, int sig);

int inotify_init(void);
int inotify_init1(int flags);
int inotify_add_watch(int fd, const char *pathname, uint32_t mask);

int mkdir(const char *pathname, mode_t mode);
int mkdirat(int dirfd, const char *pathname, mode_t mode);
mode_t umask(mode_t mask);

char* dlerror();
void* dlopen(char const* file, int32_t mode);
void* dlsym(void* handle);

char* getenv(char const* name);
char *secure_getenv(const char *name);
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);

struct fd_pair {
    long read_fd;
    long write_fd;
};
int pipe(struct fd_pair pipefd);
int pipe2(int pipefd[2], int flags);

pid_t fork(void);
int execl(const char *pathname, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
int execle(const char *pathname, const char *arg, ...);
int execv(const char *pathname, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int execvpe(const char *file, char *const argv[], char *const envp[]);

int dup(int oldfd);
int dup2(int oldfd, int newfd);
int dup3(int oldfd, int newfd, int flags);

typedef int uid_t;

struct passwd *getpwnam(const char *name);
struct passwd *getpwuid(uid_t uid);
int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result);
int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result);
int initgroups(const char *user, gid_t group);
int getgroups(int size, gid_t list[]);
int setgroups(size_t size, const gid_t *list);

pid_t setsid(void);
int setgid(gid_t gid);
int setuid(uid_t uid);
