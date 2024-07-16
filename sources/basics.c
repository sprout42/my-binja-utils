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
int32_t __fxstat(int32_t vers, int32_t fd, struct stat* buf);
uint32_t strtoul(char const* nptr, char** endptr, int32_t base);
char const* strchr(char const* s, int32_t c_in);
char* strtok(char* s, char const* delim);
int32_t strncmp(char const* s1, char const* s2, size_t n);
size_t strlen(const char *s);
void *memmove(void *dest, const void *src, size_t n);

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


int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);
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

/* struct epoll_event {
    uint32_t     events;
    epoll_data_t data;
}; */

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int open(const char *pathname, int flags, mode_t mode);
int creat(const char *pathname, mode_t mode);
int openat(int dirfd, const char *pathname, int flags, mode_t mode);
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

typedef enum {
    PR_SET_PDEATHSIG = 1,
    PR_GET_PDEATHSIG = 2,
    PR_GET_DUMPABLE = 3,
    PR_SET_DUMPABLE = 4,
    PR_GET_UNALIGN = 5,
    PR_SET_UNALIGN = 6,
    PR_GET_KEEPCAPS = 7,
    PR_SET_KEEPCAPS = 8,
    PR_GET_FPEMU = 9,
    PR_SET_FPEMU = 10,
    PR_GET_FPEXC = 11,
    PR_SET_FPEXC = 12,
    PR_GET_TIMING = 13,
    PR_SET_TIMING = 14,
    PR_SET_NAME = 15,
    PR_GET_NAME = 16,
    PR_GET_ENDIAN = 19,
    PR_SET_ENDIAN = 20,
    PR_GET_SECCOMP = 21,
    PR_SET_SECCOMP = 22,
    PR_CAPBSET_READ = 23,
    PR_CAPBSET_DROP = 24,
    PR_GET_TSC = 25,
    PR_SET_TSC = 26,
    PR_GET_SECUREBITS = 27,
    PR_SET_SECUREBITS = 28,
    PR_SET_TIMERSLACK = 29,
    PR_GET_TIMERSLACK = 30,
    PR_TASK_PERF_EVENTS_DISABLE = 31,
    PR_TASK_PERF_EVENTS_ENABLE = 32,
    PR_MCE_KILL = 33,
    PR_MCE_KILL_GET = 34,
    PR_SET_MM = 35,
    PR_SET_PTRACER = 0x59616d61,
    PR_SET_CHILD_SUBREAPER = 36,
    PR_GET_CHILD_SUBREAPER = 37,
    PR_SET_NO_NEW_PRIVS = 38,
    PR_GET_NO_NEW_PRIVS = 39,
    PR_GET_TID_ADDRESS = 40,
    PR_SET_THP_DISABLE = 41,
    PR_GET_THP_DISABLE = 42,
    PR_MPX_ENABLE_MANAGEMENT = 43,
    PR_MPX_DISABLE_MANAGEMENT = 44,
    PR_SET_FP_MODE = 45,
    PR_GET_FP_MODE = 46,
    PR_CAP_AMBIENT = 47,
    PR_SVE_SET_VL = 50,
    PR_SVE_GET_VL = 51,
    PR_GET_SPECULATION_CTRL = 52,
    PR_SET_SPECULATION_CTRL = 53,
    PR_PAC_RESET_KEYS = 54,
    PR_SET_TAGGED_ADDR_CTRL = 55,
    PR_GET_TAGGED_ADDR_CTRL = 56,
    PR_SET_IO_FLUSHER = 57,
    PR_GET_IO_FLUSHER = 58,
    PR_SET_SYSCALL_USER_DISPATCH = 59,
    PR_PAC_SET_ENABLED_KEYS = 60,
    PR_PAC_GET_ENABLED_KEYS = 61,
    PR_SCHED_CORE = 62,
} prctl_option_t;
int prctl (prctl_option_t option, ...);

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


typedef void* cap_t;

typedef enum {
    CAP_CLEAR=0,
    CAP_SET=1
} cap_flag_value_t;

typedef int cap_value_t;

typedef enum {
    CAP_EFFECTIVE = 0,
    CAP_PERMITTED = 1,
    CAP_INHERITABLE = 2
} cap_flag_t;

typedef enum {
    CAP_IAB_INH = 2,
    CAP_IAB_AMB = 3,
    CAP_IAB_BOUND = 4
} cap_iab_vector_t;

typedef struct cap_iab_s *cap_iab_t;

typedef enum {
    CAP_MODE_UNCERTAIN = 0,
    CAP_MODE_NOPRIV = 1,
    CAP_MODE_PURE1E_INIT = 2,
    CAP_MODE_PURE1E = 3,
} cap_mode_t;

typedef int uid_t;

cap_t cap_init(void);
int cap_free(void *obj_d);
cap_t cap_dup(cap_t cap_p);
int cap_clear(cap_t cap_p);
int cap_clear_flag(cap_t cap_p, cap_flag_t flag);
int cap_get_flag(cap_t cap_p, cap_value_t cap, cap_flag_t flag, cap_flag_value_t *value_p);
int cap_set_flag(cap_t cap_p, cap_flag_t flag, int ncap, const cap_value_t *caps, cap_flag_value_t value);
int cap_compare(cap_t cap_a, cap_t cap_b);
cap_t cap_from_text(const char* buf_p );
char *cap_to_text(cap_t caps, ssize_t * length_p);
int cap_from_name(const char* name , cap_value_t* cap_p);
char *cap_to_name(cap_value_t cap);
cap_t cap_get_proc(void);
int cap_set_proc(cap_t cap_p);
int cap_get_bound(cap_value_t cap);
int cap_drop_bound(cap_value_t cap);
int cap_get_ambient(cap_value_t cap);
int cap_set_ambient(cap_value_t cap, cap_flag_value_t value);
int cap_reset_ambient(void);
unsigned cap_get_secbits(void);
int cap_set_secbits(unsigned bits);
cap_mode_t cap_get_mode(void);
const char *cap_mode_name(cap_mode_t mode);
int cap_set_mode(cap_mode_t mode);
cap_t cap_get_pid(pid_t pid);
int cap_setuid(uid_t uid);
int cap_setgroups(gid_t gid, size_t ngroups, const gid_t groups);
