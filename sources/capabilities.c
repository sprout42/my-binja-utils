
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

typedef enum {
    SECBIT_NOROOT = 0x01,
    SECBIT_NOROOT_LOCKED = 0x02,
    SECBIT_NO_SETUID_FIXUP = 0x04,
    SECBIT_NO_SETUID_FIXUP_LOCKED = 0x08,
    SECBIT_KEEP_CAPS = 0x10,
    SECBIT_KEEP_CAPS_LOCKED = 0x20,
    SECBIT_NO_CAP_AMBIENT_RAISE = 0x40,
    SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED = 0x80
} prctl_set_securebits_flags_t;

int prctl (prctl_option_t option, ...);

typedef enum {
    CAP_CHOWN               = 0,
    CAP_DAC_OVERRIDE        = 1,
    CAP_DAC_READ_SEARCH     = 2,
    CAP_FOWNER              = 3,
    CAP_FSETID              = 4,
    CAP_KILL                = 5,
    CAP_SETGID              = 6,
    CAP_SETUID              = 7,
    CAP_SETPCAP             = 8,
    CAP_LINUX_IMMUTABLE     = 9,
    CAP_NET_BIND_SERVICE    = 10,
    CAP_NET_BROADCAST       = 11,
    CAP_NET_ADMIN           = 12,
    CAP_NET_RAW             = 13,
    CAP_IPC_LOCK            = 14,
    CAP_IPC_OWNER           = 15,
    CAP_SYS_MODULE          = 16,
    CAP_SYS_RAWIO           = 17,
    CAP_SYS_CHROOT          = 18,
    CAP_SYS_PTRACE          = 19,
    CAP_SYS_PACCT           = 20,
    CAP_SYS_ADMIN           = 21,
    CAP_SYS_BOOT            = 22,
    CAP_SYS_NICE            = 23,
    CAP_SYS_RESOURCE        = 24,
    CAP_SYS_TIME            = 25,
    CAP_SYS_TTY_CONFIG      = 26,
    CAP_MKNOD               = 27,
    CAP_LEASE               = 28,
    CAP_AUDIT_WRITE         = 29,
    CAP_AUDIT_CONTROL       = 30,
    CAP_SETFCAP             = 31,
    CAP_MAC_OVERRIDE        = 32,
    CAP_MAC_ADMIN           = 33,
    CAP_SYSLOG              = 34,
    CAP_WAKE_ALARM          = 35,
    CAP_BLOCK_SUSPEND       = 36,
    CAP_AUDIT_READ          = 37,
    CAP_PERFMON             = 38,
    CAP_BPF                 = 39,
    CAP_CHECKPOINT_RESTORE  = 40,
} cap_value_t;
/*typedef int cap_value_t;*/

typedef void* cap_t;

typedef enum {
    CAP_CLEAR=0,
    CAP_SET=1
} cap_flag_value_t;

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


int cap_clear(cap_t cap_p);
int cap_fill(cap_t cap_p, cap_flag_t to, cap_flag_t from);
int cap_fill_flag(cap_t cap_p, cap_flag_t to, const cap_t ref, cap_flag_t from);
int cap_clear_flag(cap_t cap_p, cap_flag_t flag);
int cap_compare(cap_t cap_a, cap_t cap_b);
ssize_t cap_copy_ext(void *ext_p, cap_t cap_p, ssize_t size);
cap_t cap_copy_int(const void *ext_p);
int cap_free(void *obj_d);
int cap_from_name(const char *name, cap_value_t *cap_p);
cap_t cap_from_text(const char *buf_p);
cap_t cap_get_fd(int fd);
cap_t cap_get_file(const char *path_p);
int cap_get_flag(cap_t cap_p, cap_value_t cap, cap_flag_t flag, cap_flag_value_t *value_p);
cap_value_t cap_max_bits();
cap_t cap_get_pid(pid_t pid);
cap_t cap_get_proc(void);
int cap_set_fd(int fd, cap_t caps);
int cap_set_file(const char *path_p, cap_t cap_p);
int cap_set_flag(cap_t cap_p, cap_flag_t flag, int ncap, const cap_value_t *caps, cap_flag_value_t value);
int cap_set_proc(cap_t cap_p);
ssize_t cap_size(cap_t cap_p);
char *cap_to_name(cap_value_t cap);
char *cap_to_text(cap_t caps, ssize_t *length_p);
cap_t cap_get_pid(pid_t pid);
cap_t cap_init();
cap_t cap_dup(cap_t cap_p);

char *cap_proc_root(const char *root);
int cap_get_nsowner(cap_t cap_p);
int cap_set_nsowner(cap_t cap_p, uid_t rootuid);
int cap_get_bound(cap_value_t cap);
int cap_drop_bound(cap_value_t cap);
int cap_get_ambient(cap_value_t cap);
int cap_set_ambient(cap_value_t cap, cap_flag_value_t value);
int cap_reset_ambient(void);
int cap_set_mode(cap_mode_t flavor);
cap_mode_t cap_get_mode(void);
const char *cap_mode_name(cap_mode_t flavor);
unsigned cap_get_secbits();
int cap_set_secbits(unsigned bits);
int cap_prctl(long int pr_cmd, long int arg1, long int arg2, long int arg3, long int arg4, long int arg5);
int cap_prctlw(long int pr_cmd, long int arg1, long int arg2, long int arg3, long int arg4, long int arg5);
int cap_setuid(uid_t uid);
int cap_setgroups(gid_t gid, size_t ngroups, const gid_t groups[]);
