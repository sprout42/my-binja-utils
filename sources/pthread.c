/*
union pthread_attr_t
{
    char __size[0x24];
    int32_t __align;
};

union pthread_condattr_t
{
    char __size[0x4];
    int32_t __align;
};

union pthread_cond_t
{
    struct
    {
        union
        {
            uint64_t __wseq;
            struct
            {
                uint32_t __low;
                uint32_t __high;
            } __wseq32;
        };
        union
        {
            uint64_t __g1_start;
            struct
            {
                uint32_t __low;
                uint32_t __high;
            } __g1_start32;
        };
        uint32_t __g_refs[0x2];
        uint32_t __g_size[0x2];
        uint32_t __g1_orig_size;
        uint32_t __wrefs;
        uint32_t __g_signals[0x2];
    } __data;
    char __size[0x30];
    int64_t __align;
};

struct __pthread_internal_slist
{
    struct __pthread_internal_slist* __next;
};

union pthread_mutexattr_t
{
    char __size[0x4];
    int32_t __align;
};

union pthread_mutex_t
{
    struct
    {
        int32_t __lock;
        uint32_t __count;
        int32_t __owner;
        int32_t __kind;
        uint32_t __nusers;
        union
        {
            int32_t __spins;
            __pthread_slist_t __list;
        };
    } __data;
    char __size[0x18];
    int32_t __align;
};

typedef struct __pthread_internal_slist __pthread_slist_t;

typedef uint32_t pthread_t;
*/

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
int pthread_detach(pthread_t thread);
int pthread_join(pthread_t thread, void **retval);
int pthread_cancel(pthread_t thread);
int pthread_setcancelstate(int state, int *oldstate);
int pthread_setcanceltype(int type, int *oldtype);
void pthread_testcancel(void);
int pthread_equal(pthread_t t1, pthread_t t2);
void pthread_exit(void *retval);
int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void));
int pthread_kill(pthread_t thread, int sig);
int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset);
int pthread_sigqueue(pthread_t thread, int sig, const union sigval value);

void pthread_cleanup_push(void (*routine)(void *), void *arg);
void pthread_cleanup_pop(int execute);

int pthread_attr_init(pthread_attr_t *attr);
int pthread_attr_destroy(pthread_attr_t *attr);

int pthread_cond_init(pthread_cond_t *cond, pthread_condattr_t *cond_attr);
int pthread_cond_signal(pthread_cond_t *cond);
int pthread_cond_broadcast(pthread_cond_t *cond);
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime);
int pthread_cond_destroy(pthread_cond_t *cond);

int pthread_mutexattr_init(pthread_mutexattr_t *attr);
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr);

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *mutexattr);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_destroy(pthread_mutex_t *mutex);

int pthread_once(pthread_once_t *once_control, void (*init_routine) (void));

int pthread_key_create(pthread_key_t *key, void (*destr_function) (void *));
int pthread_key_delete(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *pointer);
void * pthread_getspecific(pthread_key_t key);

int pthread_spin_init(pthread_spinlock_t *lock, int pshared);
int pthread_spin_destroy(pthread_spinlock_t *lock);
int pthread_spin_lock(pthread_spinlock_t *lock);
int pthread_spin_trylock(pthread_spinlock_t *lock);
int pthread_spin_unlock(pthread_spinlock_t *lock);

/*
union pthread_rwlockattr_t
{
    char __size[0x8];
    int32_t __align;
};

union pthread_rwlock_t
{
    struct
    {
        uint32_t __readers;
        uint32_t __writers;
        uint32_t __wrphase_futex;
        uint32_t __writers_futex;
        uint32_t __pad3;
        uint32_t __pad4;
        uint8_t __flags;
        uint8_t __shared;
        uint8_t __pad1;
        uint8_t __pad2;
        int32_t __cur_writer;
    } __data;
    char __size[0x20];
    int32_t __align;
};
*/

int pthread_rwlockattr_setkind_np(pthread_rwlockattr_t *attr, int pref);
int pthread_rwlockattr_getkind_np(const pthread_rwlockattr_t *attr, int *pref);

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock);
int pthread_rwlock_init(pthread_rwlock_t *rwlock, const pthread_rwlockattr_t *attr);
int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_timedrdlock(pthread_rwlock_t *rwlock, const struct timespec *abstime);
int pthread_rwlock_timedwrlock(pthread_rwlock_t *rwlock, const struct timespec *abstime);
