/*
 * linux/kernel/lock.c - LIH Hybrid Lock Manager
 * 
 * Sistema de locks que unifica mecanismos de sincronização entre:
 *   - Linux: spinlocks, mutexes, rwlocks, RCU
 *   - GNU Mach: mutexes, lock sets, semaphores, simple locks
 * 
 * Parte do projeto LIH (Linux Is Hybrid)
 * 
 * Licença: GPLv2
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/clock.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/debug_locks.h>
#include <linux/lockdep.h>
#include <linux/atomic.h>
#include <linux/ktime.h>
#include <linux/wait.h>
#include <linux/hashtable.h>
#include <asm/barrier.h>
#include <asm/processor.h>

/* Headers do GNU Mach */
#include <mach/mach_types.h>
#include <mach/lock.h>
#include <mach/semaphore.h>
#include <mach/sync.h>

/* ============================================================================
 * Constantes e definições
 * ============================================================================ */

/* Tipos de lock */
#define LOCK_TYPE_SPINLOCK      0x0001  /* Spinlock Linux */
#define LOCK_TYPE_MUTEX         0x0002  /* Mutex Linux */
#define LOCK_TYPE_RWLOCK        0x0003  /* Read-Write lock Linux */
#define LOCK_TYPE_RCU           0x0004  /* RCU Linux */
#define LOCK_TYPE_MACH_MUTEX    0x0010  /* Mach mutex */
#define LOCK_TYPE_MACH_LOCKSET  0x0011  /* Mach lock set */
#define LOCK_TYPE_MACH_SEMAPHORE 0x0012 /* Mach semaphore */
#define LOCK_TYPE_MACH_SIMPLE   0x0013  /* Mach simple lock */

/* Flags de lock */
#define LOCK_FLAG_IRQ_SAFE      0x0001  /* Safe for IRQ context */
#define LOCK_FLAG_SLEEP_OK      0x0002  /* Can sleep when waiting */
#define LOCK_FLAG_RECURSIVE     0x0004  /* Recursive lock allowed */
#define LOCK_FLAG_DEADLINE      0x0008  /* Has deadline (priority inheritance) */
#define LOCK_FLAG_DEADLINE_CEIL 0x0010  /* Priority ceiling protocol */
#define LOCK_FLAG_STATS         0x0020  /* Collect statistics */
#define LOCK_FLAG_DEBUG         0x0040  /* Debug mode enabled */

/* Estados de lock */
#define LOCK_STATE_UNLOCKED     0
#define LOCK_STATE_LOCKED       1
#define LOCK_STATE_CONTENDED    2
#define LOCK_STATE_DEADLOCK     3
#define LOCK_STATE_ABANDONED    4

/* Prioridades para herança */
#define LOCK_PRIO_INHERIT_MIN   1
#define LOCK_PRIO_INHERIT_MAX   99
#define LOCK_PRIO_CEILING_DEFAULT 50

/* Timeouts */
#define LOCK_TIMEOUT_NEVER      0
#define LOCK_TIMEOUT_DEFAULT_MS 5000
#define LOCK_SPIN_MAX_ITER      1024

/* Estatísticas */
#define LOCK_STAT_MAX_HOLD_MS   10000
#define LOCK_STAT_MAX_WAIT_MS   60000

/* ============================================================================
 * Estruturas de dados
 * ============================================================================ */

/* Estatísticas de um lock */
struct lock_statistics {
    u64 lock_count;              /* Número total de aquisições */
    u64 lock_failures;           /* Número de falhas */
    u64 lock_contended;          /* Número de vezes que houve contenção */
    u64 lock_timeouts;           /* Número de timeouts */
    u64 lock_deadlocks;          /* Número de deadlocks detectados */
    
    u64 total_hold_time_ns;      /* Tempo total de hold */
    u64 total_wait_time_ns;      /* Tempo total de espera */
    u64 max_hold_time_ns;        /* Máximo tempo de hold */
    u64 max_wait_time_ns;        /* Máximo tempo de espera */
    
    u64 last_acquire_time;       /* Última aquisição */
    u64 last_release_time;       /* Última liberação */
    
    /* Quem está segurando */
    pid_t last_owner_pid;        /* Último owner (Linux) */
    thread_t last_owner_thread;  /* Último owner (Mach) */
};

/* Entidade de lock tracking (para detecção de deadlock) */
struct lock_tracking_entry {
    struct hlist_node node;
    u64 lock_id;                 /* ID do lock */
    void *lock_addr;             /* Endereço do lock */
    pid_t owner_pid;             /* PID do owner */
    thread_t owner_thread;       /* Thread Mach do owner */
    u64 acquire_time;            /* Tempo de aquisição */
    unsigned long stack_entries[16]; /* Stack trace */
    int stack_depth;             /* Profundidade da stack */
};

/* Wait queue entry (fila de espera) */
struct lock_waiter {
    struct list_head node;
    
    /* Identificação */
    pid_t pid;                   /* Linux PID */
    thread_t thread;             /* Mach thread */
    int task_type;               /* LINUX ou MACH */
    
    /* Prioridade */
    int priority;                /* Prioridade para herança */
    int original_priority;       /* Prioridade original */
    
    /* Deadline */
    u64 deadline;                /* Deadline absoluto */
    u64 start_wait;              /* Início da espera */
    
    /* Callback de timeout */
    void (*timeout_cb)(void *data);
    void *timeout_data;
    
    /* Estado */
    int state;
    struct completion *completion; /* Para wakeup */
};

/* Estrutura principal de lock híbrido */
struct hybrid_lock {
    /* Identificação */
    u64 id;                      /* ID único */
    int type;                    /* LOCK_TYPE_* */
    unsigned long flags;         /* LOCK_FLAG_* */
    char name[64];               /* Nome para debug */
    
    /* Lock nativo */
    union {
        /* Linux locks */
        struct {
            spinlock_t spinlock;
            mutex_t mutex;
            struct rw_semaphore rwsem;
            struct rcu_head rcu;
        } linux_lock;
        
        /* Mach locks */
        struct {
            struct mutex mach_mutex;
            struct lock_set *lock_set;
            struct semaphore semaphore;
            simple_lock_data_t simple_lock;
        } mach_lock;
    };
    
    /* Estado atual */
    atomic_t state;              /* LOCK_STATE_* */
    atomic_t refcount;           /* Contagem de referências */
    atomic_t waiters_count;      /* Número de waiters */
    
    /* Owner atual */
    union {
        struct task_struct *owner_task;
        thread_t owner_thread;
        u64 owner_id;
    };
    
    /* Filas de espera */
    struct list_head wait_queue; /* Waiters Linux */
    struct list_head mach_wait_queue; /* Waiters Mach */
    
    /* Protocolos de prioridade */
    int current_priority;        /* Prioridade atual (após herança) */
    int ceiling_priority;        /* Priority ceiling */
    int original_priority;       /* Prioridade original do owner */
    
    /* Para locks recursivos */
    int recursion_depth;
    pid_t recursion_pid;
    
    /* Deadline */
    u64 deadline;                /* Deadline para aquisição */
    struct timer_list timeout_timer; /* Timer para timeout */
    
    /* Estatísticas */
    struct lock_statistics stats;
    
    /* Deadlock detection */
    struct lock_tracking_entry *tracking;
    struct hlist_node deadlock_hash;
    
    /* Sincronização interna */
    raw_spinlock_t internal_lock;
    
    /* Callbacks */
    void (*on_acquire)(struct hybrid_lock *lock, void *owner);
    void (*on_release)(struct hybrid_lock *lock, void *owner);
    void (*on_contention)(struct hybrid_lock *lock, int waiters_count);
    void (*on_timeout)(struct hybrid_lock *lock, struct lock_waiter *waiter);
    
    /* Debug */
    void *debug_data;
    u64 debug_magic;
};

/* Hash table para detecção de deadlock */
#define DEADLOCK_HASH_BITS 10
#define DEADLOCK_HASH_SIZE (1 << DEADLOCK_HASH_BITS)

static DECLARE_HASHTABLE(deadlock_hash, DEADLOCK_HASH_BITS);
static DEFINE_SPINLOCK(deadlock_hash_lock);

/* Pool de locks híbridos */
static struct kmem_cache *hybrid_lock_cache;
static DEFINE_IDR(hybrid_lock_idr);
static DEFINE_RWLOCK(hybrid_lock_idr_lock);

/* Estatísticas globais */
struct global_lock_stats {
    atomic_t total_locks;
    atomic_t active_locks;
    atomic_t total_deadlocks;
    atomic_t total_timeouts;
    u64 total_acquire_time;
    u64 total_hold_time;
} global_stats;

/* ============================================================================
 * Funções auxiliares
 * ============================================================================ */

/* Gera ID único para lock */
static inline u64 generate_lock_id(void)
{
    static atomic64_t next_id = ATOMIC64_INIT(1);
    return atomic64_inc_return(&next_id);
}

/* Obtém timestamp atual em nanosegundos */
static inline u64 get_lock_timestamp(void)
{
    return local_clock();
}

/* Verifica se o lock é válido */
static inline bool is_lock_valid(struct hybrid_lock *lock)
{
    if (!lock)
        return false;
    
    if (lock->debug_magic != 0xDEADBEEFCAFEBABEULL)
        return false;
    
    return true;
}

/* Converte prioridade Linux para Mach */
static inline int linux_prio_to_mach_prio(int linux_prio)
{
    /* Linux: -20..19 -> Mach: 0..39 (invertido) */
    return (linux_prio + 20) * 2;
}

/* Converte prioridade Mach para Linux */
static inline int mach_prio_to_linux_prio(int mach_prio)
{
    /* Mach: 0..39 -> Linux: -20..19 */
    return (mach_prio / 2) - 20;
}

/* ============================================================================
 * Protocolos de prioridade (Priority Inheritance/Ceiling)
 * ============================================================================ */

/* Atualiza prioridade baseada nos waiters */
static void lock_update_priority(struct hybrid_lock *lock)
{
    struct lock_waiter *waiter;
    int max_priority = -1;
    unsigned long flags;
    
    if (!(lock->flags & LOCK_FLAG_DEADLINE))
        return;
    
    raw_spin_lock_irqsave(&lock->internal_lock, flags);
    
    /* Encontra a maior prioridade entre os waiters */
    list_for_each_entry(waiter, &lock->wait_queue, node) {
        if (waiter->priority > max_priority)
            max_priority = waiter->priority;
    }
    
    list_for_each_entry(waiter, &lock->mach_wait_queue, node) {
        if (waiter->priority > max_priority)
            max_priority = waiter->priority;
    }
    
    /* Aplica priority inheritance */
    if (max_priority > lock->current_priority) {
        lock->current_priority = max_priority;
        
        /* Atualiza prioridade do owner */
        if (lock->owner_task) {
            if (lock->flags & LOCK_FLAG_DEADLINE_CEIL)
                lock->owner_task->prio = max_priority;
            else
                lock->owner_task->prio = min(max_priority, lock->owner_task->normal_prio);
        } else if (lock->owner_thread) {
            thread_set_priority(lock->owner_thread, max_priority);
        }
    } else if (list_empty(&lock->wait_queue) && list_empty(&lock->mach_wait_queue)) {
        /* Restaura prioridade original */
        lock->current_priority = lock->original_priority;
        
        if (lock->owner_task)
            lock->owner_task->prio = lock->owner_task->normal_prio;
        else if (lock->owner_thread)
            thread_set_priority(lock->owner_thread, lock->original_priority);
    }
    
    raw_spin_unlock_irqrestore(&lock->internal_lock, flags);
}

/* Aplica priority ceiling protocol */
static int lock_check_priority_ceiling(struct hybrid_lock *lock, int priority)
{
    if (!(lock->flags & LOCK_FLAG_DEADLINE_CEIL))
        return 1;
    
    /* Verifica se a prioridade excede o teto */
    if (priority > lock->ceiling_priority) {
        printk(KERN_WARNING "Lock %s: Priority %d exceeds ceiling %d\n",
               lock->name, priority, lock->ceiling_priority);
        return 0;
    }
    
    /* Eleva prioridade do lock ao teto */
    lock->current_priority = lock->ceiling_priority;
    
    return 1;
}

/* ============================================================================
 * Detecção de deadlock
 * ============================================================================ */

/* Adiciona entrada de tracking para deadlock detection */
static void lock_add_tracking(struct hybrid_lock *lock, void *owner)
{
    struct lock_tracking_entry *entry;
    unsigned long flags;
    
    if (!(lock->flags & LOCK_FLAG_DEBUG))
        return;
    
    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return;
    
    entry->lock_id = lock->id;
    entry->lock_addr = lock;
    entry->acquire_time = get_lock_timestamp();
    
    if (owner) {
        if (lock->type == LOCK_TYPE_SPINLOCK || 
            lock->type == LOCK_TYPE_MUTEX ||
            lock->type == LOCK_TYPE_RWLOCK) {
            entry->owner_pid = ((struct task_struct *)owner)->pid;
            entry->owner_thread = NULL;
        } else {
            entry->owner_pid = 0;
            entry->owner_thread = (thread_t)owner;
        }
    }
    
    /* Captura stack trace */
    entry->stack_depth = stack_trace_save(entry->stack_entries, 16, 2);
    
    spin_lock_irqsave(&deadlock_hash_lock, flags);
    hash_add(deadlock_hash, &entry->node, lock->id);
    spin_unlock_irqrestore(&deadlock_hash_lock, flags);
    
    lock->tracking = entry;
}

/* Remove tracking entry */
static void lock_remove_tracking(struct hybrid_lock *lock)
{
    unsigned long flags;
    
    if (!lock->tracking)
        return;
    
    spin_lock_irqsave(&deadlock_hash_lock, flags);
    hash_del(&lock->tracking->node);
    spin_unlock_irqrestore(&deadlock_hash_lock, flags);
    
    kfree(lock->tracking);
    lock->tracking = NULL;
}

/* Detecta potencial deadlock (ciclo no grafo de locks) */
static int lock_detect_deadlock(struct hybrid_lock *lock, void *owner)
{
    struct lock_tracking_entry *entry;
    struct task_struct *owner_task = NULL;
    thread_t owner_thread = NULL;
    unsigned long flags;
    int bkt;
    
    if (!(lock->flags & LOCK_FLAG_DEBUG))
        return 0;
    
    /* Identifica owner */
    if (lock->type == LOCK_TYPE_SPINLOCK || 
        lock->type == LOCK_TYPE_MUTEX ||
        lock->type == LOCK_TYPE_RWLOCK) {
        owner_task = (struct task_struct *)owner;
    } else {
        owner_thread = (thread_t)owner;
    }
    
    /* Verifica se o owner já tem este lock */
    hash_for_each(deadlock_hash, bkt, entry, node) {
        if (entry->owner_pid == current->pid) {
            /* Potencial deadlock detectado */
            printk(KERN_ERR "Potential deadlock detected!\n");
            printk(KERN_ERR "Lock %s (id=%llu) already held by current task\n",
                   lock->name, lock->id);
            
            atomic_inc(&global_stats.total_deadlocks);
            return 1;
        }
    }
    
    return 0;
}

/* ============================================================================
 * Funções de lock específicas por tipo
 * ============================================================================ */

/* Spinlock operations */
static int spinlock_acquire(struct hybrid_lock *lock, int irq_flags)
{
    unsigned long flags = 0;
    
    if (irq_flags) {
        if (irq_flags & LOCK_FLAG_IRQ_SAFE)
            spin_lock_irqsave(&lock->linux_lock.spinlock, flags);
        else
            spin_lock_irq(&lock->linux_lock.spinlock);
    } else {
        spin_lock(&lock->linux_lock.spinlock);
    }
    
    lock->owner_task = current;
    lock->recursion_depth = 1;
    lock->recursion_pid = current->pid;
    
    return 0;
}

static void spinlock_release(struct hybrid_lock *lock, int irq_flags)
{
    lock->owner_task = NULL;
    lock->recursion_depth = 0;
    
    if (irq_flags) {
        if (irq_flags & LOCK_FLAG_IRQ_SAFE)
            spin_unlock_irqrestore(&lock->linux_lock.spinlock, irq_flags);
        else
            spin_unlock_irq(&lock->linux_lock.spinlock);
    } else {
        spin_unlock(&lock->linux_lock.spinlock);
    }
}

/* Mutex operations */
static int mutex_acquire(struct hybrid_lock *lock)
{
    int ret;
    
    if (lock->flags & LOCK_FLAG_RECURSIVE && 
        lock->recursion_pid == current->pid) {
        lock->recursion_depth++;
        return 0;
    }
    
    ret = mutex_lock_interruptible(&lock->linux_lock.mutex);
    if (ret)
        return ret;
    
    lock->owner_task = current;
    lock->recursion_depth = 1;
    lock->recursion_pid = current->pid;
    
    return 0;
}

static void mutex_release(struct hybrid_lock *lock)
{
    if (lock->flags & LOCK_FLAG_RECURSIVE && lock->recursion_depth > 1) {
        lock->recursion_depth--;
        return;
    }
    
    lock->owner_task = NULL;
    lock->recursion_depth = 0;
    
    mutex_unlock(&lock->linux_lock.mutex);
}

/* Read-Write lock operations */
static int rwlock_read_acquire(struct hybrid_lock *lock)
{
    int ret;
    
    ret = down_read_interruptible(&lock->linux_lock.rwsem);
    if (ret)
        return ret;
    
    /* Para rwlock, owner não é exclusivo */
    atomic_inc(&lock->refcount);
    
    return 0;
}

static int rwlock_write_acquire(struct hybrid_lock *lock)
{
    int ret;
    
    ret = down_write_interruptible(&lock->linux_lock.rwsem);
    if (ret)
        return ret;
    
    lock->owner_task = current;
    lock->recursion_depth = 1;
    
    return 0;
}

static void rwlock_read_release(struct hybrid_lock *lock)
{
    atomic_dec(&lock->refcount);
    up_read(&lock->linux_lock.rwsem);
}

static void rwlock_write_release(struct hybrid_lock *lock)
{
    lock->owner_task = NULL;
    up_write(&lock->linux_lock.rwsem);
}

/* Mach lock operations */
static int mach_mutex_acquire(struct hybrid_lock *lock, u64 timeout_ns)
{
    kern_return_t kr;
    
    if (timeout_ns == LOCK_TIMEOUT_NEVER) {
        kr = mutex_lock(&lock->mach_lock.mach_mutex);
    } else {
        kr = mutex_timed_lock(&lock->mach_lock.mach_mutex, 
                               mach_absolute_time() + 
                               ns_to_absolutetime(timeout_ns));
    }
    
    if (kr != KERN_SUCCESS) {
        if (kr == MACH_SEND_TIMED_OUT)
            atomic_inc(&global_stats.total_timeouts);
        return -ETIMEDOUT;
    }
    
    lock->owner_thread = current->mach_thread;
    lock->recursion_depth = 1;
    
    return 0;
}

static void mach_mutex_release(struct hybrid_lock *lock)
{
    lock->owner_thread = NULL;
    mutex_unlock(&lock->mach_lock.mach_mutex);
}

/* Mach semaphore operations */
static int mach_semaphore_wait(struct hybrid_lock *lock, u64 timeout_ns)
{
    kern_return_t kr;
    
    if (timeout_ns == LOCK_TIMEOUT_NEVER) {
        kr = semaphore_wait(&lock->mach_lock.semaphore);
    } else {
        kr = semaphore_timedwait(&lock->mach_lock.semaphore,
                                  mach_absolute_time() +
                                  ns_to_absolutetime(timeout_ns));
    }
    
    if (kr != KERN_SUCCESS)
        return -ETIMEDOUT;
    
    atomic_inc(&lock->refcount);
    
    return 0;
}

static void mach_semaphore_signal(struct hybrid_lock *lock)
{
    atomic_dec(&lock->refcount);
    semaphore_signal(&lock->mach_lock.semaphore);
}

/* ============================================================================
 * API principal do sistema de locks
 * ============================================================================ */

/**
 * hybrid_lock_create - Cria um novo lock híbrido
 * @type: Tipo do lock (LOCK_TYPE_*)
 * @flags: Flags do lock
 * @name: Nome do lock (para debug)
 * 
 * Retorna: Ponteiro para hybrid_lock ou ERR_PTR
 */
struct hybrid_lock *hybrid_lock_create(int type, unsigned long flags, const char *name)
{
    struct hybrid_lock *lock;
    int ret;
    
    lock = kmem_cache_alloc(hybrid_lock_cache, GFP_KERNEL);
    if (!lock)
        return ERR_PTR(-ENOMEM);
    
    memset(lock, 0, sizeof(*lock));
    
    lock->id = generate_lock_id();
    lock->type = type;
    lock->flags = flags;
    strscpy(lock->name, name ?: "unknown", sizeof(lock->name));
    
    atomic_set(&lock->state, LOCK_STATE_UNLOCKED);
    atomic_set(&lock->refcount, 0);
    atomic_set(&lock->waiters_count, 0);
    
    INIT_LIST_HEAD(&lock->wait_queue);
    INIT_LIST_HEAD(&lock->mach_wait_queue);
    
    raw_spin_lock_init(&lock->internal_lock);
    
    lock->current_priority = LOCK_PRIO_INHERIT_MIN;
    lock->ceiling_priority = LOCK_PRIO_CEILING_DEFAULT;
    lock->original_priority = LOCK_PRIO_INHERIT_MIN;
    
    lock->debug_magic = 0xDEADBEEFCAFEBABEULL;
    
    /* Inicializa lock nativo baseado no tipo */
    switch (type) {
    case LOCK_TYPE_SPINLOCK:
        spin_lock_init(&lock->linux_lock.spinlock);
        break;
    case LOCK_TYPE_MUTEX:
        mutex_init(&lock->linux_lock.mutex);
        break;
    case LOCK_TYPE_RWLOCK:
        init_rwsem(&lock->linux_lock.rwsem);
        break;
    case LOCK_TYPE_MACH_MUTEX:
        mutex_init(&lock->mach_lock.mach_mutex);
        break;
    case LOCK_TYPE_MACH_SEMAPHORE:
        semaphore_init(&lock->mach_lock.semaphore, 1);
        break;
    case LOCK_TYPE_MACH_SIMPLE:
        simple_lock_init(&lock->mach_lock.simple_lock);
        break;
    default:
        kmem_cache_free(hybrid_lock_cache, lock);
        return ERR_PTR(-EINVAL);
    }
    
    /* Registra no IDR */
    write_lock(&hybrid_lock_idr_lock);
    ret = idr_alloc(&hybrid_lock_idr, lock, (int)lock->id, 
                     (int)lock->id + 1, GFP_ATOMIC);
    write_unlock(&hybrid_lock_idr_lock);
    
    if (ret < 0) {
        kmem_cache_free(hybrid_lock_cache, lock);
        return ERR_PTR(ret);
    }
    
    atomic_inc(&global_stats.total_locks);
    atomic_inc(&global_stats.active_locks);
    
    printk(KERN_DEBUG "Lock created: %s (type=%d, id=%llu, flags=0x%lx)\n",
           lock->name, type, lock->id, flags);
    
    return lock;
}
EXPORT_SYMBOL(hybrid_lock_create);

/**
 * hybrid_lock_acquire - Adquire um lock híbrido
 * @lock: Lock a adquirir
 * @timeout_ns: Timeout em nanosegundos (0 = infinito)
 * @flags: Flags de aquisição
 * 
 * Retorna: 0 em sucesso, -errno em falha
 */
int hybrid_lock_acquire(struct hybrid_lock *lock, u64 timeout_ns, unsigned long flags)
{
    u64 start_time = 0;
    int ret = 0;
    
    if (!is_lock_valid(lock))
        return -EINVAL;
    
    if (flags & LOCK_FLAG_STATS)
        start_time = get_lock_timestamp();
    
    /* Verifica deadlock */
    if (lock_detect_deadlock(lock, current)) {
        lock->stats.lock_deadlocks++;
        return -EDEADLK;
    }
    
    /* Verifica protocolo de priority ceiling */
    if (!lock_check_priority_ceiling(lock, current->prio)) {
        return -EPERM;
    }
    
    /* Adquire baseado no tipo */
    switch (lock->type) {
    case LOCK_TYPE_SPINLOCK:
        ret = spinlock_acquire(lock, flags);
        break;
    case LOCK_TYPE_MUTEX:
        ret = mutex_acquire(lock);
        break;
    case LOCK_TYPE_RWLOCK:
        if (flags & LOCK_FLAG_DEADLINE)  /* Write lock */
            ret = rwlock_write_acquire(lock);
        else  /* Read lock */
            ret = rwlock_read_acquire(lock);
        break;
    case LOCK_TYPE_MACH_MUTEX:
        ret = mach_mutex_acquire(lock, timeout_ns);
        break;
    case LOCK_TYPE_MACH_SEMAPHORE:
        ret = mach_semaphore_wait(lock, timeout_ns);
        break;
    default:
        ret = -EINVAL;
    }
    
    if (ret == 0) {
        /* Atualiza estatísticas */
        atomic_set(&lock->state, LOCK_STATE_LOCKED);
        
        if (flags & LOCK_FLAG_STATS && start_time) {
            u64 acquire_time = get_lock_timestamp() - start_time;
            lock->stats.lock_count++;
            lock->stats.total_wait_time_ns += acquire_time;
            if (acquire_time > lock->stats.max_wait_time_ns)
                lock->stats.max_wait_time_ns = acquire_time;
            lock->stats.last_acquire_time = get_lock_timestamp();
            
            global_stats.total_acquire_time += acquire_time;
        }
        
        /* Tracking para deadlock detection */
        if (lock->flags & LOCK_FLAG_DEBUG)
            lock_add_tracking(lock, current);
        
        /* Atualiza prioridade */
        lock_update_priority(lock);
        
        /* Callback */
        if (lock->on_acquire)
            lock->on_acquire(lock, current);
    } else {
        lock->stats.lock_failures++;
        if (ret == -ETIMEDOUT)
            lock->stats.lock_timeouts++;
    }
    
    return ret;
}
EXPORT_SYMBOL(hybrid_lock_acquire);

/**
 * hybrid_lock_release - Libera um lock híbrido
 * @lock: Lock a liberar
 * @flags: Flags de liberação
 */
void hybrid_lock_release(struct hybrid_lock *lock, unsigned long flags)
{
    u64 start_time = 0;
    
    if (!is_lock_valid(lock))
        return;
    
    if (flags & LOCK_FLAG_STATS)
        start_time = get_lock_timestamp();
    
    /* Remove tracking */
    if (lock->flags & LOCK_FLAG_DEBUG)
        lock_remove_tracking(lock);
    
    /* Libera baseado no tipo */
    switch (lock->type) {
    case LOCK_TYPE_SPINLOCK:
        spinlock_release(lock, flags);
        break;
    case LOCK_TYPE_MUTEX:
        mutex_release(lock);
        break;
    case LOCK_TYPE_RWLOCK:
        if (flags & LOCK_FLAG_DEADLINE)  /* Write lock */
            rwlock_write_release(lock);
        else  /* Read lock */
            rwlock_read_release(lock);
        break;
    case LOCK_TYPE_MACH_MUTEX:
        mach_mutex_release(lock);
        break;
    case LOCK_TYPE_MACH_SEMAPHORE:
        mach_semaphore_signal(lock);
        break;
    }
    
    atomic_set(&lock->state, LOCK_STATE_UNLOCKED);
    
    /* Atualiza estatísticas */
    if (flags & LOCK_FLAG_STATS && start_time) {
        u64 hold_time = get_lock_timestamp() - start_time;
        lock->stats.total_hold_time_ns += hold_time;
        if (hold_time > lock->stats.max_hold_time_ns)
            lock->stats.max_hold_time_ns = hold_time;
        lock->stats.last_release_time = get_lock_timestamp();
        
        global_stats.total_hold_time += hold_time;
    }
    
    /* Acorda waiters se houver */
    if (atomic_read(&lock->waiters_count) > 0) {
        lock_update_priority(lock);
    }
    
    /* Callback */
    if (lock->on_release)
        lock->on_release(lock, current);
}
EXPORT_SYMBOL(hybrid_lock_release);

/**
 * hybrid_lock_try_acquire - Tenta adquirir lock sem bloquear
 * @lock: Lock a adquirir
 * 
 * Retorna: 0 em sucesso, -EBUSY se ocupado
 */
int hybrid_lock_try_acquire(struct hybrid_lock *lock)
{
    int ret;
    
    if (!is_lock_valid(lock))
        return -EINVAL;
    
    switch (lock->type) {
    case LOCK_TYPE_SPINLOCK:
        ret = spin_trylock(&lock->linux_lock.spinlock);
        if (ret) {
            lock->owner_task = current;
            return 0;
        }
        return -EBUSY;
        
    case LOCK_TYPE_MUTEX:
        ret = mutex_trylock(&lock->linux_lock.mutex);
        if (ret) {
            lock->owner_task = current;
            return 0;
        }
        return -EBUSY;
        
    case LOCK_TYPE_RWLOCK:
        ret = down_read_trylock(&lock->linux_lock.rwsem);
        if (ret)
            return 0;
        ret = down_write_trylock(&lock->linux_lock.rwsem);
        if (ret) {
            lock->owner_task = current;
            return 0;
        }
        return -EBUSY;
        
    case LOCK_TYPE_MACH_MUTEX:
        if (mutex_trylock(&lock->mach_lock.mach_mutex) == KERN_SUCCESS) {
            lock->owner_thread = current->mach_thread;
            return 0;
        }
        return -EBUSY;
        
    default:
        return -EINVAL;
    }
}
EXPORT_SYMBOL(hybrid_lock_try_acquire);

/**
 * hybrid_lock_destroy - Destroi um lock híbrido
 * @lock: Lock a destruir
 */
void hybrid_lock_destroy(struct hybrid_lock *lock)
{
    if (!is_lock_valid(lock))
        return;
    
    /* Verifica se o lock está livre */
    if (atomic_read(&lock->state) != LOCK_STATE_UNLOCKED) {
        printk(KERN_WARNING "Destroying locked lock %s\n", lock->name);
    }
    
    /* Remove do IDR */
    write_lock(&hybrid_lock_idr_lock);
    idr_remove(&hybrid_lock_idr, (int)lock->id);
    write_unlock(&hybrid_lock_idr_lock);
    
    /* Destroi lock nativo */
    switch (lock->type) {
    case LOCK_TYPE_MUTEX:
        mutex_destroy(&lock->linux_lock.mutex);
        break;
    case LOCK_TYPE_MACH_MUTEX:
        mutex_destroy(&lock->mach_lock.mach_mutex);
        break;
    case LOCK_TYPE_MACH_SEMAPHORE:
        semaphore_destroy(&lock->mach_lock.semaphore);
        break;
    }
    
    lock->debug_magic = 0;
    
    kmem_cache_free(hybrid_lock_cache, lock);
    
    atomic_dec(&global_stats.active_locks);
    
    printk(KERN_DEBUG "Lock destroyed: %s (id=%llu)\n", lock->name, lock->id);
}
EXPORT_SYMBOL(hybrid_lock_destroy);

/* ============================================================================
 * Funções de query e estatísticas
 * ============================================================================ */

/**
 * hybrid_lock_get_stats - Obtém estatísticas de um lock
 * @lock: Lock a consultar
 * @stats: Estrutura para preencher
 */
void hybrid_lock_get_stats(struct hybrid_lock *lock, struct lock_statistics *stats)
{
    if (!is_lock_valid(lock) || !stats)
        return;
    
    memcpy(stats, &lock->stats, sizeof(*stats));
}
EXPORT_SYMBOL(hybrid_lock_get_stats);

/**
 * hybrid_lock_get_owner - Obtém o owner atual do lock
 * @lock: Lock a consultar
 * @owner_pid: Ponteiro para preencher PID (Linux)
 * @owner_thread: Ponteiro para preencher thread (Mach)
 * 
 * Retorna: 1 se locked, 0 se unlocked
 */
int hybrid_lock_get_owner(struct hybrid_lock *lock, pid_t *owner_pid, thread_t *owner_thread)
{
    if (!is_lock_valid(lock))
        return -EINVAL;
    
    if (atomic_read(&lock->state) != LOCK_STATE_LOCKED) {
        if (owner_pid) *owner_pid = 0;
        if (owner_thread) *owner_thread = NULL;
        return 0;
    }
    
    if (owner_pid && lock->owner_task)
        *owner_pid = lock->owner_task->pid;
    
    if (owner_thread && lock->owner_thread)
        *owner_thread = lock->owner_thread;
    
    return 1;
}
EXPORT_SYMBOL(hybrid_lock_get_owner);

/* ============================================================================
 * RCU (Read-Copy-Update) operations
 * ============================================================================ */

/**
 * hybrid_rcu_read_lock - Inicia seção RCU híbrida
 */
void hybrid_rcu_read_lock(void)
{
    rcu_read_lock();
}
EXPORT_SYMBOL(hybrid_rcu_read_lock);

/**
 * hybrid_rcu_read_unlock - Termina seção RCU híbrida
 */
void hybrid_rcu_read_unlock(void)
{
    rcu_read_unlock();
}
EXPORT_SYMBOL(hybrid_rcu_read_unlock);

/**
 * hybrid_synchronize_rcu - Espera por seções RCU pendentes
 */
void hybrid_synchronize_rcu(void)
{
    synchronize_rcu();
}
EXPORT_SYMBOL(hybrid_synchronize_rcu);

/* ============================================================================
 * Inicialização e finalização
 * ============================================================================ */

static int __init hybrid_lock_init(void)
{
    int ret;
    
    printk(KERN_INFO "LIH Hybrid Lock Manager: Inicializando...\n");
    
    /* Cria cache de locks */
    hybrid_lock_cache = kmem_cache_create("hybrid_lock",
                                          sizeof(struct hybrid_lock),
                                          __alignof__(struct hybrid_lock),
                                          SLAB_PANIC | SLAB_ACCOUNT,
                                          NULL);
    if (!hybrid_lock_cache)
        return -ENOMEM;
    
    /* Inicializa IDR */
    idr_init(&hybrid_lock_idr);
    
    /* Inicializa hash de deadlock */
    hash_init(deadlock_hash);
    
    /* Inicializa estatísticas globais */
    atomic_set(&global_stats.total_locks, 0);
    atomic_set(&global_stats.active_locks, 0);
    atomic_set(&global_stats.total_deadlocks, 0);
    atomic_set(&global_stats.total_timeouts, 0);
    global_stats.total_acquire_time = 0;
    global_stats.total_hold_time = 0;
    
    printk(KERN_INFO "LIH Hybrid Lock Manager: Inicializado\n");
    printk(KERN_INFO "  - Lock cache size: %zu bytes\n", sizeof(struct hybrid_lock));
    printk(KERN_INFO "  - Deadlock hash size: %d entries\n", DEADLOCK_HASH_SIZE);
    
    return 0;
}

static void __exit hybrid_lock_exit(void)
{
    printk(KERN_INFO "LIH Hybrid Lock Manager: Finalizando...\n");
    
    /* Destroi cache */
    kmem_cache_destroy(hybrid_lock_cache);
    
    /* Destroi IDR */
    idr_destroy(&hybrid_lock_idr);
    
    printk(KERN_INFO "LIH Hybrid Lock Manager: Finalizado\n");
    printk(KERN_INFO "  - Total locks created: %d\n", 
           atomic_read(&global_stats.total_locks));
    printk(KERN_INFO "  - Deadlocks detected: %d\n",
           atomic_read(&global_stats.total_deadlocks));
    printk(KERN_INFO "  - Timeouts: %d\n",
           atomic_read(&global_stats.total_timeouts));
}

module_init(hybrid_lock_init);
module_exit(hybrid_lock_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LIH Project");
MODULE_DESCRIPTION("LIH Hybrid Lock Manager - Unified synchronization for Linux + Mach");
MODULE_VERSION("1.0");
