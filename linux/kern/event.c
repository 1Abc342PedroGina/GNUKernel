/*
 * linux/kernel/event.c - LIH Event Subsystem
 * 
 * Gerencia eventos assíncronos entre Linux e GNU Mach:
 *   - Eventos de sistema (criação/destruição de processos/threads)
 *   - Eventos de memória (page faults, alocações)
 *   - Eventos de IPC (mensagens, portas)
 *   - Eventos de sincronização (locks, semáforos)
 *   - Eventos de temporização (timers, deadlines)
 *   - Eventos de interrupção (IRQ handling)
 *   - Eventos personalizados (para extensibilidade)
 * 
 * Parte do projeto LIH (Linux Is Hybrid)
 * 
 * Licença: GPLv2
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/time64.h>
#include <linux/ktime.h>
#include <linux/percpu.h>
#include <linux/cpumask.h>
#include <linux/rcupdate.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/ratelimit.h>

/* Headers do GNU Mach */
#include <mach/mach_types.h>
#include <mach/message.h>
#include <mach/notify.h>
#include <mach/sync.h>

/* ============================================================================
 * Constantes e definições
 * ============================================================================ */

/* Tipos de evento */
#define LIH_EVENT_TYPE_NONE             0x0000
#define LIH_EVENT_TYPE_SYSTEM           0x0001  /* Eventos de sistema */
#define LIH_EVENT_TYPE_MEMORY           0x0002  /* Eventos de memória */
#define LIH_EVENT_TYPE_IPC              0x0004  /* Eventos de IPC */
#define LIH_EVENT_TYPE_SYNC             0x0008  /* Eventos de sincronização */
#define LIH_EVENT_TYPE_TIMER            0x0010  /* Eventos de temporização */
#define LIH_EVENT_TYPE_INTERRUPT        0x0020  /* Eventos de interrupção */
#define LIH_EVENT_TYPE_CUSTOM           0x8000  /* Eventos personalizados */

/* Subtipos de evento */
#define LIH_EVENT_SUBTYPE_TASK_CREATE   0x0001
#define LIH_EVENT_SUBTYPE_TASK_EXIT     0x0002
#define LIH_EVENT_SUBTYPE_TASK_EXEC     0x0003
#define LIH_EVENT_SUBTYPE_THREAD_CREATE 0x0004
#define LIH_EVENT_SUBTYPE_THREAD_EXIT   0x0005
#define LIH_EVENT_SUBTYPE_PAGE_FAULT    0x0010
#define LIH_EVENT_SUBTYPE_PAGE_ALLOC    0x0011
#define LIH_EVENT_SUBTYPE_PAGE_FREE     0x0012
#define LIH_EVENT_SUBTYPE_MSG_SEND      0x0020
#define LIH_EVENT_SUBTYPE_MSG_RECV      0x0021
#define LIH_EVENT_SUBTYPE_PORT_CREATE   0x0022
#define LIH_EVENT_SUBTYPE_PORT_DESTROY  0x0023
#define LIH_EVENT_SUBTYPE_LOCK_ACQUIRE  0x0030
#define LIH_EVENT_SUBTYPE_LOCK_RELEASE  0x0031
#define LIH_EVENT_SUBTYPE_SEM_WAIT      0x0032
#define LIH_EVENT_SUBTYPE_SEM_SIGNAL    0x0033
#define LIH_EVENT_SUBTYPE_TIMER_EXPIRED 0x0040
#define LIH_EVENT_SUBTYPE_DEADLINE_MISS 0x0041
#define LIH_EVENT_SUBTYPE_IRQ_HANDLED   0x0050

/* Prioridades de evento */
#define LIH_EVENT_PRIO_CRITICAL         0  /* Crítico (não pode ser perdido) */
#define LIH_EVENT_PRIO_HIGH             1  /* Alta prioridade */
#define LIH_EVENT_PRIO_NORMAL           2  /* Prioridade normal */
#define LIH_EVENT_PRIO_LOW              3  /* Baixa prioridade */
#define LIH_EVENT_PRIO_BACKGROUND       4  /* Background (pode ser coalescido) */

/* Flags de evento */
#define LIH_EVENT_FLAG_SYNC             (1 << 0)  /* Evento síncrono */
#define LIH_EVENT_FLAG_ASYNC            (1 << 1)  /* Evento assíncrono */
#define LIH_EVENT_FLAG_BROADCAST        (1 << 2)  /* Broadcast para múltiplos listeners */
#define LIH_EVENT_FLAG_COALESCE         (1 << 3)  /* Permite coalescência */
#define LIH_EVENT_FLAG_PERSISTENT       (1 << 4)  /* Evento persistente */
#define LIH_EVENT_FLAG_CALLBACK         (1 << 5)  /* Tem callback associado */
#define LIH_EVENT_FLAG_NO_WAKEUP        (1 << 6)  /* Não acorda listeners */
#define LIH_EVENT_FLAG_TIMESTAMP        (1 << 7)  /* Inclui timestamp */

/* Estados de evento */
#define LIH_EVENT_STATE_PENDING         0
#define LIH_EVENT_STATE_PROCESSING      1
#define LIH_EVENT_STATE_COMPLETED       2
#define LIH_EVENT_STATE_CANCELLED       3
#define LIH_EVENT_STATE_TIMEOUT         4

/* Configurações do sistema */
#define LIH_EVENT_QUEUE_SIZE            4096    /* Tamanho da fila de eventos */
#define LIH_EVENT_MAX_HANDLERS          256     /* Máximo handlers por tipo */
#define LIH_EVENT_COALESCE_WINDOW_NS    1000000 /* Janela de coalescência (1ms) */
#define LIH_EVENT_DEFAULT_TIMEOUT_MS    5000    /* Timeout padrão (5s) */
#define LIH_EVENT_WQ_MAX_ACTIVE         32      /* Máximo workers ativos */

/* Estatísticas */
#define LIH_EVENT_STAT_HASH_BITS        8
#define LIH_EVENT_STAT_HASH_SIZE        (1 << LIH_EVENT_STAT_HASH_BITS)

/* ============================================================================
 * Estruturas de dados
 * ============================================================================ */

/* Estrutura base de evento */
struct lih_event {
    u64 id;                             /* ID único do evento */
    u32 type;                           /* Tipo do evento (LIH_EVENT_TYPE_*) */
    u32 subtype;                        /* Subtipo do evento */
    u32 priority;                       /* Prioridade (LIH_EVENT_PRIO_*) */
    u32 flags;                          /* Flags do evento */
    u32 state;                          /* Estado atual */
    
    u64 timestamp;                      /* Timestamp de criação */
    u64 deadline;                       /* Deadline para processamento */
    
    /* Origem do evento */
    union {
        pid_t source_pid;               /* PID de origem (Linux) */
        thread_t source_thread;         /* Thread de origem (Mach) */
        int source_cpu;                 /* CPU de origem */
    };
    
    /* Destino do evento */
    union {
        pid_t target_pid;               /* PID de destino (Linux) */
        thread_t target_thread;         /* Thread de destino (Mach) */
        struct lih_event_queue *target_queue; /* Fila de destino */
    };
    
    /* Dados específicos do evento */
    union {
        /* Eventos de sistema */
        struct {
            pid_t pid;
            pid_t ppid;
            uid_t uid;
            char comm[16];
            unsigned long clone_flags;
        } task;
        
        struct {
            pid_t pid;
            pid_t tid;
            unsigned long entry_ip;
            unsigned long stack_start;
        } thread;
        
        /* Eventos de memória */
        struct {
            unsigned long vaddr;
            unsigned long paddr;
            size_t size;
            int fault_type;
            int prot_flags;
        } memory;
        
        /* Eventos de IPC */
        struct {
            mach_port_t port;
            mach_msg_id_t msg_id;
            size_t msg_size;
            int msg_priority;
        } ipc;
        
        /* Eventos de sincronização */
        struct {
            void *lock_addr;
            int lock_type;
            int acquire_result;
            u64 wait_time_ns;
        } sync;
        
        /* Eventos de temporização */
        struct {
            u64 expires;
            u64 period;
            int cpu;
            void (*callback)(void *);
            void *data;
        } timer;
        
        /* Eventos de interrupção */
        struct {
            int irq;
            struct pt_regs regs;
            int handled;
        } irq;
        
        /* Dados personalizados */
        struct {
            u32 custom_type;
            size_t data_len;
            u8 data[128];
        } custom;
    } data;
    
    /* Callback de conclusão */
    void (*completion_cb)(struct lih_event *event, void *data);
    void *completion_data;
    
    /* Listas e filas */
    struct list_head queue_node;
    struct list_head pending_node;
    struct hlist_node hash_node;
    struct rcu_head rcu;
    
    /* Referências */
    atomic_t refcount;
    struct completion completion;
};

/* Fila de eventos */
struct lih_event_queue {
    u32 id;                             /* ID da fila */
    char name[64];                      /* Nome da fila */
    
    struct list_head events;            /* Lista de eventos pendentes */
    spinlock_t lock;                    /* Lock da fila */
    wait_queue_head_t waitq;            /* Fila de espera */
    
    atomic_t pending_count;             /* Contagem de eventos pendentes */
    atomic_t max_pending;               /* Máximo pendente histórico */
    u64 total_events;                   /* Total de eventos processados */
    
    u32 flags;                          /* Flags da fila */
    int priority;                       /* Prioridade da fila */
    
    struct lih_event_queue *next;       /* Próxima fila na chain */
};

/* Handler de eventos */
struct lih_event_handler {
    u32 type;                           /* Tipo de evento tratado */
    u32 subtype;                        /* Subtipo (0 = todos) */
    int priority;                       /* Prioridade do handler */
    
    /* Função de callback */
    int (*handler)(struct lih_event *event, void *context);
    void *context;
    
    /* Para handlers de filtro */
    int (*filter)(struct lih_event *event, void *filter_data);
    void *filter_data;
    
    /* Estatísticas */
    atomic_t events_processed;
    atomic_t events_filtered;
    atomic_t events_errors;
    
    struct list_head list;
    struct rcu_head rcu;
};

/* Subsistema de eventos */
struct lih_event_subsystem {
    int state;                          /* Estado do subsistema */
    unsigned long flags;                /* Flags globais */
    
    /* Filas de eventos */
    struct lih_event_queue *system_queue;    /* Fila do sistema */
    struct lih_event_queue *user_queue;      /* Fila de usuário */
    struct lih_event_queue *monitor_queue;   /* Fila de monitoramento */
    
    /* Handlers registrados */
    struct list_head handlers[LIH_EVENT_TYPE_CUSTOM + 1];
    spinlock_t handlers_lock;
    
    /* Tabela hash para busca rápida de eventos */
    DECLARE_HASHTABLE(event_hash, LIH_EVENT_STAT_HASH_BITS);
    spinlock_t hash_lock;
    
    /* Pool de eventos */
    struct kmem_cache *event_cache;
    atomic_t events_in_flight;
    atomic_t events_allocated;
    
    /* Workqueues */
    struct workqueue_struct *event_wq;
    struct workqueue_struct *high_prio_wq;
    
    /* Timers de limpeza */
    struct timer_list cleanup_timer;
    struct delayed_work expiry_work;
    
    /* Estatísticas globais */
    struct {
        atomic64_t total_events;
        atomic64_t total_dropped;
        atomic64_t total_timeouts;
        atomic64_t total_errors;
        atomic64_t total_coalesced;
        
        atomic64_t events_by_type[LIH_EVENT_TYPE_CUSTOM + 1];
        
        u64 start_time;
        u64 last_cleanup;
    } stats;
    
    /* Debug */
    struct dentry *debugfs_root;
    struct ratelimit_state ratelimit;
};

/* ============================================================================
 * Variáveis globais
 * ============================================================================ */

static struct lih_event_subsystem *lih_event_subsys;
static DEFINE_MUTEX(lih_event_global_lock);

/* ============================================================================
 * Funções auxiliares
 * ============================================================================ */

/* Gera ID único para evento */
static inline u64 lih_event_generate_id(void)
{
    static atomic64_t next_id = ATOMIC64_INIT(1);
    u64 id = atomic64_inc_return(&next_id);
    /* Adiciona timestamp nos bits altos para ordenação */
    return (ktime_get_real_ns() << 16) ^ (id & 0xFFFF);
}

/* Obtém timestamp em nanosegundos */
static inline u64 lih_event_timestamp(void)
{
    return ktime_get_ns();
}

/* Verifica se evento expirou */
static inline bool lih_event_expired(struct lih_event *event)
{
    if (event->deadline == 0)
        return false;
    return lih_event_timestamp() > event->deadline;
}

/* Coalesce eventos (combina eventos similares) */
static bool lih_event_can_coalesce(struct lih_event *existing,
                                    struct lih_event *new)
{
    if (!(existing->flags & LIH_EVENT_FLAG_COALESCE) ||
        !(new->flags & LIH_EVENT_FLAG_COALESCE))
        return false;
    
    if (existing->type != new->type ||
        existing->subtype != new->subtype)
        return false;
    
    /* Verifica janela de coalescência */
    if (new->timestamp - existing->timestamp > LIH_EVENT_COALESCE_WINDOW_NS)
        return false;
    
    /* Coalescência baseada no tipo */
    switch (existing->type) {
    case LIH_EVENT_TYPE_MEMORY:
        return (existing->data.memory.vaddr == new->data.memory.vaddr);
    
    case LIH_EVENT_TYPE_IPC:
        return (existing->data.ipc.port == new->data.ipc.port);
    
    case LIH_EVENT_TYPE_SYNC:
        return (existing->data.sync.lock_addr == new->data.sync.lock_addr);
    
    default:
        return false;
    }
}

/* ============================================================================
 * Gerenciamento de eventos
 * ============================================================================ */

/* Aloca um novo evento */
static struct lih_event *lih_event_alloc(gfp_t gfp)
{
    struct lih_event *event;
    
    event = kmem_cache_alloc(lih_event_subsys->event_cache, gfp);
    if (!event)
        return NULL;
    
    memset(event, 0, sizeof(*event));
    event->id = lih_event_generate_id();
    event->timestamp = lih_event_timestamp();
    event->state = LIH_EVENT_STATE_PENDING;
    atomic_set(&event->refcount, 1);
    init_completion(&event->completion);
    INIT_LIST_HEAD(&event->queue_node);
    INIT_LIST_HEAD(&event->pending_node);
    
    atomic_inc(&lih_event_subsys->events_allocated);
    atomic_inc(&lih_event_subsys->events_in_flight);
    
    return event;
}

/* Libera um evento */
static void lih_event_free(struct lih_event *event)
{
    if (!event)
        return;
    
    if (atomic_dec_and_test(&event->refcount)) {
        atomic_dec(&lih_event_subsys->events_in_flight);
        kmem_cache_free(lih_event_subsys->event_cache, event);
    }
}

/* Adiciona referência ao evento */
static void lih_event_get(struct lih_event *event)
{
    if (event)
        atomic_inc(&event->refcount);
}

/* Remove referência do evento */
static void lih_event_put(struct lih_event *event)
{
    lih_event_free(event);
}

/* Enfileira evento */
static int lih_event_enqueue(struct lih_event_queue *queue,
                              struct lih_event *event)
{
    unsigned long flags;
    int ret = 0;
    
    if (!queue || !event)
        return -EINVAL;
    
    spin_lock_irqsave(&queue->lock, flags);
    
    /* Verifica coalescência */
    if (event->flags & LIH_EVENT_FLAG_COALESCE) {
        struct lih_event *existing, *tmp;
        
        list_for_each_entry_safe(existing, tmp, &queue->events, queue_node) {
            if (lih_event_can_coalesce(existing, event)) {
                /* Coalesce: atualiza evento existente */
                existing->timestamp = event->timestamp;
                existing->data = event->data;
                existing->flags |= LIH_EVENT_FLAG_COALESCE;
                
                atomic64_inc(&lih_event_subsys->stats.total_coalesced);
                ret = 1; /* Coalesced */
                goto out;
            }
        }
    }
    
    /* Adiciona à fila */
    list_add_tail(&event->queue_node, &queue->events);
    atomic_inc(&queue->pending_count);
    queue->total_events++;
    
    /* Atualiza máximo histórico */
    int pending = atomic_read(&queue->pending_count);
    if (pending > atomic_read(&queue->max_pending))
        atomic_set(&queue->max_pending, pending);
    
    /* Acorda waiters */
    wake_up_interruptible(&queue->waitq);
    
    /* Adiciona à hash table */
    spin_lock(&lih_event_subsys->hash_lock);
    hash_add(lih_event_subsys->event_hash, &event->hash_node,
             (unsigned long)event->id);
    spin_unlock(&lih_event_subsys->hash_lock);
    
out:
    spin_unlock_irqrestore(&queue->lock, flags);
    return ret;
}

/* Desenfileira evento */
static struct lih_event *lih_event_dequeue(struct lih_event_queue *queue)
{
    struct lih_event *event = NULL;
    unsigned long flags;
    
    if (!queue)
        return NULL;
    
    spin_lock_irqsave(&queue->lock, flags);
    
    if (!list_empty(&queue->events)) {
        event = list_first_entry(&queue->events, struct lih_event, queue_node);
        list_del(&event->queue_node);
        atomic_dec(&queue->pending_count);
        
        /* Remove da hash table */
        spin_lock(&lih_event_subsys->hash_lock);
        hash_del(&event->hash_node);
        spin_unlock(&lih_event_subsys->hash_lock);
    }
    
    spin_unlock_irqrestore(&queue->lock, flags);
    
    return event;
}

/* Aguarda evento */
static int lih_event_wait(struct lih_event_queue *queue,
                           struct lih_event **event_ptr,
                           long timeout_ms)
{
    struct lih_event *event;
    unsigned long flags;
    long timeout_jiffies;
    int ret = 0;
    
    if (!queue || !event_ptr)
        return -EINVAL;
    
    timeout_jiffies = msecs_to_jiffies(timeout_ms);
    
    spin_lock_irqsave(&queue->lock, flags);
    
    while (list_empty(&queue->events)) {
        spin_unlock_irqrestore(&queue->lock, flags);
        
        ret = wait_event_interruptible_timeout(queue->waitq,
                                                !list_empty(&queue->events),
                                                timeout_jiffies);
        
        if (ret <= 0) {
            if (ret == 0)
                ret = -ETIMEDOUT;
            return ret;
        }
        
        spin_lock_irqsave(&queue->lock, flags);
    }
    
    event = list_first_entry(&queue->events, struct lih_event, queue_node);
    list_del(&event->queue_node);
    atomic_dec(&queue->pending_count);
    
    spin_unlock_irqrestore(&queue->lock, flags);
    
    *event_ptr = event;
    return 0;
}

/* ============================================================================
 * Processamento de eventos
 * ============================================================================ */

/* Processa evento através de handlers registrados */
static int lih_event_process_handlers(struct lih_event *event)
{
    struct lih_event_handler *handler;
    int ret = 0;
    int processed = 0;
    unsigned long flags;
    
    if (!event)
        return -EINVAL;
    
    /* Busca handlers para este tipo de evento */
    spin_lock_irqsave(&lih_event_subsys->handlers_lock, flags);
    
    list_for_each_entry_rcu(handler, &lih_event_subsys->handlers[event->type], list) {
        /* Verifica subtipo (0 = todos) */
        if (handler->subtype != 0 && handler->subtype != event->subtype)
            continue;
        
        /* Aplica filtro se existir */
        if (handler->filter && !handler->filter(event, handler->filter_data))
            continue;
        
        /* Executa handler */
        if (handler->handler) {
            int handler_ret = handler->handler(event, handler->context);
            atomic_inc(&handler->events_processed);
            
            if (handler_ret < 0) {
                atomic_inc(&handler->events_errors);
                if (ret == 0)
                    ret = handler_ret;
            }
            processed++;
        }
    }
    
    spin_unlock_irqrestore(&lih_event_subsys->handlers_lock, flags);
    
    if (processed == 0 && event->type != LIH_EVENT_TYPE_NONE) {
        /* Nenhum handler encontrado */
        if (printk_ratelimit())
            printk(KERN_WARNING "LIH Event: No handler for type %u/%u\n",
                   event->type, event->subtype);
        ret = -ENOENT;
    }
    
    return ret;
}

/* Worker para processamento assíncrono */
static void lih_event_worker(struct work_struct *work)
{
    struct lih_event *event = container_of(work, struct lih_event, pending_node);
    int ret;
    
    ret = lih_event_process_handlers(event);
    
    if (ret < 0) {
        atomic64_inc(&lih_event_subsys->stats.total_errors);
    }
    
    /* Completa evento síncrono */
    if (event->flags & LIH_EVENT_FLAG_SYNC) {
        event->state = LIH_EVENT_STATE_COMPLETED;
        complete(&event->completion);
    }
    
    /* Callback de conclusão */
    if (event->completion_cb) {
        event->completion_cb(event, event->completion_data);
    }
    
    lih_event_put(event);
}

/* Dispara evento (síncrono ou assíncrono) */
int lih_event_fire(struct lih_event *event, int sync)
{
    int ret = 0;
    
    if (!event || !lih_event_subsys)
        return -EINVAL;
    
    atomic64_inc(&lih_event_subsys->stats.total_events);
    atomic64_inc(&lih_event_subsys->stats.events_by_type[event->type]);
    
    if (sync || (event->flags & LIH_EVENT_FLAG_SYNC)) {
        /* Processamento síncrono */
        ret = lih_event_process_handlers(event);
        event->state = LIH_EVENT_STATE_COMPLETED;
    } else {
        /* Processamento assíncrono */
        struct work_struct *work;
        lih_event_get(event);
        
        /* Escolhe workqueue baseado na prioridade */
        if (event->priority <= LIH_EVENT_PRIO_HIGH) {
            work = &event->pending_node;
            INIT_WORK(work, lih_event_worker);
            queue_work(lih_event_subsys->high_prio_wq, work);
        } else {
            work = &event->pending_node;
            INIT_WORK(work, lih_event_worker);
            queue_work(lih_event_subsys->event_wq, work);
        }
    }
    
    return ret;
}
EXPORT_SYMBOL(lih_event_fire);

/* Cria e dispara evento */
int lih_event_emit(u32 type, u32 subtype, u32 priority, u32 flags,
                    void *data, size_t data_len)
{
    struct lih_event *event;
    int ret;
    
    if (!lih_event_subsys)
        return -ENODEV;
    
    event = lih_event_alloc(GFP_ATOMIC);
    if (!event)
        return -ENOMEM;
    
    event->type = type;
    event->subtype = subtype;
    event->priority = priority;
    event->flags = flags;
    
    if (data && data_len && data_len <= sizeof(event->data.custom.data)) {
        memcpy(event->data.custom.data, data, data_len);
        event->data.custom.data_len = data_len;
    }
    
    ret = lih_event_fire(event, flags & LIH_EVENT_FLAG_SYNC);
    lih_event_put(event);
    
    return ret;
}
EXPORT_SYMBOL(lih_event_emit);

/* ============================================================================
 * Eventos específicos do sistema
 * ============================================================================ */

/* Notifica criação de task */
int lih_event_task_create(pid_t pid, pid_t ppid, uid_t uid,
                           const char *comm, unsigned long clone_flags)
{
    struct lih_event *event;
    
    event = lih_event_alloc(GFP_KERNEL);
    if (!event)
        return -ENOMEM;
    
    event->type = LIH_EVENT_TYPE_SYSTEM;
    event->subtype = LIH_EVENT_SUBTYPE_TASK_CREATE;
    event->priority = LIH_EVENT_PRIO_NORMAL;
    event->flags = LIH_EVENT_FLAG_ASYNC;
    
    event->data.task.pid = pid;
    event->data.task.ppid = ppid;
    event->data.task.uid = uid;
    strscpy(event->data.task.comm, comm, sizeof(event->data.task.comm));
    event->data.task.clone_flags = clone_flags;
    
    return lih_event_fire(event, 0);
}
EXPORT_SYMBOL(lih_event_task_create);

/* Notifica page fault */
int lih_event_page_fault(pid_t pid, unsigned long vaddr,
                          unsigned long pc, int fault_type)
{
    struct lih_event *event;
    
    event = lih_event_alloc(GFP_ATOMIC);
    if (!event)
        return -ENOMEM;
    
    event->type = LIH_EVENT_TYPE_MEMORY;
    event->subtype = LIH_EVENT_SUBTYPE_PAGE_FAULT;
    event->priority = LIH_EVENT_PRIO_HIGH;
    event->flags = LIH_EVENT_FLAG_ASYNC | LIH_EVENT_FLAG_COALESCE;
    
    event->data.memory.vaddr = vaddr;
    event->data.memory.fault_type = fault_type;
    event->source_pid = pid;
    
    return lih_event_fire(event, 0);
}
EXPORT_SYMBOL(lih_event_page_fault);

/* Notifica mensagem IPC */
int lih_event_ipc_message(mach_port_t port, mach_msg_id_t msg_id,
                           size_t msg_size, int direction)
{
    struct lih_event *event;
    u32 subtype;
    
    event = lih_event_alloc(GFP_ATOMIC);
    if (!event)
        return -ENOMEM;
    
    subtype = (direction == 0) ? LIH_EVENT_SUBTYPE_MSG_SEND :
                                  LIH_EVENT_SUBTYPE_MSG_RECV;
    
    event->type = LIH_EVENT_TYPE_IPC;
    event->subtype = subtype;
    event->priority = LIH_EVENT_PRIO_NORMAL;
    event->flags = LIH_EVENT_FLAG_ASYNC | LIH_EVENT_FLAG_COALESCE;
    
    event->data.ipc.port = port;
    event->data.ipc.msg_id = msg_id;
    event->data.ipc.msg_size = msg_size;
    
    return lih_event_fire(event, 0);
}
EXPORT_SYMBOL(lih_event_ipc_message);

/* Notifica evento de lock */
int lih_event_lock_acquire(void *lock_addr, int lock_type, u64 wait_time_ns)
{
    struct lih_event *event;
    
    event = lih_event_alloc(GFP_ATOMIC);
    if (!event)
        return -ENOMEM;
    
    event->type = LIH_EVENT_TYPE_SYNC;
    event->subtype = LIH_EVENT_SUBTYPE_LOCK_ACQUIRE;
    event->priority = LIH_EVENT_PRIO_NORMAL;
    event->flags = LIH_EVENT_FLAG_ASYNC;
    
    event->data.sync.lock_addr = lock_addr;
    event->data.sync.lock_type = lock_type;
    event->data.sync.wait_time_ns = wait_time_ns;
    
    return lih_event_fire(event, 0);
}
EXPORT_SYMBOL(lih_event_lock_acquire);

/* ============================================================================
 * Gerenciamento de handlers
 * ============================================================================ */

/* Registra handler de evento */
int lih_event_register_handler(u32 type, u32 subtype,
                                int (*handler)(struct lih_event *, void *),
                                void *context)
{
    struct lih_event_handler *h;
    unsigned long flags;
    
    if (!lih_event_subsys || !handler)
        return -EINVAL;
    
    if (type > LIH_EVENT_TYPE_CUSTOM)
        return -EINVAL;
    
    h = kzalloc(sizeof(*h), GFP_KERNEL);
    if (!h)
        return -ENOMEM;
    
    h->type = type;
    h->subtype = subtype;
    h->handler = handler;
    h->context = context;
    atomic_set(&h->events_processed, 0);
    atomic_set(&h->events_filtered, 0);
    atomic_set(&h->events_errors, 0);
    
    spin_lock_irqsave(&lih_event_subsys->handlers_lock, flags);
    list_add_rcu(&h->list, &lih_event_subsys->handlers[type]);
    spin_unlock_irqrestore(&lih_event_subsys->handlers_lock, flags);
    
    return 0;
}
EXPORT_SYMBOL(lih_event_register_handler);

/* Remove handler de evento */
int lih_event_unregister_handler(u32 type, u32 subtype,
                                  int (*handler)(struct lih_event *, void *))
{
    struct lih_event_handler *h;
    unsigned long flags;
    int found = 0;
    
    if (!lih_event_subsys || !handler)
        return -EINVAL;
    
    spin_lock_irqsave(&lih_event_subsys->handlers_lock, flags);
    list_for_each_entry_rcu(h, &lih_event_subsys->handlers[type], list) {
        if (h->handler == handler && h->subtype == subtype) {
            list_del_rcu(&h->list);
            found = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&lih_event_subsys->handlers_lock, flags);
    
    if (found) {
        synchronize_rcu();
        kfree(h);
        return 0;
    }
    
    return -ENOENT;
}
EXPORT_SYMBOL(lih_event_unregister_handler);

/* ============================================================================
 * Interface com usuário (eventfd)
 * ============================================================================ */

/* File operations para evento de usuário */
static ssize_t lih_event_read(struct file *file, char __user *buf,
                               size_t count, loff_t *pos)
{
    struct lih_event_queue *queue = file->private_data;
    struct lih_event *event;
    int ret;
    
    if (!queue)
        return -EINVAL;
    
    event = lih_event_dequeue(queue);
    if (!event) {
        /* Aguarda evento */
        ret = lih_event_wait(queue, &event,
                              LIH_EVENT_DEFAULT_TIMEOUT_MS);
        if (ret < 0)
            return ret;
    }
    
    if (count < sizeof(event->id))
        return -EINVAL;
    
    /* Copia ID do evento para usuário */
    if (copy_to_user(buf, &event->id, sizeof(event->id))) {
        ret = -EFAULT;
    } else {
        ret = sizeof(event->id);
    }
    
    lih_event_put(event);
    return ret;
}

static unsigned int lih_event_poll(struct file *file, poll_table *wait)
{
    struct lih_event_queue *queue = file->private_data;
    unsigned int mask = 0;
    
    if (!queue)
        return POLLERR;
    
    poll_wait(file, &queue->waitq, wait);
    
    if (atomic_read(&queue->pending_count) > 0)
        mask |= POLLIN | POLLRDNORM;
    
    return mask;
}

static int lih_event_release(struct inode *inode, struct file *file)
{
    struct lih_event_queue *queue = file->private_data;
    struct lih_event *event, *tmp;
    unsigned long flags;
    
    if (!queue)
        return 0;
    
    /* Limpa fila */
    spin_lock_irqsave(&queue->lock, flags);
    list_for_each_entry_safe(event, tmp, &queue->events, queue_node) {
        list_del(&event->queue_node);
        lih_event_put(event);
    }
    spin_unlock_irqrestore(&queue->lock, flags);
    
    kfree(queue);
    return 0;
}

static const struct file_operations lih_event_fops = {
    .owner = THIS_MODULE,
    .read = lih_event_read,
    .poll = lih_event_poll,
    .release = lih_event_release,
};

/* Cria descritor de arquivo para eventos de usuário */
int lih_event_create_fd(u32 flags)
{
    struct lih_event_queue *queue;
    int fd;
    
    queue = kzalloc(sizeof(*queue), GFP_KERNEL);
    if (!queue)
        return -ENOMEM;
    
    queue->id = prandom_u32();
    queue->flags = flags;
    snprintf(queue->name, sizeof(queue->name), "lih-event-%u", queue->id);
    
    INIT_LIST_HEAD(&queue->events);
    spin_lock_init(&queue->lock);
    init_waitqueue_head(&queue->waitq);
    atomic_set(&queue->pending_count, 0);
    atomic_set(&queue->max_pending, 0);
    
    fd = anon_inode_getfd("lih-event", &lih_event_fops, queue, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        kfree(queue);
    
    return fd;
}
EXPORT_SYMBOL(lih_event_create_fd);

/* Envia evento para fila de usuário */
int lih_event_send_to_fd(int fd, u64 event_id)
{
    struct file *file;
    struct lih_event_queue *queue;
    struct lih_event *event;
    int ret = 0;
    
    file = fget(fd);
    if (!file)
        return -EBADF;
    
    if (file->f_op != &lih_event_fops) {
        ret = -EINVAL;
        goto out;
    }
    
    queue = file->private_data;
    if (!queue) {
        ret = -EINVAL;
        goto out;
    }
    
    event = lih_event_alloc(GFP_KERNEL);
    if (!event) {
        ret = -ENOMEM;
        goto out;
    }
    
    event->id = event_id;
    event->type = LIH_EVENT_TYPE_CUSTOM;
    
    ret = lih_event_enqueue(queue, event);
    if (ret < 0)
        lih_event_put(event);
    
out:
    fput(file);
    return ret;
}
EXPORT_SYMBOL(lih_event_send_to_fd);

/* ============================================================================
 * Debug e estatísticas
 * ============================================================================ */

#ifdef CONFIG_DEBUG_FS

static int lih_event_stats_show(struct seq_file *m, void *v)
{
    struct lih_event_subsystem *es = m->private;
    int i;
    
    if (!es)
        return 0;
    
    seq_printf(m, "LIH Event Subsystem Statistics\n");
    seq_printf(m, "==============================\n\n");
    
    seq_printf(m, "Total events:       %llu\n",
               atomic64_read(&es->stats.total_events));
    seq_printf(m, "Total dropped:      %llu\n",
               atomic64_read(&es->stats.total_dropped));
    seq_printf(m, "Total timeouts:     %llu\n",
               atomic64_read(&es->stats.total_timeouts));
    seq_printf(m, "Total errors:       %llu\n",
               atomic64_read(&es->stats.total_errors));
    seq_printf(m, "Total coalesced:    %llu\n",
               atomic64_read(&es->stats.total_coalesced));
    
    seq_printf(m, "\nEvents in flight:   %d\n",
               atomic_read(&es->events_in_flight));
    seq_printf(m, "Events allocated:   %d\n",
               atomic_read(&es->events_allocated));
    
    seq_printf(m, "\nEvents by type:\n");
    for (i = 0; i <= LIH_EVENT_TYPE_CUSTOM; i++) {
        u64 count = atomic64_read(&es->stats.events_by_type[i]);
        if (count > 0) {
            seq_printf(m, "  Type %04x:        %llu\n", i, count);
        }
    }
    
    return 0;
}

static int lih_event_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, lih_event_stats_show, inode->i_private);
}

static const struct file_operations lih_event_stats_fops = {
    .open = lih_event_stats_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

#endif /* CONFIG_DEBUG_FS */

/* ============================================================================
 * Inicialização e finalização
 * ============================================================================ */

static int __init lih_event_init(void)
{
    int ret = 0;
    int i;
    
    printk(KERN_INFO "LIH Event Subsystem initializing...\n");
    
    /* Aloca subsistema */
    lih_event_subsys = kzalloc(sizeof(*lih_event_subsys), GFP_KERNEL);
    if (!lih_event_subsys)
        return -ENOMEM;
    
    /* Inicializa filas */
    lih_event_subsys->system_queue = kzalloc(sizeof(struct lih_event_queue),
                                              GFP_KERNEL);
    if (!lih_event_subsys->system_queue) {
        ret = -ENOMEM;
        goto out_free;
    }
    
    lih_event_subsys->user_queue = kzalloc(sizeof(struct lih_event_queue),
                                            GFP_KERNEL);
    if (!lih_event_subsys->user_queue) {
        ret = -ENOMEM;
        goto out_free_system;
    }
    
    lih_event_subsys->monitor_queue = kzalloc(sizeof(struct lih_event_queue),
                                               GFP_KERNEL);
    if (!lih_event_subsys->monitor_queue) {
        ret = -ENOMEM;
        goto out_free_user;
    }
    
    /* Inicializa filas do sistema */
    lih_event_subsys->system_queue->id = 1;
    strcpy(lih_event_subsys->system_queue->name, "system");
    INIT_LIST_HEAD(&lih_event_subsys->system_queue->events);
    spin_lock_init(&lih_event_subsys->system_queue->lock);
    init_waitqueue_head(&lih_event_subsys->system_queue->waitq);
    
    lih_event_subsys->user_queue->id = 2;
    strcpy(lih_event_subsys->user_queue->name, "user");
    INIT_LIST_HEAD(&lih_event_subsys->user_queue->events);
    spin_lock_init(&lih_event_subsys->user_queue->lock);
    init_waitqueue_head(&lih_event_subsys->user_queue->waitq);
    
    lih_event_subsys->monitor_queue->id = 3;
    strcpy(lih_event_subsys->monitor_queue->name, "monitor");
    INIT_LIST_HEAD(&lih_event_subsys->monitor_queue->events);
    spin_lock_init(&lih_event_subsys->monitor_queue->lock);
    init_waitqueue_head(&lih_event_subsys->monitor_queue->waitq);
    
    /* Inicializa handlers */
    for (i = 0; i <= LIH_EVENT_TYPE_CUSTOM; i++)
        INIT_LIST_HEAD(&lih_event_subsys->handlers[i]);
    spin_lock_init(&lih_event_subsys->handlers_lock);
    
    /* Inicializa hash table */
    hash_init(lih_event_subsys->event_hash);
    spin_lock_init(&lih_event_subsys->hash_lock);
    
    /* Cria cache de eventos */
    lih_event_subsys->event_cache = kmem_cache_create("lih_event",
                                                       sizeof(struct lih_event),
                                                       __alignof__(struct lih_event),
                                                       SLAB_PANIC | SLAB_ACCOUNT,
                                                       NULL);
    if (!lih_event_subsys->event_cache) {
        ret = -ENOMEM;
        goto out_free_monitor;
    }
    
    /* Cria workqueues */
    lih_event_subsys->event_wq = alloc_workqueue("lih_event_wq",
                                                  WQ_UNBOUND | WQ_MEM_RECLAIM,
                                                  LIH_EVENT_WQ_MAX_ACTIVE);
    if (!lih_event_subsys->event_wq) {
        ret = -ENOMEM;
        goto out_free_cache;
    }
    
    lih_event_subsys->high_prio_wq = alloc_workqueue("lih_event_high_wq",
                                                      WQ_UNBOUND | WQ_HIGHPRI,
                                                      LIH_EVENT_WQ_MAX_ACTIVE / 2);
    if (!lih_event_subsys->high_prio_wq) {
        ret = -ENOMEM;
        goto out_free_wq;
    }
    
    /* Inicializa estatísticas */
    atomic64_set(&lih_event_subsys->stats.total_events, 0);
    atomic64_set(&lih_event_subsys->stats.total_dropped, 0);
    atomic64_set(&lih_event_subsys->stats.total_timeouts, 0);
    atomic64_set(&lih_event_subsys->stats.total_errors, 0);
    atomic64_set(&lih_event_subsys->stats.total_coalesced, 0);
    for (i = 0; i <= LIH_EVENT_TYPE_CUSTOM; i++)
        atomic64_set(&lih_event_subsys->stats.events_by_type[i], 0);
    
    lih_event_subsys->stats.start_time = ktime_get_real_ns();
    lih_event_subsys->state = 1;
    
    /* Ratelimit para logs */
    ratelimit_state_init(&lih_event_subsys->ratelimit, 5 * HZ, 10);
    ratelimit_set_flags(&lih_event_subsys->ratelimit, RATELIMIT_MSG_ON_RELEASE);
    
#ifdef CONFIG_DEBUG_FS
    /* Cria debugfs */
    lih_event_subsys->debugfs_root = debugfs_create_dir("lih_event", NULL);
    if (!IS_ERR(lih_event_subsys->debugfs_root)) {
        debugfs_create_file("stats", 0444, lih_event_subsys->debugfs_root,
                            lih_event_subsys, &lih_event_stats_fops);
        debugfs_create_u32("state", 0444, lih_event_subsys->debugfs_root,
                           (u32 *)&lih_event_subsys->state);
    }
#endif
    
    printk(KERN_INFO "LIH Event Subsystem initialized\n");
    printk(KERN_INFO "  - Event cache size: %zu bytes\n",
           sizeof(struct lih_event));
    printk(KERN_INFO "  - Queue size: %d events\n", LIH_EVENT_QUEUE_SIZE);
    printk(KERN_INFO "  - Workqueues: %s, %s\n", "lih_event_wq", "lih_event_high_wq");
    
    return 0;

out_free_wq:
    destroy_workqueue(lih_event_subsys->event_wq);
out_free_cache:
    kmem_cache_destroy(lih_event_subsys->event_cache);
out_free_monitor:
    kfree(lih_event_subsys->monitor_queue);
out_free_user:
    kfree(lih_event_subsys->user_queue);
out_free_system:
    kfree(lih_event_subsys->system_queue);
out_free:
    kfree(lih_event_subsys);
    lih_event_subsys = NULL;
    
    return ret;
}

static void __exit lih_event_exit(void)
{
    if (!lih_event_subsys)
        return;
    
    printk(KERN_INFO "LIH Event Subsystem shutting down...\n");
    
    lih_event_subsys->state = 0;
    
    /* Limpa filas */
    flush_workqueue(lih_event_subsys->event_wq);
    flush_workqueue(lih_event_subsys->high_prio_wq);
    
    /* Destroi workqueues */
    destroy_workqueue(lih_event_subsys->event_wq);
    destroy_workqueue(lih_event_subsys->high_prio_wq);
    
    /* Destroi cache */
    kmem_cache_destroy(lih_event_subsys->event_cache);
    
    /* Libera filas */
    kfree(lih_event_subsys->system_queue);
    kfree(lih_event_subsys->user_queue);
    kfree(lih_event_subsys->monitor_queue);
    
#ifdef CONFIG_DEBUG_FS
    debugfs_remove_recursive(lih_event_subsys->debugfs_root);
#endif
    
    kfree(lih_event_subsys);
    lih_event_subsys = NULL;
    
    printk(KERN_INFO "LIH Event Subsystem shut down\n");
}

module_init(lih_event_init);
module_exit(lih_event_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LIH Project");
MODULE_DESCRIPTION("LIH Event Subsystem - Async event handling for Linux+Mach");
MODULE_VERSION("1.0");
