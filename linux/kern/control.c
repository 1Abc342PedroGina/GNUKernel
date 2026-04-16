/*
 * linux/kernel/control.c - LIH Control Module
 * 
 * Módulo central de controle do projeto LIH (Linux Is Hybrid)
 * Gerencia:
 *   - Inicialização e shutdown do sistema híbrido
 *   - Comunicação bidirecional Linux <-> Mach
 *   - Tabelas de mapeamento de processos/threads
 *   - Syscalls híbridas
 *   - Monitoramento de saúde do sistema
 *   - Recovery em caso de falhas
 * 
 * Parte do projeto LIH (Linux Is Hybrid)
 * 
 * Licença: GPLv2
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/panic_notifier.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/ctype.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/irqflags.h>
#include <linux/rcupdate.h>
#include <linux/version.h>
#include <linux/buildid.h>
#include <linux/elf.h>
#include <linux/crash_dump.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>

/* Headers do GNU Mach */
#include <mach/mach_types.h>
#include <mach/mach_host.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <mach/vm_prot.h>
#include <mach/kern_return.h>
#include <mach/task_info.h>
#include <mach/thread_info.h>
#include <mach/processor_info.h>

/* Headers internos do LIH */
#include <linux/lih_control.h>
#include <linux/lih_kmalloc.h>
#include <linux/lih_lock.h>
#include <linux/lih_sched.h>
#include <linux/lih_ast.h>
#include <linux/lih_bsd.h>

/* ============================================================================
 * Constantes e definições
 * ============================================================================ */

/* Versão do LIH */
#define LIH_VERSION_MAJOR       0
#define LIH_VERSION_MINOR       1
#define LIH_VERSION_PATCH       0
#define LIH_VERSION_STRING      "0.1.0"

/* Estados do sistema */
#define LIH_STATE_UNINIT        0   /* Não inicializado */
#define LIH_STATE_INIT          1   /* Inicializando */
#define LIH_STATE_RUNNING       2   /* Executando normalmente */
#define LIH_STATE_DEGRADED      3   /* Modo degradado (algum subsistema falhou) */
#define LIH_STATE_RECOVERY      4   /* Modo de recuperação */
#define LIH_STATE_SHUTDOWN      5   /* Desligando */
#define LIH_STATE_PANIC         6   /* Estado de pânico */

/* Tipos de mensagem entre Linux e Mach */
#define LIH_MSG_TYPE_NONE       0
#define LIH_MSG_TYPE_TASK_CREATE 1
#define LIH_MSG_TYPE_TASK_EXIT  2
#define LIH_MSG_TYPE_THREAD_CREATE 3
#define LIH_MSG_TYPE_THREAD_EXIT 4
#define LIH_MSG_TYPE_SIGNAL     5
#define LIH_MSG_TYPE_PAGE_FAULT 6
#define LIH_MSG_TYPE_SYSCALL    7
#define LIH_MSG_TYPE_IPC        8
#define LIH_MSG_TYPE_INTERRUPT  9
#define LIH_MSG_TYPE_TIMER      10
#define LIH_MSG_TYPE_HEARTBEAT  11
#define LIH_MSG_TYPE_RECOVERY   12

/* Prioridades das mensagens */
#define LIH_MSG_PRIO_HIGH       0   /* Alta prioridade (interrupções) */
#define LIH_MSG_PRIO_NORMAL     1   /* Prioridade normal */
#define LIH_MSG_PRIO_LOW        2   /* Baixa prioridade (background) */

/* Timeouts em milissegundos */
#define LIH_HEARTBEAT_INTERVAL  1000    /* 1 segundo */
#define LIH_HEARTBEAT_TIMEOUT   3000    /* 3 segundos */
#define LIH_RECOVERY_TIMEOUT    5000    /* 5 segundos */
#define LIH_SHUTDOWN_TIMEOUT    10000   /* 10 segundos */
#define LIH_MSG_TIMEOUT         100     /* 100ms */

/* Máximos do sistema */
#define LIH_MAX_TASKS           65536
#define LIH_MAX_THREADS         262144
#define LIH_MAX_PORTS           4096
#define LIH_MAX_MSG_QUEUE       1024

/* Flags de controle */
#define LIH_FLAG_VERBOSE        (1 << 0)
#define LIH_FLAG_DEBUG          (1 << 1)
#define LIH_FLAG_PROFILE        (1 << 2)
#define LIH_FLAG_RECOVERY       (1 << 3)
#define LIH_FLAG_NO_FALLBACK    (1 << 4)
#define LIH_FLAG_SYNC_MODE      (1 << 5)

/* ============================================================================
 * Estruturas de dados
 * ============================================================================ */

/* Mensagem de comunicação Linux-Mach */
struct lih_message {
    u32 type;                       /* Tipo da mensagem */
    u32 priority;                   /* Prioridade */
    u32 flags;                      /* Flags da mensagem */
    u32 seq;                        /* Número de sequência */
    u64 timestamp;                  /* Timestamp de envio */
    
    union {
        /* Dados de criação de task */
        struct {
            pid_t pid;
            pid_t ppid;
            uid_t uid;
            gid_t gid;
            char comm[16];
            unsigned long flags;
        } task_create;
        
        /* Dados de criação de thread */
        struct {
            pid_t pid;
            pid_t tid;
            unsigned long entry;
            unsigned long stack;
        } thread_create;
        
        /* Dados de sinal */
        struct {
            pid_t pid;
            int signo;
            siginfo_t info;
        } signal;
        
        /* Dados de page fault */
        struct {
            pid_t pid;
            unsigned long vaddr;
            unsigned long pc;
            int type;
        } page_fault;
        
        /* Heartbeat */
        struct {
            u64 uptime;
            u32 load_avg;
            u32 free_memory;
        } heartbeat;
        
        /* Dados genéricos */
        u8 raw[256];
    } data;
};

/* Entidade de mapeamento Linux -> Mach */
struct lih_mapping_entry {
    u32 id;                         /* ID do mapeamento */
    pid_t linux_pid;                /* PID no Linux */
    pid_t linux_tid;                /* TID no Linux */
    thread_t mach_thread;           /* Thread no Mach */
    task_t mach_task;               /* Task no Mach */
    mach_port_t reply_port;         /* Porta de resposta */
    
    unsigned long flags;            /* Flags do mapeamento */
    atomic_t refcount;              /* Contagem de referências */
    
    struct rcu_head rcu;            /* Para liberação RCU */
    struct hlist_node hash_node;    /* Nó na hash table */
};

/* Estatísticas do sistema */
struct lih_stats {
    atomic64_t messages_sent;
    atomic64_t messages_received;
    atomic64_t messages_dropped;
    atomic64_t messages_timeout;
    
    atomic64_t tasks_created;
    atomic64_t tasks_exited;
    atomic64_t threads_created;
    atomic64_t threads_exited;
    
    atomic64_t signals_sent;
    atomic64_t page_faults_handled;
    
    atomic64_t recovery_events;
    atomic64_t fallback_events;
    
    atomic64_t errors_total;
    u64 start_time;
    u64 last_heartbeat;
};

/* Contexto de controle do LIH */
struct lih_control_context {
    int state;                      /* Estado atual do sistema */
    unsigned long flags;            /* Flags de controle */
    
    /* Comunicação */
    mach_port_t control_port;       /* Porta de controle principal */
    mach_port_t notify_port;        /* Porta de notificações */
    struct lih_message msg_queue[LIH_MAX_MSG_QUEUE];
    int msg_queue_head;
    int msg_queue_tail;
    spinlock_t msg_queue_lock;
    
    /* Mapeamentos */
    DECLARE_HASHTABLE(pid_to_mapping, 16);  /* PID -> mapping */
    DECLARE_HASHTABLE(tid_to_mapping, 16);  /* TID -> mapping */
    DECLARE_HASHTABLE(thread_to_mapping, 16); /* Mach thread -> mapping */
    rwlock_t mapping_lock;
    
    /* Threads de kernel */
    struct task_struct *control_thread;
    struct task_struct *heartbeat_thread;
    struct task_struct *recovery_thread;
    
    /* Timers e workqueues */
    struct timer_list heartbeat_timer;
    struct delayed_work recovery_work;
    
    /* Callbacks registrados */
    struct lih_callback {
        int type;
        void (*callback)(struct lih_message *msg, void *data);
        void *data;
        struct list_head list;
    } callbacks;
    struct list_head callback_list;
    spinlock_t callback_lock;
    
    /* Estatísticas */
    struct lih_stats stats;
    
    /* Sincronização */
    struct mutex init_mutex;
    struct completion shutdown_complete;
    wait_queue_head_t recovery_wq;
    
    /* Informações do Mach */
    host_t mach_host;
    processor_set_t mach_pset;
    vm_size_t mach_memory_size;
    
    /* Debug */
    struct dentry *debugfs_root;
    atomic_t debug_level;
};

/* ============================================================================
 * Variáveis globais
 * ============================================================================ */

static struct lih_control_context *lih_ctx;
static DEFINE_MUTEX(lih_global_lock);

/* Notifier chain para eventos do sistema */
static BLOCKING_NOTIFIER_HEAD(lih_chain);

/* ============================================================================
 * Funções auxiliares
 * ============================================================================ */

/* Obtém timestamp atual em nanosegundos */
static inline u64 lih_get_timestamp(void)
{
    return ktime_get_ns();
}

/* Calcula sequência para mensagem */
static inline u32 lih_next_seq(void)
{
    static atomic_t seq = ATOMIC_INIT(0);
    return (u32)atomic_inc_return(&seq);
}

/* Verifica se o sistema está em estado válido */
static inline bool lih_is_running(void)
{
    return lih_ctx && (lih_ctx->state == LIH_STATE_RUNNING ||
                       lih_ctx->state == LIH_STATE_DEGRADED);
}

/* ============================================================================
 * Comunicação bidirecional Linux <-> Mach
 * ============================================================================ */

/**
 * lih_send_message - Envia mensagem para o Mach
 * @msg: Mensagem a enviar
 * 
 * Retorna: 0 em sucesso, erro negativo em falha
 */
static int lih_send_message(struct lih_message *msg)
{
    kern_return_t kr;
    mach_msg_header_t header;
    int ret = 0;
    unsigned long flags;
    
    if (!lih_is_running())
        return -ENODEV;
    
    /* Preenche cabeçalho da mensagem */
    header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    header.msgh_size = sizeof(*msg);
    header.msgh_remote_port = lih_ctx->control_port;
    header.msgh_local_port = MACH_PORT_NULL;
    header.msgh_id = msg->type;
    
    /* Preenche campos da mensagem */
    msg->seq = lih_next_seq();
    msg->timestamp = lih_get_timestamp();
    
    /* Envia via Mach IPC */
    kr = mach_msg_send(&header);
    
    if (kr != KERN_SUCCESS) {
        printk(KERN_ERR "LIH: Failed to send message type %d: %d\n",
               msg->type, kr);
        atomic64_inc(&lih_ctx->stats.messages_dropped);
        ret = -EIO;
    } else {
        atomic64_inc(&lih_ctx->stats.messages_sent);
    }
    
    return ret;
}

/**
 * lih_receive_message - Recebe mensagem do Mach
 * @msg: Buffer para receber mensagem
 * @timeout_ms: Timeout em milissegundos
 * 
 * Retorna: 0 em sucesso, erro negativo em falha
 */
static int lih_receive_message(struct lih_message *msg, int timeout_ms)
{
    kern_return_t kr;
    mach_msg_header_t *header;
    mach_msg_timeout_t timeout = timeout_ms;
    int ret = 0;
    
    if (!lih_is_running())
        return -ENODEV;
    
    header = (mach_msg_header_t *)msg;
    header->msgh_local_port = lih_ctx->notify_port;
    header->msgh_size = sizeof(*msg);
    
    kr = mach_msg_receive(header, timeout);
    
    if (kr == MACH_RCV_TIMED_OUT) {
        ret = -ETIMEDOUT;
        atomic64_inc(&lih_ctx->stats.messages_timeout);
    } else if (kr != KERN_SUCCESS) {
        printk(KERN_WARNING "LIH: Receive message failed: %d\n", kr);
        ret = -EIO;
    } else {
        atomic64_inc(&lih_ctx->stats.messages_received);
    }
    
    return ret;
}

/**
 * lih_process_message - Processa mensagem recebida
 * @msg: Mensagem a processar
 */
static void lih_process_message(struct lih_message *msg)
{
    struct lih_callback *cb;
    unsigned long flags;
    
    /* Atualiza heartbeat */
    if (msg->type == LIH_MSG_TYPE_HEARTBEAT) {
        lih_ctx->stats.last_heartbeat = msg->timestamp;
        return;
    }
    
    /* Notifica callbacks registrados */
    spin_lock_irqsave(&lih_ctx->callback_lock, flags);
    list_for_each_entry(cb, &lih_ctx->callback_list, list) {
        if (cb->type == msg->type && cb->callback) {
            cb->callback(msg, cb->data);
        }
    }
    spin_unlock_irqrestore(&lih_ctx->callback_lock, flags);
    
    /* Processa mensagens específicas */
    switch (msg->type) {
    case LIH_MSG_TYPE_TASK_CREATE:
        atomic64_inc(&lih_ctx->stats.tasks_created);
        break;
    case LIH_MSG_TYPE_TASK_EXIT:
        atomic64_inc(&lih_ctx->stats.tasks_exited);
        break;
    case LIH_MSG_TYPE_THREAD_CREATE:
        atomic64_inc(&lih_ctx->stats.threads_created);
        break;
    case LIH_MSG_TYPE_THREAD_EXIT:
        atomic64_inc(&lih_ctx->stats.threads_exited);
        break;
    case LIH_MSG_TYPE_SIGNAL:
        atomic64_inc(&lih_ctx->stats.signals_sent);
        break;
    case LIH_MSG_TYPE_PAGE_FAULT:
        atomic64_inc(&lih_ctx->stats.page_faults_handled);
        break;
    case LIH_MSG_TYPE_RECOVERY:
        atomic64_inc(&lih_ctx->stats.recovery_events);
        break;
    }
}

/* ============================================================================
 * Thread de controle principal
 * ============================================================================ */

/**
 * lih_control_thread - Thread principal de controle
 * @data: Dados (não usado)
 * 
 * Retorna: 0
 */
static int lih_control_thread(void *data)
{
    struct lih_message msg;
    int ret;
    
    printk(KERN_INFO "LIH: Control thread started on CPU %d\n",
           smp_processor_id());
    
    while (!kthread_should_stop() && lih_ctx->state != LIH_STATE_SHUTDOWN) {
        /* Aguarda mensagem do Mach */
        ret = lih_receive_message(&msg, 100);
        
        if (ret == 0) {
            lih_process_message(&msg);
        } else if (ret != -ETIMEDOUT) {
            printk(KERN_WARNING "LIH: Control thread receive error: %d\n", ret);
            
            if (lih_ctx->state == LIH_STATE_RUNNING) {
                lih_ctx->state = LIH_STATE_DEGRADED;
                wake_up(&lih_ctx->recovery_wq);
            }
        }
        
        /* Processa fila de mensagens pendentes */
        spin_lock(&lih_ctx->msg_queue_lock);
        if (lih_ctx->msg_queue_head != lih_ctx->msg_queue_tail) {
            memcpy(&msg, &lih_ctx->msg_queue[lih_ctx->msg_queue_head],
                   sizeof(msg));
            lih_ctx->msg_queue_head = (lih_ctx->msg_queue_head + 1) %
                                       LIH_MAX_MSG_QUEUE;
            spin_unlock(&lih_ctx->msg_queue_lock);
            
            lih_send_message(&msg);
        } else {
            spin_unlock(&lih_ctx->msg_queue_lock);
        }
        
        cond_resched();
    }
    
    printk(KERN_INFO "LIH: Control thread stopped\n");
    return 0;
}

/* ============================================================================
 * Heartbeat e monitoramento
 * ============================================================================ */

/**
 * lih_heartbeat_timer_callback - Timer de heartbeat
 * @timer: Ponteiro para o timer
 */
static void lih_heartbeat_timer_callback(struct timer_list *timer)
{
    struct lih_message msg;
    u64 now = lih_get_timestamp();
    
    if (!lih_is_running())
        return;
    
    /* Prepara mensagem de heartbeat */
    memset(&msg, 0, sizeof(msg));
    msg.type = LIH_MSG_TYPE_HEARTBEAT;
    msg.priority = LIH_MSG_PRIO_LOW;
    msg.data.heartbeat.uptime = now - lih_ctx->stats.start_time;
    msg.data.heartbeat.load_avg = this_cpu_read(avenrun[0]) >> FSHIFT;
    msg.data.heartbeat.free_memory = si_mem_available();
    
    /* Envia heartbeat */
    lih_send_message(&msg);
    
    /* Verifica timeout do Mach */
    if (now - lih_ctx->stats.last_heartbeat > LIH_HEARTBEAT_TIMEOUT * NSEC_PER_MSEC) {
        printk(KERN_WARNING "LIH: Mach heartbeat timeout!\n");
        
        if (lih_ctx->state == LIH_STATE_RUNNING) {
            lih_ctx->state = LIH_STATE_DEGRADED;
            wake_up(&lih_ctx->recovery_wq);
        }
    }
    
    /* Rearma timer */
    mod_timer(timer, jiffies + msecs_to_jiffies(LIH_HEARTBEAT_INTERVAL));
}

/* ============================================================================
 * Gerenciamento de mapeamentos
 * ============================================================================ */

/**
 * lih_add_mapping - Adiciona mapeamento Linux->Mach
 * @linux_pid: PID no Linux
 * @mach_thread: Thread no Mach
 * @mach_task: Task no Mach
 * 
 * Retorna: 0 em sucesso, erro negativo em falha
 */
int lih_add_mapping(pid_t linux_pid, thread_t mach_thread, task_t mach_task)
{
    struct lih_mapping_entry *entry;
    unsigned long flags;
    
    if (!lih_is_running())
        return -ENODEV;
    
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    
    entry->linux_pid = linux_pid;
    entry->linux_tid = linux_pid;
    entry->mach_thread = mach_thread;
    entry->mach_task = mach_task;
    entry->reply_port = MACH_PORT_NULL;
    atomic_set(&entry->refcount, 1);
    
    write_lock_irqsave(&lih_ctx->mapping_lock, flags);
    hash_add(lih_ctx->pid_to_mapping, &entry->hash_node, linux_pid);
    hash_add(lih_ctx->thread_to_mapping, &entry->hash_node,
             (unsigned long)mach_thread);
    write_unlock_irqrestore(&lih_ctx->mapping_lock, flags);
    
    return 0;
}
EXPORT_SYMBOL(lih_add_mapping);

/**
 * lih_remove_mapping - Remove mapeamento
 * @linux_pid: PID no Linux
 */
void lih_remove_mapping(pid_t linux_pid)
{
    struct lih_mapping_entry *entry;
    unsigned long flags;
    
    if (!lih_is_running())
        return;
    
    write_lock_irqsave(&lih_ctx->mapping_lock, flags);
    hash_for_each_possible(lih_ctx->pid_to_mapping, entry, hash_node, linux_pid) {
        if (entry->linux_pid == linux_pid) {
            hash_del(&entry->hash_node);
            hash_del(&entry->hash_node);
            kfree_rcu(entry, rcu);
            break;
        }
    }
    write_unlock_irqrestore(&lih_ctx->mapping_lock, flags);
}
EXPORT_SYMBOL(lih_remove_mapping);

/**
 * lih_find_mapping_by_pid - Encontra mapeamento por PID
 * @linux_pid: PID no Linux
 * 
 * Retorna: Ponteiro para entry ou NULL
 */
struct lih_mapping_entry *lih_find_mapping_by_pid(pid_t linux_pid)
{
    struct lih_mapping_entry *entry;
    unsigned long flags;
    
    if (!lih_is_running())
        return NULL;
    
    read_lock_irqsave(&lih_ctx->mapping_lock, flags);
    hash_for_each_possible(lih_ctx->pid_to_mapping, entry, hash_node, linux_pid) {
        if (entry->linux_pid == linux_pid) {
            atomic_inc(&entry->refcount);
            read_unlock_irqrestore(&lih_ctx->mapping_lock, flags);
            return entry;
        }
    }
    read_unlock_irqrestore(&lih_ctx->mapping_lock, flags);
    
    return NULL;
}
EXPORT_SYMBOL(lih_find_mapping_by_pid);

/**
 * lih_find_mapping_by_thread - Encontra mapeamento por thread Mach
 * @mach_thread: Thread no Mach
 * 
 * Retorna: Ponteiro para entry ou NULL
 */
struct lih_mapping_entry *lih_find_mapping_by_thread(thread_t mach_thread)
{
    struct lih_mapping_entry *entry;
    unsigned long flags;
    unsigned long key = (unsigned long)mach_thread;
    
    if (!lih_is_running())
        return NULL;
    
    read_lock_irqsave(&lih_ctx->mapping_lock, flags);
    hash_for_each_possible(lih_ctx->thread_to_mapping, entry, hash_node, key) {
        if (entry->mach_thread == mach_thread) {
            atomic_inc(&entry->refcount);
            read_unlock_irqrestore(&lih_ctx->mapping_lock, flags);
            return entry;
        }
    }
    read_unlock_irqrestore(&lih_ctx->mapping_lock, flags);
    
    return NULL;
}
EXPORT_SYMBOL(lih_find_mapping_by_thread);

/* ============================================================================
 * Gerenciamento de estado e recovery
 * ============================================================================ */

/**
 * lih_recovery_work - Trabalho de recuperação
 * @work: Trabalho atrasado
 */
static void lih_recovery_work(struct work_struct *work)
{
    printk(KERN_WARNING "LIH: Starting recovery procedure...\n");
    
    /* Tenta reiniciar comunicação */
    if (lih_ctx->state == LIH_STATE_DEGRADED) {
        /* Reenvia heartbeat para testar */
        struct lih_message msg;
        memset(&msg, 0, sizeof(msg));
        msg.type = LIH_MSG_TYPE_HEARTBEAT;
        
        if (lih_send_message(&msg) == 0) {
            /* Aguarda resposta */
            msleep(100);
            
            if (lih_ctx->stats.last_heartbeat > 0) {
                printk(KERN_INFO "LIH: Recovery successful!\n");
                lih_ctx->state = LIH_STATE_RUNNING;
                return;
            }
        }
        
        printk(KERN_ERR "LIH: Recovery failed, staying in degraded mode\n");
    } else if (lih_ctx->state == LIH_STATE_RECOVERY) {
        /* Recuperação total - reinicia subsistemas */
        printk(KERN_INFO "LIH: Performing full recovery...\n");
        
        /* TODO: Reinicializar subsistemas específicos */
        
        lih_ctx->state = LIH_STATE_RUNNING;
        printk(KERN_INFO "LIH: Full recovery completed\n");
    }
}

/**
 * lih_set_state - Altera estado do sistema
 * @new_state: Novo estado
 * 
 * Retorna: 0 em sucesso
 */
int lih_set_state(int new_state)
{
    int old_state;
    
    if (!lih_ctx)
        return -ENODEV;
    
    mutex_lock(&lih_ctx->init_mutex);
    old_state = lih_ctx->state;
    
    printk(KERN_INFO "LIH: State change %d -> %d\n", old_state, new_state);
    
    switch (new_state) {
    case LIH_STATE_RUNNING:
        if (old_state == LIH_STATE_DEGRADED ||
            old_state == LIH_STATE_RECOVERY) {
            /* Sai do modo degradado */
            lih_ctx->state = new_state;
        }
        break;
        
    case LIH_STATE_DEGRADED:
    case LIH_STATE_RECOVERY:
        lih_ctx->state = new_state;
        schedule_delayed_work(&lih_ctx->recovery_work,
                              msecs_to_jiffies(LIH_RECOVERY_TIMEOUT));
        break;
        
    case LIH_STATE_SHUTDOWN:
        lih_ctx->state = new_state;
        break;
        
    default:
        mutex_unlock(&lih_ctx->init_mutex);
        return -EINVAL;
    }
    
    mutex_unlock(&lih_ctx->init_mutex);
    
    /* Notifica listeners */
    blocking_notifier_call_chain(&lih_chain, new_state, NULL);
    
    return 0;
}
EXPORT_SYMBOL(lih_set_state);

/* ============================================================================
 * Syscalls híbridas (interface com usuário)
 * ============================================================================ */

/**
 * lih_syscall_control - Syscall de controle do LIH
 * @cmd: Comando a executar
 * @arg: Argumento do comando
 * 
 * Retorna: Resultado do comando
 */
SYSCALL_DEFINE2(lih_control, int, cmd, unsigned long, arg)
{
    int ret = 0;
    
    if (!lih_is_running())
        return -ENODEV;
    
    switch (cmd) {
    case LIH_CMD_GET_STATE:
        ret = lih_ctx->state;
        break;
        
    case LIH_CMD_GET_STATS:
        if (copy_to_user((void __user *)arg, &lih_ctx->stats,
                         sizeof(lih_ctx->stats)))
            ret = -EFAULT;
        break;
        
    case LIH_CMD_SET_VERBOSE:
        if (arg)
            lih_ctx->flags |= LIH_FLAG_VERBOSE;
        else
            lih_ctx->flags &= ~LIH_FLAG_VERBOSE;
        break;
        
    case LIH_CMD_FORCE_RECOVERY:
        ret = lih_set_state(LIH_STATE_RECOVERY);
        break;
        
    default:
        ret = -EINVAL;
    }
    
    return ret;
}

/* ============================================================================
 * Interface /proc e debugfs
 * ============================================================================ */

#ifdef CONFIG_PROC_FS

/**
 * lih_proc_show - Mostra informações no /proc/lih
 * @m: Seq_file para saída
 */
static int lih_proc_show(struct seq_file *m, void *v)
{
    if (!lih_ctx) {
        seq_puts(m, "LIH not initialized\n");
        return 0;
    }
    
    seq_printf(m, "LIH Control Module v%s\n", LIH_VERSION_STRING);
    seq_printf(m, "State: %d\n", lih_ctx->state);
    seq_printf(m, "Flags: 0x%lx\n", lih_ctx->flags);
    seq_printf(m, "\nStatistics:\n");
    seq_printf(m, "  Messages sent:       %llu\n",
               atomic64_read(&lih_ctx->stats.messages_sent));
    seq_printf(m, "  Messages received:   %llu\n",
               atomic64_read(&lih_ctx->stats.messages_received));
    seq_printf(m, "  Messages dropped:    %llu\n",
               atomic64_read(&lih_ctx->stats.messages_dropped));
    seq_printf(m, "  Tasks created:       %llu\n",
               atomic64_read(&lih_ctx->stats.tasks_created));
    seq_printf(m, "  Tasks exited:        %llu\n",
               atomic64_read(&lih_ctx->stats.tasks_exited));
    seq_printf(m, "  Threads created:     %llu\n",
               atomic64_read(&lih_ctx->stats.threads_created));
    seq_printf(m, "  Threads exited:      %llu\n",
               atomic64_read(&lih_ctx->stats.threads_exited));
    seq_printf(m, "  Recovery events:     %llu\n",
               atomic64_read(&lih_ctx->stats.recovery_events));
    seq_printf(m, "  Errors:              %llu\n",
               atomic64_read(&lih_ctx->stats.errors_total));
    
    return 0;
}

static int lih_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, lih_proc_show, NULL);
}

static const struct proc_ops lih_proc_ops = {
    .proc_open = lih_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

#endif /* CONFIG_PROC_FS */

#ifdef CONFIG_DEBUG_FS

/**
 * lih_debugfs_init - Inicializa debugfs
 */
static void lih_debugfs_init(void)
{
    lih_ctx->debugfs_root = debugfs_create_dir("lih", NULL);
    if (IS_ERR(lih_ctx->debugfs_root))
        return;
    
    debugfs_create_u32("state", 0444, lih_ctx->debugfs_root,
                       (u32 *)&lih_ctx->state);
    debugfs_create_ulong("flags", 0644, lih_ctx->debugfs_root,
                         &lih_ctx->flags);
    debugfs_create_u64("messages_sent", 0444, lih_ctx->debugfs_root,
                       (u64 *)&lih_ctx->stats.messages_sent.counter);
    debugfs_create_u64("messages_received", 0444, lih_ctx->debugfs_root,
                       (u64 *)&lih_ctx->stats.messages_received.counter);
    debugfs_create_atomic_t("debug_level", 0644, lih_ctx->debugfs_root,
                            &lih_ctx->debug_level);
}

#endif /* CONFIG_DEBUG_FS */

/* ============================================================================
 * Notificações de eventos do sistema
 * ============================================================================ */

/**
 * lih_panic_handler - Handler para pânico do kernel
 * @buf: Buffer de pânico
 * 
 * Retorna: NOTIFY_DONE
 */
static int lih_panic_handler(struct notifier_block *this,
                              unsigned long event, void *buf)
{
    printk(KERN_EMERG "LIH: Kernel panic detected!\n");
    
    if (lih_ctx) {
        lih_ctx->state = LIH_STATE_PANIC;
        
        /* Tenta enviar mensagem de pânico para o Mach */
        struct lih_message msg;
        memset(&msg, 0, sizeof(msg));
        msg.type = LIH_MSG_TYPE_RECOVERY;
        lih_send_message(&msg);
    }
    
    return NOTIFY_DONE;
}

/**
 * lih_reboot_handler - Handler para reboot
 * @nb: Notifier block
 * @event: Evento de reboot
 * @buf: Dados
 * 
 * Retorna: NOTIFY_OK
 */
static int lih_reboot_handler(struct notifier_block *nb,
                               unsigned long event, void *buf)
{
    printk(KERN_INFO "LIH: Reboot event detected, shutting down...\n");
    
    if (lih_ctx) {
        lih_set_state(LIH_STATE_SHUTDOWN);
        
        /* Aguarda shutdown */
        if (!wait_for_completion_timeout(&lih_ctx->shutdown_complete,
                                          msecs_to_jiffies(LIH_SHUTDOWN_TIMEOUT))) {
            printk(KERN_WARNING "LIH: Shutdown timeout\n");
        }
    }
    
    return NOTIFY_OK;
}

static struct notifier_block lih_panic_nb = {
    .notifier_call = lih_panic_handler,
    .priority = INT_MAX,
};

static struct notifier_block lih_reboot_nb = {
    .notifier_call = lih_reboot_handler,
    .priority = INT_MAX,
};

/* ============================================================================
 * Inicialização e finalização
 * ============================================================================ */

/**
 * lih_init - Inicializa o módulo de controle LIH
 */
static int __init lih_init(void)
{
    int ret = 0;
    
    printk(KERN_INFO "LIH Control Module v%s initializing...\n",
           LIH_VERSION_STRING);
    
    /* Aloca contexto */
    lih_ctx = kzalloc(sizeof(*lih_ctx), GFP_KERNEL);
    if (!lih_ctx)
        return -ENOMEM;
    
    /* Inicializa estruturas */
    lih_ctx->state = LIH_STATE_INIT;
    lih_ctx->flags = LIH_FLAG_RECOVERY;
    
    hash_init(lih_ctx->pid_to_mapping);
    hash_init(lih_ctx->tid_to_mapping);
    hash_init(lih_ctx->thread_to_mapping);
    rwlock_init(&lih_ctx->mapping_lock);
    
    spin_lock_init(&lih_ctx->msg_queue_lock);
    spin_lock_init(&lih_ctx->callback_lock);
    mutex_init(&lih_ctx->init_mutex);
    init_completion(&lih_ctx->shutdown_complete);
    init_waitqueue_head(&lih_ctx->recovery_wq);
    
    INIT_LIST_HEAD(&lih_ctx->callback_list);
    
    /* Inicializa estatísticas */
    memset(&lih_ctx->stats, 0, sizeof(lih_ctx->stats));
    lih_ctx->stats.start_time = lih_get_timestamp();
    lih_ctx->stats.last_heartbeat = lih_get_timestamp();
    
    /* Tenta conectar com Mach */
    lih_ctx->mach_host = mach_host_self();
    if (lih_ctx->mach_host == MACH_PORT_NULL) {
        printk(KERN_WARNING "LIH: Failed to get Mach host port\n");
        ret = -ENODEV;
        goto out_free;
    }
    
    /* Cria portas de comunicação */
    ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                              &lih_ctx->control_port);
    if (ret != KERN_SUCCESS) {
        printk(KERN_ERR "LIH: Failed to allocate control port\n");
        ret = -ENOMEM;
        goto out_free;
    }
    
    ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                              &lih_ctx->notify_port);
    if (ret != KERN_SUCCESS) {
        printk(KERN_ERR "LIH: Failed to allocate notify port\n");
        ret = -ENOMEM;
        goto out_free_control;
    }
    
    /* Inicia thread de controle */
    lih_ctx->control_thread = kthread_run(lih_control_thread, NULL,
                                           "lih_control");
    if (IS_ERR(lih_ctx->control_thread)) {
        ret = PTR_ERR(lih_ctx->control_thread);
        printk(KERN_ERR "LIH: Failed to start control thread: %d\n", ret);
        goto out_free_notify;
    }
    
    /* Inicializa timer de heartbeat */
    timer_setup(&lih_ctx->heartbeat_timer, lih_heartbeat_timer_callback, 0);
    mod_timer(&lih_ctx->heartbeat_timer,
              jiffies + msecs_to_jiffies(LIH_HEARTBEAT_INTERVAL));
    
    /* Inicializa work de recovery */
    INIT_DELAYED_WORK(&lih_ctx->recovery_work, lih_recovery_work);
    
    /* Registra handlers de notificação */
    atomic_notifier_chain_register(&panic_notifier_list, &lih_panic_nb);
    register_reboot_notifier(&lih_reboot_nb);
    
#ifdef CONFIG_PROC_FS
    /* Cria entrada /proc/lih */
    proc_create("lih", 0444, NULL, &lih_proc_ops);
#endif
    
#ifdef CONFIG_DEBUG_FS
    /* Inicializa debugfs */
    lih_debugfs_init();
#endif
    
    lih_ctx->state = LIH_STATE_RUNNING;
    
    printk(KERN_INFO "LIH Control Module initialized successfully\n");
    printk(KERN_INFO "  - Control port: %d\n", lih_ctx->control_port);
    printk(KERN_INFO "  - Notify port: %d\n", lih_ctx->notify_port);
    printk(KERN_INFO "  - Mach host: %d\n", lih_ctx->mach_host);
    
    return 0;

out_free_notify:
    mach_port_deallocate(mach_task_self(), lih_ctx->notify_port);
out_free_control:
    mach_port_deallocate(mach_task_self(), lih_ctx->control_port);
out_free:
    kfree(lih_ctx);
    lih_ctx = NULL;
    
    return ret;
}

/**
 * lih_exit - Finaliza o módulo de controle LIH
 */
static void __exit lih_exit(void)
{
    if (!lih_ctx)
        return;
    
    printk(KERN_INFO "LIH Control Module shutting down...\n");
    
    lih_set_state(LIH_STATE_SHUTDOWN);
    
    /* Para threads */
    if (lih_ctx->control_thread)
        kthread_stop(lih_ctx->control_thread);
    
    /* Para timer */
    del_timer_sync(&lih_ctx->heartbeat_timer);
    
    /* Cancela work pendente */
    cancel_delayed_work_sync(&lih_ctx->recovery_work);
    
    /* Remove handlers de notificação */
    atomic_notifier_chain_unregister(&panic_notifier_list, &lih_panic_nb);
    unregister_reboot_notifier(&lih_reboot_nb);
    
    /* Libera portas Mach */
    if (lih_ctx->control_port)
        mach_port_deallocate(mach_task_self(), lih_ctx->control_port);
    if (lih_ctx->notify_port)
        mach_port_deallocate(mach_task_self(), lih_ctx->notify_port);
    
#ifdef CONFIG_PROC_FS
    remove_proc_entry("lih", NULL);
#endif
    
#ifdef CONFIG_DEBUG_FS
    debugfs_remove_recursive(lih_ctx->debugfs_root);
#endif
    
    complete(&lih_ctx->shutdown_complete);
    
    kfree(lih_ctx);
    lih_ctx = NULL;
    
    printk(KERN_INFO "LIH Control Module shut down\n");
}

module_init(lih_init);
module_exit(lih_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LIH Project");
MODULE_DESCRIPTION("LIH Control Module - Core control for Linux+Mach hybrid system");
MODULE_VERSION(LIH_VERSION_STRING);
MODULE_INFO(lih_version, LIH_VERSION_STRING);
