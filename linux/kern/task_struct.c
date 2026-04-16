/*
 * linux/kernel/task_struct.c - LIH Task Management Subsystem
 * 
 * Gerencia task_struct com funcionalidades estendidas:
 *   - Ledger (contabilidade financeira de recursos)
 *   - Criação e inicialização de tasks
 *   - Controle de ciclo de vida (start, stop, pause, resume, terminate)
 *   - Checkpoint/Restore de tasks
 *   - Migração entre CPUs/NUMA nodes
 *   - Isolation e containment
 *   - Sandboxing e restrições de segurança
 *   - Audit trail e forensics
 *   - Resource accounting estendido
 * 
 * Integra com GNU Mach para tasks híbridas
 * 
 * Parte do projeto LIH (Linux Is Hybrid)
 * 
 * Licença: GPLv2
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/sched/cputime.h>
#include <linux/sched/mm.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/debug.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/nsproxy.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/cgroup.h>
#include <linux/cgroup_subsys.h>
#include <linux/kcov.h>
#include <linux/io_uring.h>
#include <linux/uprobes.h>
#include <linux/tracehook.h>
#include <linux/freezer.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/stop_machine.h>
#include <linux/reboot.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/rbtree.h>
#include <linux/atomic.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>
#include <linux/time64.h>
#include <linux/random.h>
#include <linux/crc32.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/signalfd.h>
#include <linux/eventfd.h>
#include <linux/userfaultfd.h>
#include <linux/memfd.h>
#include <linux/binfmts.h>
#include <linux/elf.h>
#include <linux/elfcore.h>
#include <linux/coredump.h>
#include <uapi/linux/taskstats.h>

/* Headers do GNU Mach */
#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/thread.h>
#include <mach/vm_map.h>
#include <mach/vm_prot.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <mach/exception.h>

/* ============================================================================
 * Constantes e definições
 * ============================================================================ */

/* Estados estendidos da task */
#define TASK_STATE_CREATED       0x0001   /* Task criada, não iniciada */
#define TASK_STATE_RUNNING       0x0002   /* Task em execução */
#define TASK_STATE_PAUSED        0x0004   /* Task pausada (SIGSTOP) */
#define TASK_STATE_SUSPENDED     0x0008   /* Task suspensa (kernel) */
#define TASK_STATE_FROZEN        0x0010   /* Congelada (hibernate/suspend) */
#define TASK_STATE_MIGRATING     0x0020   /* Em migração entre CPUs */
#define TASK_STATE_CHECKPOINT    0x0040   /* Em checkpoint */
#define TASK_STATE_RESTORING     0x0080   /* Em restore */
#define TASK_STATE_ISOLATED      0x0100   /* Isolada (não interage com outras) */
#define TASK_STATE_SANDBOXED     0x0200   /* Em sandbox */
#define TASK_STATE_TERMINATING   0x0400   /* Em processo de término */
#define TASK_STATE_ZOMBIE        0x0800   /* Zombie (aguardando reaper) */
#define TASK_STATE_DEAD          0x1000   /* Task morta */

/* Flags de ledger */
#define LEDGER_FLAG_CPU          0x0001   /* Contabiliza CPU time */
#define LEDGER_FLAG_MEMORY       0x0002   /* Contabiliza memória */
#define LEDGER_FLAG_IO           0x0004   /* Contabiliza I/O */
#define LEDGER_FLAG_NETWORK      0x0008   /* Contabiliza rede */
#define LEDGER_FLAG_POWER        0x0010   /* Contabiliza energia */
#define LEDGER_FLAG_CHARGED      0x0020   /* Já cobrado (para billing) */
#define LEDGER_FLAG_OVERDRAFT    0x0040   /* Permite overdraft */
#define LEDGER_FLAG_AUDIT        0x0080   /* Audit trail ativo */

/* Tipos de ledger entry */
#define LEDGER_ENTRY_CPU_TIME    0x0001   /* Tempo de CPU */
#define LEDGER_ENTRY_MEMORY_BYTES 0x0002  /* Bytes de memória */
#define LEDGER_ENTRY_IO_BYTES    0x0003   /* Bytes de I/O */
#define LEDGER_ENTRY_IO_OPS      0x0004   /* Operações de I/O */
#define LEDGER_ENTRY_NET_TX      0x0005   /* Bytes transmitidos */
#define LEDGER_ENTRY_NET_RX      0x0006   /* Bytes recebidos */
#define LEDGER_ENTRY_POWER_ENERGY 0x0007  /* Energia (microjoules) */
#define LEDGER_ENTRY_SYSCALLS    0x0008   /* Número de syscalls */
#define LEDGER_ENTRY_PAGE_FAULTS 0x0009   /* Page faults */
#define LEDGER_ENTRY_CONTEXT_SW  0x000A   /* Context switches */
#define LEDGER_ENTRY_CUSTOM      0x8000   /* Entry personalizado */

/* Flags de checkpoint */
#define CHECKPOINT_FLAG_MEMORY   0x0001   /* Salva memória */
#define CHECKPOINT_FLAG_FDS      0x0002   /* Salva file descriptors */
#define CHECKPOINT_FLAG_SIGNALS  0x0004   /* Salva estado de sinais */
#define CHECKPOINT_FLAG_TIMERS   0x0008   /* Salva timers */
#define CHECKPOINT_FLAG_CRED     0x0010   /* Salva credenciais */
#define CHECKPOINT_FLAG_NS       0x0020   /* Salva namespaces */
#define CHECKPOINT_FLAG_SECCOMP  0x0040   /* Salva seccomp state */
#define CHECKPOINT_FLAG_FULL     0xFFFF   /* Salva tudo */

/* Flags de sandbox */
#define SANDBOX_FLAG_NO_NETWORK  0x0001   /* Sem acesso à rede */
#define SANDBOX_FLAG_NO_FILESYSTEM 0x0002 /* Sem acesso a filesystem */
#define SANDBOX_FLAG_READONLY_FS 0x0004   /* FS somente leitura */
#define SANDBOX_FLAG_NO_PROC     0x0008   /* Sem acesso a /proc */
#define SANDBOX_FLAG_NO_SYSLOG   0x0010   /* Sem acesso a syslog */
#define SANDBOX_FLAG_NO_PTRACE   0x0020   /* Sem ptrace */
#define SANDBOX_FLAG_NO_EXEC     0x0040   /* Não pode executar novos bins */
#define SANDBOX_FLAG_SECCOMP     0x0080   /* Usa seccomp-bpf */
#define SANDBOX_FLAG_LANDLOCK    0x0100   /* Usa Landlock */
#define SANDBOX_FLAG_APPARMOR    0x0200   /* Usa AppArmor */

/* Flags de isolamento */
#define ISOLATION_FLAG_CPU       0x0001   /* Isolamento de CPU */
#define ISOLATION_FLAG_CACHE     0x0002   /* Isolamento de cache */
#define ISOLATION_FLAG_MEMORY    0x0004   /* Isolamento de memória */
#define ISOLATION_FLAG_IO        0x0008   /* Isolamento de I/O */
#define ISOLATION_FLAG_NETWORK   0x0010   /* Isolamento de rede */

/* Timeouts e limites */
#define TASK_STOP_TIMEOUT_MS     5000     /* 5 segundos para stop */
#define TASK_TERMINATE_TIMEOUT_MS 10000   /* 10 segundos para terminate */
#define TASK_CHECKPOINT_TIMEOUT_MS 30000  /* 30 segundos para checkpoint */
#define TASK_MIGRATION_TIMEOUT_MS 2000    /* 2 segundos para migração */

/* Máximos */
#define MAX_LEDGER_ENTRIES       1024     /* Máximo entries por ledger */
#define MAX_CHECKPOINT_IMAGES    64       /* Máximo imagens de checkpoint */
#define MAX_TASK_NAMESPACES      16       /* Máximo namespaces por task */

/* ============================================================================
 * Estruturas de dados
 * ============================================================================ */

/* Ledger entry - registro contábil */
struct ledger_entry {
    u64 id;                         /* ID único */
    u32 type;                       /* LEDGER_ENTRY_* */
    u64 amount;                     /* Quantidade (unidades dependem do tipo) */
    u64 timestamp;                  /* Timestamp da transação */
    u64 balance;                    /* Saldo após transação */
    
    /* Contexto */
    pid_t pid;                      /* PID da task */
    uid_t uid;                      /* UID do usuário */
    u32 cpu;                        /* CPU onde ocorreu */
    
    /* Metadata */
    u32 flags;                      /* Flags da entrada */
    char description[128];          /* Descrição textual */
    
    /* Hash para verificação de integridade */
    u64 hash;                       /* Hash criptográfico */
    
    struct list_head list;
    struct rcu_head rcu;
};

/* Ledger - contabilidade financeira de recursos */
struct task_ledger {
    u64 id;                         /* ID do ledger */
    char name[64];                  /* Nome do ledger */
    u32 flags;                      /* LEDGER_FLAG_* */
    
    /* Saldos por tipo */
    u64 cpu_balance;                /* Saldo de CPU time (ns) */
    u64 cpu_credit_limit;           /* Limite de crédito CPU */
    u64 memory_balance;             /* Saldo de memória (bytes) */
    u64 memory_limit;               /* Limite de memória */
    u64 io_balance;                 /* Saldo de I/O (bytes) */
    u64 io_limit;                   /* Limite de I/O */
    u64 network_balance;            /* Saldo de rede (bytes) */
    u64 network_limit;              /* Limite de rede */
    u64 power_balance;              /* Saldo de energia (µJ) */
    u64 power_limit;                /* Limite de energia */
    
    /* Taxas (custo por unidade) */
    u64 cpu_rate_ns;                /* Custo por nanosegundo */
    u64 memory_rate_bytes;          /* Custo por byte */
    u64 io_rate_bytes;              /* Custo por byte I/O */
    u64 network_rate_bytes;         /* Custo por byte rede */
    u64 power_rate_uj;              /* Custo por microjoule */
    
    /* Histórico de transações */
    struct list_head entries;       /* Lista de ledger_entry */
    atomic_t entry_count;           /* Número de entries */
    u64 total_entries;              /* Total histórico */
    
    /* Lock e proteção */
    spinlock_t lock;
    struct mutex mutex;
    
    /* Callbacks de billing */
    void (*on_charge)(struct task_ledger *ledger, struct ledger_entry *entry);
    void (*on_limit_reached)(struct task_ledger *ledger, u32 type);
    void (*on_overdraft)(struct task_ledger *ledger, u32 type, u64 amount);
    
    /* Estatísticas */
    struct {
        u64 total_charged;
        u64 total_refunded;
        u64 total_overdrafts;
        u64 limit_violations;
    } stats;
};

/* Checkpoint image - snapshot do estado da task */
struct checkpoint_image {
    u64 id;                         /* ID do checkpoint */
    u64 timestamp;                  /* Timestamp do checkpoint */
    pid_t pid;                      /* PID da task */
    u32 flags;                      /* CHECKPOINT_FLAG_* */
    char name[64];                  /* Nome do checkpoint */
    char description[256];          /* Descrição */
    
    /* Metadados */
    size_t memory_size;             /* Tamanho da memória salva */
    size_t image_size;              /* Tamanho total da imagem */
    u64 checksum;                   /* Checksum da imagem */
    
    /* Dados salvos */
    void *memory_data;              /* Dados de memória */
    void *regs_data;                /* Dados de registradores */
    void *fds_data;                 /* Dados de file descriptors */
    void *signals_data;             /* Dados de sinais */
    void *timers_data;              /* Dados de timers */
    void *namespace_data;           /* Dados de namespaces */
    void *seccomp_data;             /* Dados de seccomp */
    void *custom_data;              /* Dados personalizados */
    
    /* Ponteiros para objetos restaurados */
    struct task_struct *restored_task;
    
    /* Lista e sincronização */
    struct list_head list;
    struct mutex lock;
    refcount_t refcount;
};

/* Estrutura de sandbox da task */
struct task_sandbox {
    u32 flags;                      /* SANDBOX_FLAG_* */
    char name[64];                  /* Nome da sandbox */
    
    /* Restrições de rede */
    struct list_head allowed_ips;   /* IPs permitidos */
    struct list_head blocked_ips;   /* IPs bloqueados */
    u32 allowed_ports[16];          /* Portas permitidas */
    int allowed_port_count;
    
    /* Restrições de filesystem */
    struct list_head allowed_paths;  /* Paths permitidos */
    struct list_head readonly_paths; /* Paths somente leitura */
    struct list_head blocked_paths;  /* Paths bloqueados */
    
    /* Restrições de syscall */
    struct sock_fprog *seccomp_filter; /* Seccomp filter */
    unsigned long seccomp_filter_len;
    
    /* Limites de recursos */
    struct rlimit limits[RLIM_NLIMITS];
    
    /* Contexto LSM */
    void *apparmor_profile;
    void *selinux_context;
    void *landlock_rules;
    
    /* Sincronização */
    spinlock_t lock;
};

/* Estrutura de isolamento da task */
struct task_isolation {
    u32 flags;                      /* ISOLATION_FLAG_* */
    
    /* Isolamento de CPU */
    cpumask_t allowed_cpus;         /* CPUs permitidas */
    cpumask_t isolated_cpus;        /* CPUs isoladas (exclusivas) */
    int preferred_node;             /* NUMA node preferido */
    
    /* Isolamento de cache */
    u32 cache_way_mask;             /* Máscara de ways de cache */
    u32 cache_id;                   /* Cache ID reservado */
    
    /* Isolamento de memória */
    struct mempolicy *mempolicy;    /* Política de memória NUMA */
    unsigned long memory_nodes;     /* Nós de memória permitidos */
    
    /* Isolamento de I/O */
    struct list_head allowed_devices; /* Dispositivos permitidos */
    u32 io_priority;                /* Prioridade de I/O */
    
    /* Isolamento de rede */
    struct net *netns;              /* Network namespace isolado */
    struct list_head allowed_interfaces; /* Interfaces permitidas */
    
    /* Sincronização */
    spinlock_t lock;
};

/* Extensão do task_struct do Linux */
struct lih_task_ext {
    /* Identificação LIH */
    u64 lih_id;                     /* ID único LIH */
    u32 lih_state;                  /* TASK_STATE_* estendido */
    u32 lih_flags;                  /* Flags específicas LIH */
    
    /* Ledger associado */
    struct task_ledger *ledger;
    
    /* Checkpoints */
    struct list_head checkpoints;   /* Lista de checkpoint_image */
    struct checkpoint_image *last_checkpoint;
    atomic_t checkpoint_count;
    
    /* Sandbox e isolamento */
    struct task_sandbox *sandbox;
    struct task_isolation *isolation;
    
    /* Integração com Mach */
    task_t mach_task;               /* Task correspondente no Mach */
    thread_t mach_main_thread;      /* Thread principal no Mach */
    mach_port_t mach_exception_port; /* Porta de exceções */
    mach_port_t mach_notify_port;   /* Porta de notificações */
    
    /* Métricas estendidas */
    struct {
        /* CPU metrics */
        u64 total_cpu_time_ns;
        u64 user_cpu_time_ns;
        u64 system_cpu_time_ns;
        u64 wait_cpu_time_ns;
        u64 stolen_cpu_time_ns;
        
        /* Memory metrics */
        u64 peak_rss_bytes;
        u64 peak_swap_bytes;
        u64 page_fault_count;
        u64 major_fault_count;
        
        /* I/O metrics */
        u64 io_read_bytes;
        u64 io_write_bytes;
        u64 io_read_ops;
        u64 io_write_ops;
        
        /* Network metrics */
        u64 net_rx_bytes;
        u64 net_tx_bytes;
        u64 net_rx_packets;
        u64 net_tx_packets;
        
        /* Power metrics */
        u64 energy_uj;
        u64 power_avg_mw;
        
        /* Scheduling metrics */
        u64 context_switches;
        u64 involuntary_switches;
        u64 migration_count;
        u64 preemption_count;
        
        /* Security metrics */
        u64 seccomp_violations;
        u64 cap_usage_count;
        u64 audit_events;
    } metrics;
    
    /* Estatísticas de ledger (cache) */
    struct {
        u64 cpu_charged;
        u64 memory_charged;
        u64 io_charged;
        u64 network_charged;
        u64 power_charged;
    } ledger_cache;

    struct task_struct     member;
    /* Callbacks de ciclo de vida */
    void (*on_create)(struct task_struct *task);
    void (*on_start)(struct task_struct *task);
    void (*on_pause)(struct task_struct *task);
    void (*on_resume)(struct task_struct *task);
    void (*on_terminate)(struct task_struct *task);
    void (*on_checkpoint)(struct task_struct *task, struct checkpoint_image *img);
    void (*on_restore)(struct task_struct *task, struct checkpoint_image *img);
    void (*on_migrate)(struct task_struct *task, int src_cpu, int dst_cpu);
    
    /* Dados personalizados */
    void *private_data;
    void (*private_dtor)(void *data);
    
    /* Debug e forensics */
    u64 creation_timestamp;
    u64 last_state_change;
    u64 termination_timestamp;
    char *termination_reason;
    struct list_head audit_trail;
    
    /* Sincronização */
    spinlock_t lock;
    struct mutex ops_mutex;
    struct completion state_completion;
    
    /* Referência */
    refcount_t refcount;
    struct rcu_head rcu;
};

/* ============================================================================
 * Variáveis globais
 * ============================================================================ */

static struct kmem_cache *lih_task_ext_cache;
static struct kmem_cache *ledger_cache;
static struct kmem_cache *checkpoint_cache;
static struct kmem_cache *ledger_entry_cache;

static DEFINE_HASHTABLE(lih_task_hash, 16);
static DEFINE_RWLOCK(lih_task_hash_lock);

static atomic64_t lih_task_counter = ATOMIC64_INIT(1);
static atomic_t lih_task_active_count = ATOMIC_INIT(0);

/* ============================================================================
 * Funções auxiliares
 * ============================================================================ */

/* Gera ID único LIH */
static inline u64 lih_task_generate_id(void)
{
    return atomic64_inc_return(&lih_task_counter);
}

/* Calcula hash criptográfico para ledger entry */
static u64 ledger_entry_hash(struct ledger_entry *entry)
{
    u64 hash = 0;
    struct scatterlist sg;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    u8 digest[64];
    
    /* Simples CRC32 para performance (em produção usar SHA256) */
    hash = crc32_le(0, (u8 *)&entry->type, sizeof(entry->type));
    hash = crc32_le(hash, (u8 *)&entry->amount, sizeof(entry->amount));
    hash = crc32_le(hash, (u8 *)&entry->timestamp, sizeof(entry->timestamp));
    hash = crc32_le(hash, (u8 *)&entry->pid, sizeof(entry->pid));
    
    return hash;
}

/* Verifica se task está em estado executável */
static inline bool lih_task_is_runnable(struct task_struct *task)
{
    struct lih_task_ext *ext = task->lih_ext;
    
    if (!ext)
        return false;
    
    return (ext->lih_state == TASK_STATE_RUNNING) &&
           !(task->flags & PF_EXITING) &&
           task->__state == TASK_RUNNING;
}

/* ============================================================================
 * Ledger Operations (Contabilidade)
 * ============================================================================ */

/* Cria um novo ledger */
struct task_ledger *ledger_create(const char *name, u32 flags,
                                   u64 cpu_limit, u64 memory_limit)
{
    struct task_ledger *ledger;
    
    ledger = kmem_cache_alloc(ledger_cache, GFP_KERNEL);
    if (!ledger)
        return ERR_PTR(-ENOMEM);
    
    memset(ledger, 0, sizeof(*ledger));
    ledger->id = lih_task_generate_id();
    strscpy(ledger->name, name ?: "unnamed", sizeof(ledger->name));
    ledger->flags = flags;
    ledger->cpu_credit_limit = cpu_limit;
    ledger->memory_limit = memory_limit;
    
    /* Taxas padrão */
    ledger->cpu_rate_ns = 1;           /* 1 unidade por nanosegundo */
    ledger->memory_rate_bytes = 1;     /* 1 unidade por byte */
    ledger->io_rate_bytes = 1;
    ledger->network_rate_bytes = 1;
    ledger->power_rate_uj = 1;
    
    INIT_LIST_HEAD(&ledger->entries);
    spin_lock_init(&ledger->lock);
    mutex_init(&ledger->mutex);
    atomic_set(&ledger->entry_count, 0);
    
    return ledger;
}
EXPORT_SYMBOL(ledger_create);

/* Destroi ledger */
void ledger_destroy(struct task_ledger *ledger)
{
    struct ledger_entry *entry, *tmp;
    
    if (!ledger)
        return;
    
    /* Libera todas as entries */
    list_for_each_entry_safe(entry, tmp, &ledger->entries, list) {
        list_del(&entry->list);
        kmem_cache_free(ledger_entry_cache, entry);
    }
    
    kmem_cache_free(ledger_cache, ledger);
}
EXPORT_SYMBOL(ledger_destroy);

/* Cobra (debita) uma quantidade de recurso do ledger */
int ledger_charge(struct task_ledger *ledger, u32 type, u64 amount,
                   const char *description)
{
    struct ledger_entry *entry;
    unsigned long flags;
    u64 cost;
    u64 *balance;
    u64 *limit;
    
    if (!ledger)
        return -EINVAL;
    
    /* Calcula custo baseado no tipo */
    switch (type) {
    case LEDGER_ENTRY_CPU_TIME:
        cost = amount * ledger->cpu_rate_ns;
        balance = &ledger->cpu_balance;
        limit = &ledger->cpu_credit_limit;
        break;
    case LEDGER_ENTRY_MEMORY_BYTES:
        cost = amount * ledger->memory_rate_bytes;
        balance = &ledger->memory_balance;
        limit = &ledger->memory_limit;
        break;
    case LEDGER_ENTRY_IO_BYTES:
        cost = amount * ledger->io_rate_bytes;
        balance = &ledger->io_balance;
        limit = &ledger->io_limit;
        break;
    case LEDGER_ENTRY_NET_TX:
    case LEDGER_ENTRY_NET_RX:
        cost = amount * ledger->network_rate_bytes;
        balance = &ledger->network_balance;
        limit = &ledger->network_limit;
        break;
    case LEDGER_ENTRY_POWER_ENERGY:
        cost = amount * ledger->power_rate_uj;
        balance = &ledger->power_balance;
        limit = &ledger->power_limit;
        break;
    default:
        return -EINVAL;
    }
    
    spin_lock_irqsave(&ledger->lock, flags);
    
    /* Verifica limite */
    if (!(ledger->flags & LEDGER_FLAG_OVERDRAFT) && *balance < cost) {
        spin_unlock_irqrestore(&ledger->lock, flags);
        if (ledger->on_limit_reached)
            ledger->on_limit_reached(ledger, type);
        return -EDQUOT;
    }
    
    /* Debita */
    *balance -= cost;
    
    /* Cria entrada no ledger */
    entry = kmem_cache_alloc(ledger_entry_cache, GFP_ATOMIC);
    if (entry) {
        entry->id = lih_task_generate_id();
        entry->type = type;
        entry->amount = amount;
        entry->cost = cost;
        entry->timestamp = ktime_get_real_ns();
        entry->balance = *balance;
        entry->pid = current->pid;
        entry->uid = from_kuid(&init_user_ns, current_uid());
        entry->cpu = raw_smp_processor_id();
        entry->flags = LEDGER_FLAG_CHARGED;
        strscpy(entry->description, description ?: "charge", sizeof(entry->description));
        entry->hash = ledger_entry_hash(entry);
        
        list_add_tail(&entry->list, &ledger->entries);
        atomic_inc(&ledger->entry_count);
        ledger->total_entries++;
        ledger->stats.total_charged += cost;
    }
    
    spin_unlock_irqrestore(&ledger->lock, flags);
    
    /* Callback */
    if (ledger->on_charge)
        ledger->on_charge(ledger, entry);
    
    return 0;
}
EXPORT_SYMBOL(ledger_charge);

/* Credita (adiciona) saldo ao ledger */
int ledger_credit(struct task_ledger *ledger, u32 type, u64 amount,
                   const char *description)
{
    struct ledger_entry *entry;
    unsigned long flags;
    u64 *balance;
    
    if (!ledger)
        return -EINVAL;
    
    switch (type) {
    case LEDGER_ENTRY_CPU_TIME:
        balance = &ledger->cpu_balance;
        break;
    case LEDGER_ENTRY_MEMORY_BYTES:
        balance = &ledger->memory_balance;
        break;
    case LEDGER_ENTRY_IO_BYTES:
        balance = &ledger->io_balance;
        break;
    case LEDGER_ENTRY_NET_TX:
    case LEDGER_ENTRY_NET_RX:
        balance = &ledger->network_balance;
        break;
    case LEDGER_ENTRY_POWER_ENERGY:
        balance = &ledger->power_balance;
        break;
    default:
        return -EINVAL;
    }
    
    spin_lock_irqsave(&ledger->lock, flags);
    
    *balance += amount;
    
    entry = kmem_cache_alloc(ledger_entry_cache, GFP_ATOMIC);
    if (entry) {
        entry->id = lih_task_generate_id();
        entry->type = type;
        entry->amount = amount;
        entry->timestamp = ktime_get_real_ns();
        entry->balance = *balance;
        entry->flags = 0;
        strscpy(entry->description, description ?: "credit", sizeof(entry->description));
        
        list_add_tail(&entry->list, &ledger->entries);
        atomic_inc(&ledger->entry_count);
        ledger->stats.total_refunded += amount;
    }
    
    spin_unlock_irqrestore(&ledger->lock, flags);
    
    return 0;
}
EXPORT_SYMBOL(ledger_credit);

/* ============================================================================
 * Task Lifecycle Management
 * ============================================================================ */

/* Cria uma nova task LIH (wrapper around copy_process) */
struct task_struct *lih_task_create(int (*fn)(void *), void *arg,
                                      const char *name, struct task_ledger *ledger,
                                      u32 flags)
{
    struct task_struct *task;
    struct lih_task_ext *ext;
    pid_t pid;
    
    if (!fn)
        return ERR_PTR(-EINVAL);
    
    /* Cria kernel thread */
    task = kthread_create(fn, arg, "%s", name ?: "lih_task");
    if (IS_ERR(task))
        return task;
    
    /* Adiciona extensão LIH */
    ext = kmem_cache_alloc(lih_task_ext_cache, GFP_KERNEL);
    if (!ext) {
        kthread_stop(task);
        return ERR_PTR(-ENOMEM);
    }
    
    memset(ext, 0, sizeof(*ext));
    ext->lih_id = lih_task_generate_id();
    ext->lih_state = TASK_STATE_CREATED;
    ext->lih_flags = flags;
    ext->ledger = ledger;
    ext->creation_timestamp = ktime_get_real_ns();
    ext->last_state_change = ext->creation_timestamp;
    
    INIT_LIST_HEAD(&ext->checkpoints);
    INIT_LIST_HEAD(&ext->audit_trail);
    spin_lock_init(&ext->lock);
    mutex_init(&ext->ops_mutex);
    init_completion(&ext->state_completion);
    refcount_set(&ext->refcount, 1);
    
    task->lih_ext = ext;
    
    /* Registra na hash table */
    write_lock(&lih_task_hash_lock);
    hash_add(lih_task_hash, &ext->rcu, ext->lih_id);
    write_unlock(&lih_task_hash_lock);
    
    atomic_inc(&lih_task_active_count);
    
    return task;
}
EXPORT_SYMBOL(lih_task_create);

/* Inicia uma task (wake up) */
int lih_task_start(struct task_struct *task)
{
    struct lih_task_ext *ext;
    unsigned long flags;
    
    if (!task || !task->lih_ext)
        return -EINVAL;
    
    ext = task->lih_ext;
    
    spin_lock_irqsave(&ext->lock, flags);
    
    if (ext->lih_state != TASK_STATE_CREATED &&
        ext->lih_state != TASK_STATE_PAUSED &&
        ext->lih_state != TASK_STATE_SUSPENDED) {
        spin_unlock_irqrestore(&ext->lock, flags);
        return -EINVAL;
    }
    
    ext->lih_state = TASK_STATE_RUNNING;
    ext->last_state_change = ktime_get_real_ns();
    
    spin_unlock_irqrestore(&ext->lock, flags);
    
    /* Inicia a task */
    wake_up_process(task);
    
    /* Callback */
    if (ext->on_start)
        ext->on_start(task);
    
    return 0;
}
EXPORT_SYMBOL(lih_task_start);

/* Pausa uma task (SIGSTOP) */
int lih_task_pause(struct task_struct *task)
{
    struct lih_task_ext *ext;
    unsigned long flags;
    int ret;
    
    if (!task || !task->lih_ext)
        return -EINVAL;
    
    ext = task->lih_ext;
    
    spin_lock_irqsave(&ext->lock, flags);
    
    if (ext->lih_state != TASK_STATE_RUNNING) {
        spin_unlock_irqrestore(&ext->lock, flags);
        return -EINVAL;
    }
    
    ext->lih_state = TASK_STATE_PAUSED;
    ext->last_state_change = ktime_get_real_ns();
    
    spin_unlock_irqrestore(&ext->lock, flags);
    
    /* Envia SIGSTOP */
    ret = send_sig(SIGSTOP, task, 0);
    
    /* Callback */
    if (ext->on_pause)
        ext->on_pause(task);
    
    return ret;
}
EXPORT_SYMBOL(lih_task_pause);

/* Resuma uma task (SIGCONT) */
int lih_task_resume(struct task_struct *task)
{
    struct lih_task_ext *ext;
    unsigned long flags;
    int ret;
    
    if (!task || !task->lih_ext)
        return -EINVAL;
    
    ext = task->lih_ext;
    
    spin_lock_irqsave(&ext->lock, flags);
    
    if (ext->lih_state != TASK_STATE_PAUSED &&
        ext->lih_state != TASK_STATE_SUSPENDED) {
        spin_unlock_irqrestore(&ext->lock, flags);
        return -EINVAL;
    }
    
    ext->lih_state = TASK_STATE_RUNNING;
    ext->last_state_change = ktime_get_real_ns();
    
    spin_unlock_irqrestore(&ext->lock, flags);
    
    /* Envia SIGCONT */
    ret = send_sig(SIGCONT, task, 0);
    
    /* Callback */
    if (ext->on_resume)
        ext->on_resume(task);
    
    return ret;
}
EXPORT_SYMBOL(lih_task_resume);

/* Termina uma task */
int lih_task_terminate(struct task_struct *task, int exit_code, const char *reason)
{
    struct lih_task_ext *ext;
    unsigned long flags;
    long timeout;
    int ret = 0;
    
    if (!task || !task->lih_ext)
        return -EINVAL;
    
    ext = task->lih_ext;
    
    spin_lock_irqsave(&ext->lock, flags);
    
    if (ext->lih_state == TASK_STATE_TERMINATING ||
        ext->lih_state == TASK_STATE_DEAD) {
        spin_unlock_irqrestore(&ext->lock, flags);
        return -EALREADY;
    }
    
    ext->lih_state = TASK_STATE_TERMINATING;
    ext->last_state_change = ktime_get_real_ns();
    ext->termination_timestamp = ext->last_state_change;
    
    if (reason) {
        ext->termination_reason = kstrdup(reason, GFP_ATOMIC);
    }
    
    spin_unlock_irqrestore(&ext->lock, flags);
    
    /* Callback */
    if (ext->on_terminate)
        ext->on_terminate(task);
    
    /* Mata a task */
    if (task->flags & PF_KTHREAD) {
        /* Kernel thread */
        ret = kthread_stop(task);
    } else {
        /* User task - envia SIGKILL */
        ret = send_sig(SIGKILL, task, 0);
        
        /* Aguarda término */
        timeout = wait_for_completion_timeout(&task->exit, 
                                               msecs_to_jiffies(TASK_TERMINATE_TIMEOUT_MS));
        if (timeout == 0) {
            ret = -ETIMEDOUT;
        }
    }
    
    spin_lock_irqsave(&ext->lock, flags);
    ext->lih_state = TASK_STATE_DEAD;
    spin_unlock_irqrestore(&ext->lock, flags);
    
    complete_all(&ext->state_completion);
    
    return ret;
}
EXPORT_SYMBOL(lih_task_terminate);

/* ============================================================================
 * Checkpoint and Restore
 * ============================================================================ */

/* Cria checkpoint da task */
struct checkpoint_image *lih_task_checkpoint(struct task_struct *task, u32 flags,
                                               const char *name)
{
    struct lih_task_ext *ext;
    struct checkpoint_image *image;
    struct mm_struct *mm;
    unsigned long flags_save;
    int ret;
    
    if (!task || !task->lih_ext)
        return ERR_PTR(-EINVAL);
    
    ext = task->lih_ext;
    
    image = kmem_cache_alloc(checkpoint_cache, GFP_KERNEL);
    if (!image)
        return ERR_PTR(-ENOMEM);
    
    memset(image, 0, sizeof(*image));
    image->id = lih_task_generate_id();
    image->timestamp = ktime_get_real_ns();
    image->pid = task->pid;
    image->flags = flags;
    strscpy(image->name, name ?: "checkpoint", sizeof(image->name));
    mutex_init(&image->lock);
    refcount_set(&image->refcount, 1);
    
    /* Pausa a task para checkpoint consistente */
    spin_lock_irqsave(&ext->lock, flags_save);
    if (ext->lih_state == TASK_STATE_RUNNING) {
        ext->lih_state = TASK_STATE_CHECKPOINT;
        spin_unlock_irqrestore(&ext->lock, flags_save);
        
        /* Aguarda task ficar quiescente */
        ret = wait_for_completion_timeout(&ext->state_completion,
                                           msecs_to_jiffies(TASK_CHECKPOINT_TIMEOUT_MS));
        if (ret == 0) {
            kmem_cache_free(checkpoint_cache, image);
            return ERR_PTR(-ETIMEDOUT);
        }
    } else {
        spin_unlock_irqrestore(&ext->lock, flags_save);
    }
    
    /* Salva registradores */
    if (flags & CHECKPOINT_FLAG_MEMORY) {
        mm = get_task_mm(task);
        if (mm) {
            /* Salva memória (simplificado - implementação real seria complexa) */
            image->memory_size = mm->total_vm << PAGE_SHIFT;
            image->memory_data = vmalloc(image->memory_size);
            if (image->memory_data) {
                /* Copia memória do processo */
                struct vm_area_struct *vma;
                mmap_read_lock(mm);
                for (vma = mm->mmap; vma; vma = vma->vm_next) {
                    /* Copia cada VMA */
                }
                mmap_read_unlock(mm);
            }
            mmput(mm);
        }
    }
    
    /* Salva file descriptors */
    if (flags & CHECKPOINT_FLAG_FDS) {
        struct files_struct *files = task->files;
        if (files) {
            /* Salva estado dos FDs */
            /* ... */
        }
    }
    
    /* Salva sinais */
    if (flags & CHECKPOINT_FLAG_SIGNALS) {
        struct signal_struct *sig = task->signal;
        if (sig) {
            /* Salva estado de sinais */
            /* ... */
        }
    }
    
    /* Adiciona à lista de checkpoints */
    spin_lock(&ext->lock);
    list_add_tail(&image->list, &ext->checkpoints);
    ext->last_checkpoint = image;
    atomic_inc(&ext->checkpoint_count);
    spin_unlock(&ext->lock);
    
    /* Retorna ao estado anterior */
    spin_lock_irqsave(&ext->lock, flags_save);
    ext->lih_state = TASK_STATE_RUNNING;
    spin_unlock_irqrestore(&ext->lock, flags_save);
    
    if (ext->on_checkpoint)
        ext->on_checkpoint(task, image);
    
    return image;
}
EXPORT_SYMBOL(lih_task_checkpoint);

/* Restaura task a partir de checkpoint */
int lih_task_restore(struct task_struct *task, struct checkpoint_image *image)
{
    struct lih_task_ext *ext;
    unsigned long flags;
    int ret = 0;
    
    if (!task || !task->lih_ext || !image)
        return -EINVAL;
    
    ext = task->lih_ext;
    
    spin_lock_irqsave(&ext->lock, flags);
    ext->lih_state = TASK_STATE_RESTORING;
    spin_unlock_irqrestore(&ext->lock, flags);
    
    /* Restaura memória */
    if (image->flags & CHECKPOINT_FLAG_MEMORY && image->memory_data) {
        struct mm_struct *mm = get_task_mm(task);
        if (mm) {
            /* Restaura memória (implementação complexa) */
            /* ... */
            mmput(mm);
        }
    }
    
    /* Restaura registradores */
    if (image->regs_data) {
        /* Restaura contexto de CPU */
        /* ... */
    }
    
    /* Restaura file descriptors */
    if (image->flags & CHECKPOINT_FLAG_FDS && image->fds_data) {
        /* Restaura FDs */
        /* ... */
    }
    
    /* Restaura sinais */
    if (image->flags & CHECKPOINT_FLAG_SIGNALS && image->signals_data) {
        /* Restaura estado de sinais */
        /* ... */
    }
    
    spin_lock_irqsave(&ext->lock, flags);
    ext->lih_state = TASK_STATE_RUNNING;
    spin_unlock_irqrestore(&ext->lock, flags);
    
    if (ext->on_restore)
        ext->on_restore(task, image);
    
    return ret;
}
EXPORT_SYMBOL(lih_task_restore);

/* ============================================================================
 * Sandbox e Isolamento
 * ============================================================================ */

/* Cria sandbox para a task */
int lih_task_sandbox(struct task_struct *task, u32 flags)
{
    struct lih_task_ext *ext;
    struct task_sandbox *sandbox;
    
    if (!task || !task->lih_ext)
        return -EINVAL;
    
    ext = task->lih_ext;
    
    sandbox = kzalloc(sizeof(*sandbox), GFP_KERNEL);
    if (!sandbox)
        return -ENOMEM;
    
    sandbox->flags = flags;
    snprintf(sandbox->name, sizeof(sandbox->name), "sandbox_%d", task->pid);
    INIT_LIST_HEAD(&sandbox->allowed_ips);
    INIT_LIST_HEAD(&sandbox->blocked_ips);
    INIT_LIST_HEAD(&sandbox->allowed_paths);
    INIT_LIST_HEAD(&sandbox->readonly_paths);
    INIT_LIST_HEAD(&sandbox->blocked_paths);
    spin_lock_init(&sandbox->lock);
    
    /* Configura seccomp se necessário */
    if (flags & SANDBOX_FLAG_SECCOMP) {
        /* Carrega filtro seccomp padrão */
        /* ... */
    }
    
    /* Configura Landlock */
    if (flags & SANDBOX_FLAG_LANDLOCK) {
        /* Configura regras Landlock */
        /* ... */
    }
    
    /* Configura AppArmor */
    if (flags & SANDBOX_FLAG_APPARMOR) {
        /* Carrega perfil AppArmor */
        /* ... */
    }
    
    ext->sandbox = sandbox;
    
    return 0;
}
EXPORT_SYMBOL(lih_task_sandbox);

/* Remove sandbox */
void lih_task_unsandbox(struct task_struct *task)
{
    struct lih_task_ext *ext;
    
    if (!task || !task->lih_ext)
        return;
    
    ext = task->lih_ext;
    
    if (ext->sandbox) {
        /* Limpa seccomp */
        if (ext->sandbox->seccomp_filter) {
            kfree(ext->sandbox->seccomp_filter);
        }
        
        kfree(ext->sandbox);
        ext->sandbox = NULL;
    }
}
EXPORT_SYMBOL(lih_task_unsandbox);

/* ============================================================================
 * Migração de Tasks
 * ============================================================================ */

/* Migra task para outra CPU */
int lih_task_migrate(struct task_struct *task, int target_cpu)
{
    struct lih_task_ext *ext;
    int src_cpu;
    int ret;
    
    if (!task || !task->lih_ext)
        return -EINVAL;
    
    ext = task->lih_ext;
    
    if (!cpu_online(target_cpu))
        return -EINVAL;
    
    src_cpu = task_cpu(task);
    
    if (src_cpu == target_cpu)
        return 0;
    
    spin_lock(&ext->lock);
    ext->lih_state = TASK_STATE_MIGRATING;
    spin_unlock(&ext->lock);
    
    /* Realiza a migração */
    ret = set_cpus_allowed_ptr(task, cpumask_of(target_cpu));
    if (ret == 0) {
        ext->metrics.migration_count++;
        
        if (ext->on_migrate)
            ext->on_migrate(task, src_cpu, target_cpu);
    }
    
    spin_lock(&ext->lock);
    ext->lih_state = TASK_STATE_RUNNING;
    spin_unlock(&ext->lock);
    
    return ret;
}
EXPORT_SYMBOL(lih_task_migrate);

/* ============================================================================
 * Métricas e Estatísticas
 * ============================================================================ */

/* Atualiza métricas da task (chamado periodicamente) */
void lih_task_update_metrics(struct task_struct *task)
{
    struct lih_task_ext *ext;
    struct task_struct *t = task ?: current;
    struct mm_struct *mm;
    
    if (!t->lih_ext)
        return;
    
    ext = t->lih_ext;
    
    spin_lock(&ext->lock);
    
    /* CPU time */
    ext->metrics.total_cpu_time_ns = task_cputime(t).sum;
    ext->metrics.user_cpu_time_ns = t->utime;
    ext->metrics.system_cpu_time_ns = t->stime;
    
    /* Memory */
    mm = get_task_mm(t);
    if (mm) {
        ext->metrics.peak_rss_bytes = mm->hiwater_rss << PAGE_SHIFT;
        ext->metrics.peak_swap_bytes = mm->hiwater_swap << PAGE_SHIFT;
        mmput(mm);
    }
    
    /* Context switches */
    ext->metrics.context_switches = t->nvcsw + t->nivcsw;
    ext->metrics.involuntary_switches = t->nivcsw;
    
    spin_unlock(&ext->lock);
}
EXPORT_SYMBOL(lih_task_update_metrics);

/* ============================================================================
 * Debug e Forensics
 * ============================================================================ */

/* Adiciona entrada ao audit trail da task */
void lih_task_audit(struct task_struct *task, const char *event, void *data)
{
    struct lih_task_ext *ext;
    struct audit_entry *entry;
    
    if (!task || !task->lih_ext)
        return;
    
    ext = task->lih_ext;
    
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return;
    
    entry->timestamp = ktime_get_real_ns();
    strscpy(entry->event, event, sizeof(entry->event));
    entry->pid = task->pid;
    entry->uid = from_kuid(&init_user_ns, current_uid());
    
    spin_lock(&ext->lock);
    list_add_tail(&entry->list, &ext->audit_trail);
    
    /* Mantém apenas últimas 1000 entradas */
    if (list_length(&ext->audit_trail) > 1000) {
        struct audit_entry *old = list_first_entry(&ext->audit_trail,
                                                    struct audit_entry, list);
        list_del(&old->list);
        kfree(old);
    }
    spin_unlock(&ext->lock);
}
EXPORT_SYMBOL(lih_task_audit);

/* ============================================================================
 * Inicialização e finalização
 * ============================================================================ */

static int __init lih_task_init(void)
{
    printk(KERN_INFO "LIH Task Management initializing...\n");
    
    /* Cria caches */
    lih_task_ext_cache = kmem_cache_create("lih_task_ext",
                                            sizeof(struct lih_task_ext),
                                            __alignof__(struct lih_task_ext),
                                            SLAB_PANIC | SLAB_ACCOUNT,
                                            NULL);
    if (!lih_task_ext_cache)
        return -ENOMEM;
    
    ledger_cache = kmem_cache_create("task_ledger",
                                      sizeof(struct task_ledger),
                                      __alignof__(struct task_ledger),
                                      SLAB_PANIC | SLAB_ACCOUNT,
                                      NULL);
    if (!ledger_cache)
        goto out_destroy_ext;
    
    checkpoint_cache = kmem_cache_create("checkpoint_image",
                                          sizeof(struct checkpoint_image),
                                          __alignof__(struct checkpoint_image),
                                          SLAB_PANIC,
                                          NULL);
    if (!checkpoint_cache)
        goto out_destroy_ledger;
    
    ledger_entry_cache = kmem_cache_create("ledger_entry",
                                            sizeof(struct ledger_entry),
                                            __alignof__(struct ledger_entry),
                                            SLAB_PANIC,
                                            NULL);
    if (!ledger_entry_cache)
        goto out_destroy_checkpoint;
    
    /* Inicializa hash table */
    hash_init(lih_task_hash);
    
    printk(KERN_INFO "LIH Task Management initialized\n");
    printk(KERN_INFO "  - Task ext size: %zu bytes\n", sizeof(struct lih_task_ext));
    printk(KERN_INFO "  - Ledger size: %zu bytes\n", sizeof(struct task_ledger));
    
    return 0;

out_destroy_checkpoint:
    kmem_cache_destroy(checkpoint_cache);
out_destroy_ledger:
    kmem_cache_destroy(ledger_cache);
out_destroy_ext:
    kmem_cache_destroy(lih_task_ext_cache);
    return -ENOMEM;
}

static void __exit lih_task_exit(void)
{
    printk(KERN_INFO "LIH Task Management shutting down...\n");
    
    kmem_cache_destroy(lih_task_ext_cache);
    kmem_cache_destroy(ledger_cache);
    kmem_cache_destroy(checkpoint_cache);
    kmem_cache_destroy(ledger_entry_cache);
    
    printk(KERN_INFO "LIH Task Management shut down\n");
}

module_init(lih_task_init);
module_exit(lih_task_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LIH Project");
MODULE_DESCRIPTION("LIH Task Management - Extended task_struct with ledger and lifecycle");
MODULE_VERSION("1.0");
