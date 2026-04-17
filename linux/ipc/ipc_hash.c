/*
 * linux/ipc/ipc_hash.c - LIH IPC Hashing Subsystem
 * 
 * Gerenciamento de hash tables para lookup rápido de objetos IPC:
 *   - Hash tables para portas (Mach ports)
 *   - Hash tables para mensagens (message queues)
 *   - Hash tables para semáforos (semaphores)
 *   - Hash tables para memória compartilhada (shared memory)
 *   - Hash tables para pipes e FIFOs
 *   - Hash tables para filas de mensagens (message queues)
 *   - Hash tables para identificadores de processos IPC
 *   - Hash tables para namespaces IPC
 *   - Resolução de colisões com chain hashing
 *   - Hash dinâmico (redimensionamento automático)
 *   - Hash distribuído por CPU (per-CPU caches)
 *   - Hash com suporte a RCU para leitura lock-free
 * 
 * Integra com Linux e GNU Mach para lookup unificado de objetos IPC
 * 
 * Parte do projeto LIH (Linux Is Hybrid)
 * 
 * Licença: GPLv2
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/hash.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/ktime.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/proc_fs.h>
#include <linux/sysctl.h>
#include <linux/ratelimit.h>
#include <linux/random.h>
#include <linux/crc32.h>
#include <linux/siphash.h>

/* Headers do GNU Mach */
#include <mach/mach_types.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <mach/port.h>

/* ============================================================================
 * Constantes e definições
 * ============================================================================ */

/* Tipos de hash table IPC */
#define IPC_HASH_TYPE_PORT      0x0001   /* Mach ports */
#define IPC_HASH_TYPE_MSGQ      0x0002   /* Message queues */
#define IPC_HASH_TYPE_SEM       0x0004   /* Semaphores */
#define IPC_HASH_TYPE_SHM       0x0008   /* Shared memory */
#define IPC_HASH_TYPE_PIPE      0x0010   /* Pipes/FIFOs */
#define IPC_HASH_TYPE_MQUEUE    0x0020   /* POSIX message queues */
#define IPC_HASH_TYPE_NAMESPACE 0x0040   /* IPC namespaces */
#define IPC_HASH_TYPE_PROCESS   0x0080   /* IPC process identifiers */
#define IPC_HASH_TYPE_GLOBAL    0x8000   /* Global hash table */

/* Flags de entrada hash */
#define IPC_HASH_FLAG_ACTIVE    0x0001   /* Entrada ativa */
#define IPC_HASH_FLAG_DELETING  0x0002   /* Em processo de deleção */
#define IPC_HASH_FLAG_PERSISTENT 0x0004  /* Persistente (não expira) */
#define IPC_HASH_FLAG_EXPORTED  0x0008   /* Exportada para outros namespaces */
#define IPC_HASH_FLAG_LOCKED    0x0010   /* Entrada bloqueada */
#define IPC_HASH_FLAG_RCU       0x0020   /* Protegida por RCU */

/* Configurações de hash */
#define IPC_HASH_DEFAULT_SIZE   1024     /* Tamanho padrão */
#define IPC_HASH_MIN_SIZE       64       /* Tamanho mínimo */
#define IPC_HASH_MAX_SIZE       1048576  /* Tamanho máximo (1M) */
#define IPC_HASH_LOAD_FACTOR    75       /* Fator de carga (% para redimensionar) */
#define IPC_HASH_GROWTH_FACTOR  2        /* Fator de crescimento */
#define IPC_HASH_SHRINK_FACTOR  4        /* Fator de encolhimento */

/* Configurações de bucket */
#define IPC_HASH_MAX_CHAIN      256      /* Máximo de entradas por bucket */
#define IPC_HASH_MIGRATE_THRESH 128      /* Threshold para migração per-CPU */

/* Timeouts e expiração */
#define IPC_HASH_DEFAULT_TTL_NS (60ULL * NSEC_PER_SEC)  /* 60 segundos */
#define IPC_HASH_CLEANUP_INTERVAL_MS 5000 /* 5 segundos */
#define IPC_HASH_DEFRAG_INTERVAL_MS 60000 /* 60 segundos */

/* Estatísticas */
#define IPC_HASH_STAT_HASH_BITS 10
#define IPC_HASH_STAT_HASH_SIZE (1 << IPC_HASH_STAT_HASH_BITS)

/* ============================================================================
 * Estruturas de dados
 * ============================================================================ */

/* Forward declarations */
struct ipc_hash_table;
struct ipc_hash_bucket;
struct ipc_hash_entry;

/* Função hash para um tipo específico de objeto */
typedef u32 (*ipc_hash_func_t)(const void *key, size_t key_len, u32 seed);

/* Função de comparação de chaves */
typedef int (*ipc_hash_cmp_t)(const void *key1, const void *key2, size_t key_len);

/* Função de destruição de entrada */
typedef void (*ipc_hash_dtor_t)(struct ipc_hash_entry *entry);

/* Entrada na hash table */
struct ipc_hash_entry {
    u64 id;                         /* ID único da entrada */
    u32 type;                       /* Tipo IPC_HASH_TYPE_* */
    u32 flags;                      /* Flags IPC_HASH_FLAG_* */
    
    /* Chave (depende do tipo) */
    union {
        /* Mach port */
        struct {
            mach_port_t port;
            mach_port_name_t port_name;
            task_t owner_task;
        } port;
        
        /* Message queue */
        struct {
            key_t msgq_key;
            int msgq_id;
            struct msg_queue *msgq;
        } msgq;
        
        /* Semaphore */
        struct {
            key_t sem_key;
            int sem_id;
            struct sem_array *sem;
        } sem;
        
        /* Shared memory */
        struct {
            key_t shm_key;
            int shm_id;
            struct shmid_kernel *shm;
            unsigned long shmaddr;
        } shm;
        
        /* Pipe */
        struct {
            int pipe_fd[2];
            struct pipe_inode_info *pipe;
            struct inode *inode;
        } pipe;
        
        /* POSIX message queue */
        struct {
            char name[256];
            mqd_t mqdes;
            struct mqueue_inode_info *mq;
        } mqueue;
        
        /* Namespace */
        struct {
            struct ipc_namespace *ns;
            u32 ns_id;
            char ns_name[64];
        } namespace;
        
        /* Processo */
        struct {
            pid_t pid;
            pid_t tgid;
            struct task_struct *task;
            uid_t uid;
        } process;
        
        /* Chave genérica */
        struct {
            u8 data[256];
            size_t len;
        } generic;
    } key;
    
    /* Dados do objeto associado */
    void *data;                     /* Ponteiro para o objeto IPC */
    size_t data_size;               /* Tamanho dos dados */
    
    /* Referências */
    atomic_t refcount;              /* Contagem de referências */
    atomic_t lookup_count;          /* Contagem de lookups */
    
    /* Timestamps */
    u64 created_at;                 /* Timestamp de criação */
    u64 last_access;                /* Último acesso */
    u64 expires_at;                 /* Tempo de expiração (0 = nunca) */
    
    /* Links para buckets */
    struct hlist_node hash_node;    /* Nó na hash table */
    struct list_head lru_node;      /* Nó na lista LRU */
    struct rcu_head rcu;            /* Para liberação RCU */
    
    /* Callbacks */
    ipc_hash_dtor_t dtor;           /* Destrutor */
    
    /* Estatísticas */
    struct {
        u64 hits;                   /* Acessos com sucesso */
        u64 misses;                 /* Acessos com falha */
        u64 collisions;             /* Colisões */
        u64 migrations;             /* Migrações entre CPUs */
    } stats;
    
    /* Sincronização */
    spinlock_t lock;
    struct mutex mutex;
};

/* Bucket da hash table (contém lista de entradas) */
struct ipc_hash_bucket {
    struct hlist_head head;         /* Cabeça da lista de entradas */
    spinlock_t lock;                /* Lock do bucket */
    atomic_t count;                 /* Número de entradas no bucket */
    u32 seed;                       /* Seed para hash neste bucket */
    
    /* Estatísticas do bucket */
    struct {
        u64 total_inserts;
        u64 total_deletes;
        u64 total_lookups;
        u64 max_chain_len;
        u64 collisions;
    } stats;
};

/* Hash table principal */
struct ipc_hash_table {
    u32 id;                         /* ID da tabela */
    u32 type;                       /* Tipo IPC_HASH_TYPE_* */
    char name[64];                  /* Nome da tabela */
    
    /* Tabela de buckets */
    struct ipc_hash_bucket *buckets;
    u32 size;                       /* Número de buckets */
    u32 size_mask;                  /* Máscara para cálculo de índice */
    u32 entry_count;                /* Número total de entradas */
    u32 max_entries;                /* Máximo de entradas */
    
    /* Parâmetros de hash */
    u32 seed;                       /* Seed global para hash */
    ipc_hash_func_t hash_func;      /* Função hash personalizada */
    ipc_hash_cmp_t cmp_func;        /* Função de comparação */
    
    /* Configuração */
    u32 load_factor;                /* Fator de carga (%) */
    u32 flags;                      /* Flags da tabela */
    u32 ttl_ns;                     /* Time-to-live padrão (ns) */
    
    /* Redimensionamento */
    struct mutex resize_lock;
    struct ipc_hash_table *old_table; /* Tabela antiga durante resize */
    u32 resize_state;               /* Estado do redimensionamento */
    struct work_struct resize_work;
    
    /* LRU e expiração */
    struct list_head lru_list;      /* Lista LRU global */
    spinlock_t lru_lock;
    struct delayed_work cleanup_work;
    struct delayed_work defrag_work;
    
    /* Per-CPU caches */
    struct ipc_hash_entry __percpu **cpu_cache;
    u32 cache_size;
    
    /* Namespace associado */
    struct ipc_namespace *ns;
    
    /* Estatísticas globais */
    struct {
        atomic64_t total_inserts;
        atomic64_t total_deletes;
        atomic64_t total_lookups;
        atomic64_t total_hits;
        atomic64_t total_misses;
        atomic64_t total_collisions;
        atomic64_t total_resizes;
        atomic64_t total_expirations;
        atomic64_t total_migrations;
        
        u64 created_at;
        u64 last_resize;
        u64 last_cleanup;
    } stats;
    
    /* Sincronização global */
    struct mutex global_lock;
    struct rw_semaphore rw_sem;
    
    /* Debug */
    struct dentry *debugfs_root;
};

/* Hash table global para lookup rápido */
struct ipc_hash_global {
    /* Tabelas por tipo */
    struct ipc_hash_table *tables[IPC_HASH_TYPE_GLOBAL + 1];
    
    /* Tabela global de IDs (para lookup rápido por ID) */
    struct ipc_hash_table *id_table;
    
    /* Namespace raiz */
    struct ipc_namespace *root_ns;
    
    /* Seeds para hash */
    u32 global_seed;
    u32 per_table_seeds[IPC_HASH_TYPE_GLOBAL + 1];
    
    /* Estatísticas globais */
    struct {
        atomic64_t total_entries;
        atomic64_t total_memory;
        atomic64_t total_lookups;
        atomic64_t total_collisions;
    } stats;
    
    /* Sincronização */
    struct mutex global_lock;
    spinlock_t stats_lock;
    
    /* Configuração */
    struct {
        u32 default_table_size;
        u32 default_load_factor;
        u32 default_ttl_seconds;
        u32 enable_percpu_cache;
        u32 enable_rcu;
        u32 enable_lru;
    } config;
    
    /* Debug */
    struct dentry *debugfs_root;
    struct proc_dir_entry *proc_entry;
    struct ratelimit_state ratelimit;
};

/* ============================================================================
 * Variáveis globais
 * ============================================================================ */

static struct ipc_hash_global *ipc_hash_global;
static DEFINE_MUTEX(ipc_hash_global_lock);

/* Seeds aleatórias para hash */
static u32 ipc_hash_seed __read_mostly;
static u32 ipc_hash_seed_array[16] __read_mostly;

/* Funções hash padrão */
static siphash_key_t ipc_sip_hash_key;

/* ============================================================================
 * Funções hash
 * ============================================================================ */

/* Inicializa seeds aleatórias */
static void ipc_hash_init_seeds(void)
{
    int i;
    
    get_random_bytes(&ipc_hash_seed, sizeof(ipc_hash_seed));
    get_random_bytes(&ipc_hash_seed_array, sizeof(ipc_hash_seed_array));
    get_random_bytes(&ipc_sip_hash_key, sizeof(ipc_sip_hash_key));
}

/* Hash para inteiro (portas, IDs) */
static u32 ipc_hash_int(u32 key, u32 seed)
{
    return hash_32(key, seed);
}

/* Hash para chave genérica (array de bytes) */
static u32 ipc_hash_generic(const void *key, size_t len, u32 seed)
{
    return jhash(key, len, seed);
}

/* Hash para string (case-insensitive para compatibilidade) */
static u32 ipc_hash_string(const char *str, u32 seed)
{
    return jhash(str, strlen(str), seed);
}

/* Hash para Mach port */
static u32 ipc_hash_port(mach_port_t port, u32 seed)
{
    return hash_32((u32)port, seed);
}

/* Hash para chave IPC tradicional (key_t) */
static u32 ipc_hash_key(key_t key, u32 seed)
{
    return hash_32((u32)key, seed);
}

/* Hash para PID/TID */
static u32 ipc_hash_pid(pid_t pid, u32 seed)
{
    return hash_32((u32)pid, seed);
}

/* ============================================================================
 * Gerenciamento de entradas
 * ============================================================================ */

/* Cria uma nova entrada hash */
static struct ipc_hash_entry *ipc_hash_entry_alloc(u32 type, u32 flags)
{
    struct ipc_hash_entry *entry;
    
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return NULL;
    
    entry->id = atomic64_inc_return((atomic64_t *)&ipc_hash_global->stats.total_entries);
    entry->type = type;
    entry->flags = flags;
    entry->created_at = ktime_get_real_ns();
    entry->last_access = entry->created_at;
    
    atomic_set(&entry->refcount, 1);
    atomic_set(&entry->lookup_count, 0);
    spin_lock_init(&entry->lock);
    mutex_init(&entry->mutex);
    INIT_HLIST_NODE(&entry->hash_node);
    INIT_LIST_HEAD(&entry->lru_node);
    
    atomic64_inc(&ipc_hash_global->stats.total_memory);
    atomic64_add(sizeof(*entry), &ipc_hash_global->stats.total_memory);
    
    return entry;
}

/* Destrói uma entrada hash */
static void ipc_hash_entry_free(struct ipc_hash_entry *entry)
{
    if (!entry)
        return;
    
    if (entry->dtor)
        entry->dtor(entry);
    
    if (entry->data && entry->data_size)
        kfree(entry->data);
    
    atomic64_dec(&ipc_hash_global->stats.total_memory);
    atomic64_sub(sizeof(*entry), &ipc_hash_global->stats.total_memory);
    
    kfree(entry);
}

/* Incrementa referência */
static struct ipc_hash_entry *ipc_hash_entry_get(struct ipc_hash_entry *entry)
{
    if (entry && atomic_inc_not_zero(&entry->refcount))
        return entry;
    return NULL;
}

/* Decrementa referência */
static void ipc_hash_entry_put(struct ipc_hash_entry *entry)
{
    if (!entry)
        return;
    
    if (atomic_dec_and_test(&entry->refcount)) {
        ipc_hash_entry_free(entry);
    }
}

/* ============================================================================
 * Operações em buckets
 * ============================================================================ */

/* Calcula índice do bucket para uma chave */
static inline u32 ipc_hash_bucket_idx(struct ipc_hash_table *table, 
                                       const void *key, size_t key_len)
{
    u32 hash;
    
    if (table->hash_func) {
        hash = table->hash_func(key, key_len, table->seed);
    } else {
        /* Hash padrão para tipo específico */
        switch (table->type) {
        case IPC_HASH_TYPE_PORT:
            hash = ipc_hash_port(*(mach_port_t *)key, table->seed);
            break;
        case IPC_HASH_TYPE_MSGQ:
        case IPC_HASH_TYPE_SEM:
        case IPC_HASH_TYPE_SHM:
            hash = ipc_hash_key(*(key_t *)key, table->seed);
            break;
        case IPC_HASH_TYPE_PROCESS:
            hash = ipc_hash_pid(*(pid_t *)key, table->seed);
            break;
        default:
            hash = ipc_hash_generic(key, key_len, table->seed);
        }
    }
    
    return hash & table->size_mask;
}

/* Busca entrada em um bucket */
static struct ipc_hash_entry *ipc_hash_bucket_lookup(struct ipc_hash_bucket *bucket,
                                                      struct ipc_hash_table *table,
                                                      const void *key, size_t key_len,
                                                      int *collisions)
{
    struct ipc_hash_entry *entry;
    int col = 0;
    
    if (collisions)
        *collisions = 0;
    
    hlist_for_each_entry_rcu(entry, &bucket->head, hash_node) {
        if (entry->type != table->type) {
            col++;
            continue;
        }
        
        /* Compara chave baseado no tipo */
        int match = 0;
        
        switch (table->type) {
        case IPC_HASH_TYPE_PORT:
            if (entry->key.port.port == *(mach_port_t *)key)
                match = 1;
            break;
        case IPC_HASH_TYPE_MSGQ:
            if (entry->key.msgq.msgq_key == *(key_t *)key)
                match = 1;
            break;
        case IPC_HASH_TYPE_SEM:
            if (entry->key.sem.sem_key == *(key_t *)key)
                match = 1;
            break;
        case IPC_HASH_TYPE_SHM:
            if (entry->key.shm.shm_key == *(key_t *)key)
                match = 1;
            break;
        case IPC_HASH_TYPE_PROCESS:
            if (entry->key.process.pid == *(pid_t *)key)
                match = 1;
            break;
        default:
            if (table->cmp_func) {
                match = table->cmp_func(&entry->key.generic.data, key, key_len);
            } else if (key_len == entry->key.generic.len) {
                match = !memcmp(&entry->key.generic.data, key, key_len);
            }
        }
        
        if (match) {
            if (collisions)
                *collisions = col;
            return entry;
        }
        col++;
    }
    
    if (collisions)
        *collisions = col;
    
    return NULL;
}

/* Insere entrada em um bucket */
static int ipc_hash_bucket_insert(struct ipc_hash_bucket *bucket,
                                   struct ipc_hash_entry *entry)
{
    unsigned long flags;
    
    spin_lock_irqsave(&bucket->lock, flags);
    
    /* Verifica limite da chain */
    if (atomic_read(&bucket->count) >= IPC_HASH_MAX_CHAIN) {
        spin_unlock_irqrestore(&bucket->lock, flags);
        return -ENOSPC;
    }
    
    hlist_add_head_rcu(&entry->hash_node, &bucket->head);
    atomic_inc(&bucket->count);
    bucket->stats.total_inserts++;
    
    /* Atualiza estatísticas de chain */
    u32 count = atomic_read(&bucket->count);
    if (count > bucket->stats.max_chain_len)
        bucket->stats.max_chain_len = count;
    
    spin_unlock_irqrestore(&bucket->lock, flags);
    
    return 0;
}

/* Remove entrada de um bucket */
static void ipc_hash_bucket_remove(struct ipc_hash_bucket *bucket,
                                    struct ipc_hash_entry *entry)
{
    unsigned long flags;
    
    spin_lock_irqsave(&bucket->lock, flags);
    
    hlist_del_rcu(&entry->hash_node);
    atomic_dec(&bucket->count);
    bucket->stats.total_deletes++;
    
    spin_unlock_irqrestore(&bucket->lock, flags);
}

/* ============================================================================
 * Operações na tabela hash
 * ============================================================================ */

/* Cria uma nova tabela hash */
static struct ipc_hash_table *ipc_hash_table_create(u32 type, const char *name,
                                                     u32 size, u32 flags)
{
    struct ipc_hash_table *table;
    u32 i;
    
    table = kzalloc(sizeof(*table), GFP_KERNEL);
    if (!table)
        return ERR_PTR(-ENOMEM);
    
    table->id = atomic64_inc_return((atomic64_t *)&ipc_hash_global->stats.total_entries);
    table->type = type;
    strscpy(table->name, name ?: "unnamed", sizeof(table->name));
    table->flags = flags;
    
    /* Ajusta tamanho */
    if (size < IPC_HASH_MIN_SIZE)
        size = IPC_HASH_DEFAULT_SIZE;
    if (size > IPC_HASH_MAX_SIZE)
        size = IPC_HASH_MAX_SIZE;
    if (!is_power_of_2(size))
        size = roundup_pow_of_two(size);
    
    table->size = size;
    table->size_mask = size - 1;
    table->max_entries = (size * IPC_HASH_LOAD_FACTOR) / 100;
    
    /* Aloca buckets */
    table->buckets = kcalloc(size, sizeof(struct ipc_hash_bucket), GFP_KERNEL);
    if (!table->buckets) {
        kfree(table);
        return ERR_PTR(-ENOMEM);
    }
    
    /* Inicializa buckets */
    for (i = 0; i < size; i++) {
        INIT_HLIST_HEAD(&table->buckets[i].head);
        spin_lock_init(&table->buckets[i].lock);
        atomic_set(&table->buckets[i].count, 0);
        table->buckets[i].seed = ipc_hash_seed_array[i % 16];
    }
    
    /* Inicializa estruturas */
    table->seed = ipc_hash_seed;
    table->load_factor = IPC_HASH_LOAD_FACTOR;
    table->ttl_ns = IPC_HASH_DEFAULT_TTL_NS;
    
    mutex_init(&table->resize_lock);
    INIT_LIST_HEAD(&table->lru_list);
    spin_lock_init(&table->lru_lock);
    mutex_init(&table->global_lock);
    init_rwsem(&table->rw_sem);
    
    /* Inicializa work para cleanup */
    INIT_DELAYED_WORK(&table->cleanup_work, NULL);
    INIT_DELAYED_WORK(&table->defrag_work, NULL);
    
    /* Atualiza estatísticas globais */
    atomic64_add(size * sizeof(struct ipc_hash_bucket),
                 &ipc_hash_global->stats.total_memory);
    
    return table;
}

/* Destrói uma tabela hash */
static void ipc_hash_table_destroy(struct ipc_hash_table *table)
{
    struct ipc_hash_entry *entry;
    struct hlist_node *tmp;
    u32 i;
    
    if (!table)
        return;
    
    /* Remove todas as entradas */
    for (i = 0; i < table->size; i++) {
        struct ipc_hash_bucket *bucket = &table->buckets[i];
        
        spin_lock(&bucket->lock);
        hlist_for_each_entry_safe(entry, tmp, &bucket->head, hash_node) {
            hlist_del_rcu(&entry->hash_node);
            ipc_hash_entry_put(entry);
        }
        spin_unlock(&bucket->lock);
    }
    
    /* Libera memória */
    atomic64_sub(table->size * sizeof(struct ipc_hash_bucket),
                 &ipc_hash_global->stats.total_memory);
    
    kfree(table->buckets);
    kfree(table);
}

/* Redimensiona a tabela hash */
static int ipc_hash_table_resize(struct ipc_hash_table *table, u32 new_size)
{
    struct ipc_hash_table *new_table;
    struct ipc_hash_entry *entry;
    struct hlist_node *tmp;
    u32 i;
    int ret = 0;
    
    if (new_size < IPC_HASH_MIN_SIZE)
        new_size = IPC_HASH_MIN_SIZE;
    if (new_size > IPC_HASH_MAX_SIZE)
        new_size = IPC_HASH_MAX_SIZE;
    if (!is_power_of_2(new_size))
        new_size = roundup_pow_of_two(new_size);
    
    if (new_size == table->size)
        return 0;
    
    mutex_lock(&table->resize_lock);
    
    /* Cria nova tabela */
    new_table = ipc_hash_table_create(table->type, table->name, new_size, table->flags);
    if (IS_ERR(new_table)) {
        ret = PTR_ERR(new_table);
        goto out_unlock;
    }
    
    /* Move entradas para nova tabela */
    for (i = 0; i < table->size; i++) {
        struct ipc_hash_bucket *old_bucket = &table->buckets[i];
        
        spin_lock(&old_bucket->lock);
        hlist_for_each_entry_safe(entry, tmp, &old_bucket->head, hash_node) {
            /* Remove da tabela antiga */
            hlist_del_rcu(&entry->hash_node);
            atomic_dec(&old_bucket->count);
            
            /* Insere na nova tabela */
            u32 new_idx = ipc_hash_bucket_idx(new_table, &entry->key, 
                                               sizeof(entry->key));
            struct ipc_hash_bucket *new_bucket = &new_table->buckets[new_idx];
            
            spin_lock(&new_bucket->lock);
            hlist_add_head_rcu(&entry->hash_node, &new_bucket->head);
            atomic_inc(&new_bucket->count);
            spin_unlock(&new_bucket->lock);
        }
        spin_unlock(&old_bucket->lock);
    }
    
    /* Troca tabelas */
    struct ipc_hash_bucket *old_buckets = table->buckets;
    u32 old_size = table->size;
    
    table->buckets = new_table->buckets;
    table->size = new_table->size;
    table->size_mask = new_table->size_mask;
    table->entry_count = new_table->entry_count;
    
    new_table->buckets = old_buckets;
    new_table->size = old_size;
    
    /* Destrói tabela antiga */
    ipc_hash_table_destroy(new_table);
    
    atomic64_inc(&table->stats.total_resizes);
    table->stats.last_resize = ktime_get_real_ns();
    
out_unlock:
    mutex_unlock(&table->resize_lock);
    return ret;
}

/* ============================================================================
 * Operações principais de hash
 * ============================================================================ */

/* Insere uma entrada na hash table */
int ipc_hash_insert(struct ipc_hash_table *table, const void *key, size_t key_len,
                     void *data, size_t data_size, u32 flags, u64 *out_id)
{
    struct ipc_hash_entry *entry;
    u32 idx;
    int ret;
    
    if (!table || !key)
        return -EINVAL;
    
    /* Verifica necessidade de redimensionamento */
    if (table->entry_count >= table->max_entries) {
        u32 new_size = table->size * IPC_HASH_GROWTH_FACTOR;
        ipc_hash_table_resize(table, new_size);
    }
    
    /* Cria entrada */
    entry = ipc_hash_entry_alloc(table->type, flags);
    if (!entry)
        return -ENOMEM;
    
    /* Copia chave */
    if (key_len > sizeof(entry->key.generic.data)) {
        ret = -E2BIG;
        goto out_free;
    }
    
    memcpy(&entry->key.generic.data, key, key_len);
    entry->key.generic.len = key_len;
    
    /* Copia dados */
    if (data && data_size) {
        entry->data = kmemdup(data, data_size, GFP_KERNEL);
        if (!entry->data) {
            ret = -ENOMEM;
            goto out_free;
        }
        entry->data_size = data_size;
    }
    
    /* Calcula bucket */
    idx = ipc_hash_bucket_idx(table, key, key_len);
    
    /* Insere no bucket */
    ret = ipc_hash_bucket_insert(&table->buckets[idx], entry);
    if (ret < 0)
        goto out_free_data;
    
    table->entry_count++;
    
    /* Adiciona à lista LRU */
    if (ipc_hash_global->config.enable_lru) {
        spin_lock(&table->lru_lock);
        list_add_tail(&entry->lru_node, &table->lru_list);
        spin_unlock(&table->lru_lock);
    }
    
    if (out_id)
        *out_id = entry->id;
    
    atomic64_inc(&table->stats.total_inserts);
    atomic64_inc(&ipc_hash_global->stats.total_lookups);
    
    return 0;

out_free_data:
    kfree(entry->data);
out_free:
    ipc_hash_entry_free(entry);
    return ret;
}
EXPORT_SYMBOL(ipc_hash_insert);

/* Busca uma entrada na hash table */
struct ipc_hash_entry *ipc_hash_lookup(struct ipc_hash_table *table,
                                        const void *key, size_t key_len)
{
    struct ipc_hash_entry *entry;
    u32 idx;
    int collisions;
    
    if (!table || !key)
        return NULL;
    
    idx = ipc_hash_bucket_idx(table, key, key_len);
    
    rcu_read_lock();
    entry = ipc_hash_bucket_lookup(&table->buckets[idx], table, key, key_len, &collisions);
    
    if (entry) {
        if (atomic_inc_not_zero(&entry->refcount)) {
            entry->last_access = ktime_get_real_ns();
            atomic_inc(&entry->lookup_count);
            entry->stats.hits++;
            
            if (collisions) {
                entry->stats.collisions += collisions;
                atomic64_add(collisions, &table->stats.total_collisions);
            }
            
            atomic64_inc(&table->stats.total_hits);
        } else {
            entry = NULL;
        }
    } else {
        atomic64_inc(&table->stats.total_misses);
        if (collisions)
            table->buckets[idx].stats.collisions += collisions;
    }
    
    rcu_read_unlock();
    
    atomic64_inc(&table->stats.total_lookups);
    atomic64_inc(&ipc_hash_global->stats.total_lookups);
    
    return entry;
}
EXPORT_SYMBOL(ipc_hash_lookup);

/* Remove uma entrada da hash table */
int ipc_hash_remove(struct ipc_hash_table *table, const void *key, size_t key_len)
{
    struct ipc_hash_entry *entry;
    u32 idx;
    
    if (!table || !key)
        return -EINVAL;
    
    idx = ipc_hash_bucket_idx(table, key, key_len);
    
    entry = ipc_hash_lookup(table, key, key_len);
    if (!entry)
        return -ENOENT;
    
    /* Remove do bucket */
    ipc_hash_bucket_remove(&table->buckets[idx], entry);
    table->entry_count--;
    
    /* Remove da lista LRU */
    if (ipc_hash_global->config.enable_lru) {
        spin_lock(&table->lru_lock);
        list_del(&entry->lru_node);
        spin_unlock(&table->lru_lock);
    }
    
    atomic64_inc(&table->stats.total_deletes);
    
    /* Verifica necessidade de encolhimento */
    if (table->entry_count < table->size / IPC_HASH_SHRINK_FACTOR &&
        table->size > IPC_HASH_MIN_SIZE) {
        u32 new_size = table->size / IPC_HASH_GROWTH_FACTOR;
        ipc_hash_table_resize(table, new_size);
    }
    
    ipc_hash_entry_put(entry);
    
    return 0;
}
EXPORT_SYMBOL(ipc_hash_remove);

/* ============================================================================
 * Gerenciamento de LRU e expiração
 * ============================================================================ */

/* Limpa entradas expiradas */
static void ipc_hash_cleanup_expired(struct ipc_hash_table *table)
{
    struct ipc_hash_entry *entry, *tmp;
    u64 now = ktime_get_real_ns();
    int cleaned = 0;
    
    if (!ipc_hash_global->config.enable_lru)
        return;
    
    spin_lock(&table->lru_lock);
    list_for_each_entry_safe(entry, tmp, &table->lru_list, lru_node) {
        if (entry->flags & IPC_HASH_FLAG_PERSISTENT)
            continue;
        
        if (entry->expires_at && entry->expires_at < now) {
            list_del(&entry->lru_node);
            /* Marca para remoção */
            entry->flags |= IPC_HASH_FLAG_DELETING;
            cleaned++;
            atomic64_inc(&table->stats.total_expirations);
        }
    }
    spin_unlock(&table->lru_lock);
    
    if (cleaned > 0) {
        /* Revalida entradas marcadas */
        /* ... */
    }
}

/* Trabalho de cleanup periódico */
static void ipc_hash_cleanup_work(struct work_struct *work)
{
    struct ipc_hash_table *table = container_of(work, struct ipc_hash_table,
                                                 cleanup_work.work);
    
    ipc_hash_cleanup_expired(table);
    table->stats.last_cleanup = ktime_get_real_ns();
    
    schedule_delayed_work(&table->cleanup_work,
                          msecs_to_jiffies(IPC_HASH_CLEANUP_INTERVAL_MS));
}

/* ============================================================================
 * Per-CPU cache
 * ============================================================================ */

/* Obtém entrada do cache per-CPU */
static struct ipc_hash_entry *ipc_hash_cpu_cache_get(struct ipc_hash_table *table,
                                                      const void *key, size_t key_len)
{
    struct ipc_hash_entry *entry;
    int cpu = smp_processor_id();
    
    if (!ipc_hash_global->config.enable_percpu_cache)
        return NULL;
    
    entry = *per_cpu_ptr(table->cpu_cache, cpu);
    if (entry && entry->key.generic.len == key_len &&
        !memcmp(&entry->key.generic.data, key, key_len)) {
        return ipc_hash_entry_get(entry);
    }
    
    return NULL;
}

/* Atualiza cache per-CPU */
static void ipc_hash_cpu_cache_set(struct ipc_hash_table *table,
                                    struct ipc_hash_entry *entry)
{
    int cpu = smp_processor_id();
    
    if (!ipc_hash_global->config.enable_percpu_cache)
        return;
    
    if (*per_cpu_ptr(table->cpu_cache, cpu))
        ipc_hash_entry_put(*per_cpu_ptr(table->cpu_cache, cpu));
    
    *per_cpu_ptr(table->cpu_cache, cpu) = ipc_hash_entry_get(entry);
    atomic64_inc(&table->stats.total_migrations);
}

/* ============================================================================
 * Interface para tipos específicos de IPC
 * ============================================================================ */

/* Hash table para Mach ports */
struct ipc_hash_table *ipc_hash_port_table_create(void)
{
    struct ipc_hash_table *table;
    
    table = ipc_hash_table_create(IPC_HASH_TYPE_PORT, "mach_ports",
                                   IPC_HASH_DEFAULT_SIZE, 0);
    if (IS_ERR(table))
        return table;
    
    return table;
}
EXPORT_SYMBOL(ipc_hash_port_table_create);

/* Registra um Mach port na hash table */
int ipc_hash_port_register(struct ipc_hash_table *table, mach_port_t port,
                            task_t owner, void *data)
{
    return ipc_hash_insert(table, &port, sizeof(port), data, 0, 0, NULL);
}
EXPORT_SYMBOL(ipc_hash_port_register);

/* Busca um Mach port na hash table */
struct ipc_hash_entry *ipc_hash_port_lookup(struct ipc_hash_table *table,
                                             mach_port_t port)
{
    return ipc_hash_lookup(table, &port, sizeof(port));
}
EXPORT_SYMBOL(ipc_hash_port_lookup);

/* Hash table para semáforos IPC */
struct ipc_hash_table *ipc_hash_sem_table_create(void)
{
    return ipc_hash_table_create(IPC_HASH_TYPE_SEM, "semaphores",
                                  IPC_HASH_DEFAULT_SIZE, 0);
}
EXPORT_SYMBOL(ipc_hash_sem_table_create);

/* ============================================================================
 * Interface de depuração
 * ============================================================================ */

#ifdef CONFIG_DEBUG_FS

static int ipc_hash_stats_show(struct seq_file *m, void *v)
{
    struct ipc_hash_table *table;
    int i;
    
    if (!ipc_hash_global)
        return 0;
    
    seq_printf(m, "LIH IPC Hashing Subsystem\n");
    seq_printf(m, "==========================\n\n");
    
    seq_printf(m, "Global Statistics:\n");
    seq_printf(m, "  Total Entries: %lld\n",
               atomic64_read(&ipc_hash_global->stats.total_entries));
    seq_printf(m, "  Total Memory: %lld bytes\n",
               atomic64_read(&ipc_hash_global->stats.total_memory));
    seq_printf(m, "  Total Lookups: %lld\n",
               atomic64_read(&ipc_hash_global->stats.total_lookups));
    seq_printf(m, "  Total Collisions: %lld\n",
               atomic64_read(&ipc_hash_global->stats.total_collisions));
    
    seq_printf(m, "\nConfiguration:\n");
    seq_printf(m, "  Default Table Size: %u\n",
               ipc_hash_global->config.default_table_size);
    seq_printf(m, "  Load Factor: %u%%\n",
               ipc_hash_global->config.default_load_factor);
    seq_printf(m, "  Default TTL: %u seconds\n",
               ipc_hash_global->config.default_ttl_seconds);
    seq_printf(m, "  Per-CPU Cache: %s\n",
               ipc_hash_global->config.enable_percpu_cache ? "enabled" : "disabled");
    seq_printf(m, "  RCU: %s\n",
               ipc_hash_global->config.enable_rcu ? "enabled" : "disabled");
    
    /* Tabelas registradas */
    seq_printf(m, "\nRegistered Tables:\n");
    for (i = 0; i <= IPC_HASH_TYPE_GLOBAL; i++) {
        table = ipc_hash_global->tables[i];
        if (table) {
            seq_printf(m, "  %s (type=%d): size=%u, entries=%u, hits=%lld, misses=%lld\n",
                       table->name, table->type, table->size, table->entry_count,
                       atomic64_read(&table->stats.total_hits),
                       atomic64_read(&table->stats.total_misses));
        }
    }
    
    return 0;
}

static int ipc_hash_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, ipc_hash_stats_show, NULL);
}

static const struct file_operations ipc_hash_stats_fops = {
    .open = ipc_hash_stats_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

#endif /* CONFIG_DEBUG_FS */

/* ============================================================================
 * Inicialização e finalização
 * ============================================================================ */

static int __init ipc_hash_init(void)
{
    int ret = 0;
    int i;
    
    printk(KERN_INFO "LIH IPC Hashing Subsystem initializing...\n");
    
    /* Inicializa seeds aleatórias */
    ipc_hash_init_seeds();
    
    /* Aloca estrutura global */
    ipc_hash_global = kzalloc(sizeof(*ipc_hash_global), GFP_KERNEL);
    if (!ipc_hash_global)
        return -ENOMEM;
    
    /* Inicializa configuração */
    ipc_hash_global->config.default_table_size = IPC_HASH_DEFAULT_SIZE;
    ipc_hash_global->config.default_load_factor = IPC_HASH_LOAD_FACTOR;
    ipc_hash_global->config.default_ttl_seconds = 60;
    ipc_hash_global->config.enable_percpu_cache = 1;
    ipc_hash_global->config.enable_rcu = 1;
    ipc_hash_global->config.enable_lru = 1;
    
    /* Inicializa seeds por tabela */
    for (i = 0; i <= IPC_HASH_TYPE_GLOBAL; i++) {
        ipc_hash_global->per_table_seeds[i] = ipc_hash_seed_array[i % 16];
    }
    
    /* Inicializa estruturas */
    mutex_init(&ipc_hash_global->global_lock);
    spin_lock_init(&ipc_hash_global->stats_lock);
    ratelimit_state_init(&ipc_hash_global->ratelimit, 5 * HZ, 10);
    
    /* Cria tabela global de IDs */
    ipc_hash_global->id_table = ipc_hash_table_create(IPC_HASH_TYPE_GLOBAL,
                                                       "global_ids",
                                                       IPC_HASH_DEFAULT_SIZE, 0);
    if (IS_ERR(ipc_hash_global->id_table)) {
        ret = PTR_ERR(ipc_hash_global->id_table);
        goto out_free;
    }
    
#ifdef CONFIG_DEBUG_FS
    ipc_hash_global->debugfs_root = debugfs_create_dir("ipc_hash", NULL);
    if (!IS_ERR(ipc_hash_global->debugfs_root)) {
        debugfs_create_file("stats", 0444, ipc_hash_global->debugfs_root,
                            NULL, &ipc_hash_stats_fops);
        debugfs_create_u32("default_table_size", 0644, ipc_hash_global->debugfs_root,
                           &ipc_hash_global->config.default_table_size);
        debugfs_create_u32("default_ttl_seconds", 0644, ipc_hash_global->debugfs_root,
                           &ipc_hash_global->config.default_ttl_seconds);
    }
#endif
    
    printk(KERN_INFO "LIH IPC Hashing Subsystem initialized\n");
    printk(KERN_INFO "  - Default table size: %u\n",
           ipc_hash_global->config.default_table_size);
    printk(KERN_INFO "  - Load factor: %u%%\n",
           ipc_hash_global->config.default_load_factor);
    printk(KERN_INFO "  - Hash seeds: randomized\n");
    
    return 0;

out_free:
    kfree(ipc_hash_global);
    ipc_hash_global = NULL;
    
    return ret;
}

static void __exit ipc_hash_exit(void)
{
    int i;
    
    if (!ipc_hash_global)
        return;
    
    printk(KERN_INFO "LIH IPC Hashing Subsystem shutting down...\n");
    
    /* Destrói tabelas */
    for (i = 0; i <= IPC_HASH_TYPE_GLOBAL; i++) {
        if (ipc_hash_global->tables[i]) {
            ipc_hash_table_destroy(ipc_hash_global->tables[i]);
        }
    }
    
    if (ipc_hash_global->id_table)
        ipc_hash_table_destroy(ipc_hash_global->id_table);
    
#ifdef CONFIG_DEBUG_FS
    debugfs_remove_recursive(ipc_hash_global->debugfs_root);
#endif
    
    kfree(ipc_hash_global);
    ipc_hash_global = NULL;
    
    printk(KERN_INFO "LIH IPC Hashing Subsystem shut down\n");
}

module_init(ipc_hash_init);
module_exit(ipc_hash_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LIH Project");
MODULE_DESCRIPTION("LIH IPC Hashing Subsystem - Fast lookup for IPC objects");
MODULE_VERSION("1.0");
