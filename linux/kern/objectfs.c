/*
 * linux/kernel/objectfs.c - LIH Object File System
 * 
 * Sistema de gerenciamento de objetos em memória (não arquivos tradicionais)
 * que unifica:
 *   - Objetos de memória entre Linux e GNU Mach
 *   - Objetos IPC (portas, mensagens, semáforos, locks)
 *   - Objetos de processo/thread (task_struct, thread_t)
 *   - Objetos de memória (regiões, páginas, zonas)
 *   - Objetos de sincronização (mutexes, rwlocks, condition variables)
 *   - Objetos personalizados com callbacks
 *   - Namespace hierárquico para organização de objetos
 *   - Referência e garbage collection
 *   - Persistência opcional em memória persistente
 * 
 * Este não é um filesystem tradicional - não há arquivos, apenas objetos
 * que podem ser referenciados por pathnames simbólicos.
 * 
 * Parte do projeto LIH (Linux Is Hybrid)
 * 
 * Licença: GPLv2
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/inode.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/radix-tree.h>
#include <linux/idr.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/random.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/proc_fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/mount.h>
#include <linux/magic.h>
#include <linux/refcount.h>

/* Headers do GNU Mach */
#include <mach/mach_types.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <mach/vm_prot.h>
#include <mach/task.h>
#include <mach/thread.h>
#include <mach/semaphore.h>
#include <mach/lock.h>

/* ============================================================================
 * Constantes e definições
 * ============================================================================ */

#define OBJECTFS_MAGIC          0x4F424A4653ULL    /* "OBJFS" */
#define OBJECTFS_SUPER_MAGIC    0x4F42535550ULL    /* "OBSUP" */

/* Tipos de objeto */
#define OBJECT_TYPE_NONE        0x0000
#define OBJECT_TYPE_GENERIC     0x0001      /* Objeto genérico */
#define OBJECT_TYPE_TASK        0x0002      /* Task Linux/Mach */
#define OBJECT_TYPE_THREAD      0x0003      /* Thread Linux/Mach */
#define OBJECT_TYPE_PORT        0x0004      /* Mach port */
#define OBJECT_TYPE_MESSAGE     0x0005      /* Mensagem IPC */
#define OBJECT_TYPE_SEMAPHORE   0x0006      /* Semáforo */
#define OBJECT_TYPE_MUTEX       0x0007      /* Mutex */
#define OBJECT_TYPE_RWLOCK      0x0008      /* Read-write lock */
#define OBJECT_TYPE_CONDVAR     0x0009      /* Condition variable */
#define OBJECT_TYPE_MEMORY      0x000A      /* Região de memória */
#define OBJECT_TYPE_PAGE        0x000B      /* Página de memória */
#define OBJECT_TYPE_ZONE        0x000C      /* Zona de memória */
#define OBJECT_TYPE_VM_MAP      0x000D      /* VM map */
#define OBJECT_TYPE_IPC_QUEUE   0x000E      /* Fila IPC */
#define OBJECT_TYPE_NOTIFIER    0x000F      /* Notifier */
#define OBJECT_TYPE_TIMER       0x0010      /* Timer */
#define OBJECT_TYPE_WORKQUEUE   0x0011      /* Workqueue */
#define OBJECT_TYPE_CUSTOM      0x8000      /* Tipo personalizado */

/* Flags de objeto */
#define OBJECT_FLAG_PERSISTENT  0x0001      /* Persistente (não deleta automaticamente) */
#define OBJECT_FLAG_SHARED      0x0002      /* Compartilhado entre processos */
#define OBJECT_FLAG_EXPORTED    0x0004      /* Exportado para namespace global */
#define OBJECT_FLAG_READONLY    0x0008      /* Somente leitura */
#define OBJECT_FLAG_VOLATILE    0x0010      /* Volátil (pode ser descartado) */
#define OBJECT_FLAG_PINNED      0x0020      /* Fixado na memória */
#define OBJECT_FLAG_NOGC        0x0040      /* Excluído de garbage collection */
#define OBJECT_FLAG_INITIALIZED 0x0080      /* Objeto inicializado */
#define OBJECT_FLAG_DESTROYING  0x0100      /* Em processo de destruição */
#define OBJECT_FLAG_FINALIZED   0x0200      /* Finalizado (não pode mais ser usado) */

/* Permissões de objeto */
#define OBJECT_PERM_NONE        0x0000
#define OBJECT_PERM_READ        0x0001
#define OBJECT_PERM_WRITE       0x0002
#define OBJECT_PERM_EXEC        0x0004
#define OBJECT_PERM_DELETE      0x0008
#define OBJECT_PERM_ADMIN       0x0010
#define OBJECT_PERM_OWNER       0x8000

/* Estados de objeto */
#define OBJECT_STATE_NEW        0
#define OBJECT_STATE_ACTIVE     1
#define OBJECT_STATE_SUSPENDED  2
#define OBJECT_STATE_DYING      3
#define OBJECT_STATE_DEAD       4

/* Referências */
#define OBJECT_REF_ROOT         1
#define OBJECT_REF_NAMESPACE    2
#define OBJECT_REF_HANDLE       3
#define OBJECT_REF_CALLBACK     4

/* ============================================================================
 * Estruturas de dados
 * ============================================================================ */

/* Forward declarations */
struct objectfs_object;
struct objectfs_namespace;
struct objectfs_handle;

/* Callbacks para tipos de objeto personalizados */
struct object_type_operations {
    /* Ciclo de vida */
    int (*init)(struct objectfs_object *obj, void *data, size_t len);
    void (*destroy)(struct objectfs_object *obj);
    int (*clone)(struct objectfs_object *src, struct objectfs_object *dst);
    
    /* Operações básicas */
    int (*read)(struct objectfs_object *obj, void *buf, size_t offset, size_t len);
    int (*write)(struct objectfs_object *obj, const void *buf, size_t offset, size_t len);
    int (*exec)(struct objectfs_object *obj, void *args, size_t args_len);
    
    /* Gerenciamento */
    int (*snapshot)(struct objectfs_object *obj, void *buf, size_t *len);
    int (*restore)(struct objectfs_object *obj, const void *buf, size_t len);
    size_t (*get_size)(struct objectfs_object *obj);
    
    /* Métricas */
    void (*get_stats)(struct objectfs_object *obj, void *stats, size_t stats_len);
    
    /* Callbacks de notificação */
    void (*on_reference)(struct objectfs_object *obj, int ref_type);
    void (*on_release)(struct objectfs_object *obj, int ref_type);
    void (*on_modify)(struct objectfs_object *obj);
};

/* Estrutura principal de objeto */
struct objectfs_object {
    u64 id;                                 /* ID único do objeto */
    u32 type;                               /* Tipo do objeto (OBJECT_TYPE_*) */
    u32 flags;                              /* Flags do objeto */
    u32 state;                              /* Estado atual */
    u32 permissions;                        /* Permissões */
    
    /* Nome e namespace */
    char name[256];                         /* Nome do objeto */
    struct objectfs_namespace *namespace;   /* Namespace pai */
    struct objectfs_object *parent;         /* Objeto pai (para hierarquia) */
    
    /* Dados específicos do objeto */
    union {
        /* Objetos Linux */
        struct {
            struct task_struct *task;
            struct mm_struct *mm;
            struct vm_area_struct *vma;
            struct file *file;
            struct inode *inode;
        } linux_obj;
        
        /* Objetos Mach */
        struct {
            task_t mach_task;
            thread_t mach_thread;
            mach_port_t mach_port;
            semaphore_t mach_semaphore;
            struct mutex *mach_mutex;
        } mach_obj;
        
        /* Objetos IPC */
        struct {
            void *ipc_buffer;
            size_t ipc_size;
            mach_msg_id_t msg_id;
        } ipc_obj;
        
        /* Objetos de memória */
        struct {
            void *memory_ptr;
            size_t memory_size;
            unsigned long memory_flags;
            struct page **pages;
            int nr_pages;
        } memory_obj;
        
        /* Dados personalizados */
        struct {
            void *private_data;
            size_t private_size;
            const struct object_type_operations *ops;
        } custom;
    } data;
    
    /* Referências */
    refcount_t refcount;                    /* Contagem de referências */
    atomic_t handle_count;                  /* Número de handles abertos */
    struct list_head reference_list;        /* Lista de referências externas */
    
    /* Callbacks */
    void (*destructor)(struct objectfs_object *obj);
    void (*notify)(struct objectfs_object *obj, u32 event, void *data);
    
    /* Sincronização */
    struct rw_semaphore sem;
    spinlock_t lock;
    struct mutex mutex;
    
    /* Métricas e estatísticas */
    u64 created_at;
    u64 accessed_at;
    u64 modified_at;
    u64 last_use;
    atomic64_t read_count;
    atomic64_t write_count;
    atomic64_t exec_count;
    
    /* Links para estruturas globais */
    struct rb_node name_node;               /* Nó na árvore por nome */
    struct hlist_node id_node;              /* Nó na hash por ID */
    struct list_head namespace_list;        /* Lista no namespace */
    struct rcu_head rcu;                    /* Para liberação RCU */
    
    /* Persistência */
    u64 persist_id;                         /* ID persistente (se houver) */
    void *persist_data;                     /* Dados persistentes */
    
    /* Debug */
    const char *creator_file;
    int creator_line;
    const char *creator_func;
};

/* Namespace hierárquico */
struct objectfs_namespace {
    u64 id;
    char name[128];
    struct objectfs_namespace *parent;
    struct list_head children;
    struct list_head objects;
    
    struct rb_root objects_by_name;
    DECLARE_HASHTABLE(objects_by_id, 16);
    
    struct rw_semaphore sem;
    spinlock_t lock;
    
    refcount_t refcount;
};

/* Handle para acesso a objeto */
struct objectfs_handle {
    u64 id;
    struct objectfs_object *object;
    u32 permissions;
    u64 opened_at;
    
    void *private_data;
    
    struct list_head list;
    struct rcu_head rcu;
};

/* Contexto de montagem */
struct objectfs_fs_context {
    struct objectfs_namespace *root_ns;
    size_t max_objects;
    size_t cache_size;
    int flags;
};

/* Estrutura superblock */
struct objectfs_sb_info {
    struct objectfs_namespace *root_namespace;
    struct kmem_cache *object_cache;
    struct kmem_cache *handle_cache;
    
    struct radix_tree_root objects_by_id;
    struct rb_root objects_by_name;
    
    struct mutex global_lock;
    struct rw_semaphore namespace_sem;
    
    atomic_t total_objects;
    atomic_t max_objects;
    atomic_t total_handles;
    
    size_t memory_used;
    size_t memory_limit;
    
    struct workqueue_struct *gc_wq;
    struct delayed_work gc_work;
    
    struct notifier_block oom_nb;
};

/* ============================================================================
 * Variáveis globais
 * ============================================================================ */

static struct file_system_type objectfs_type;
static struct objectfs_sb_info *objectfs_sb;
static DEFINE_MUTEX(objectfs_global_lock);

/* Tabela de tipos de objeto padrão */
static const struct object_type_operations generic_object_ops = {
    .init = NULL,
    .destroy = NULL,
    .clone = NULL,
    .read = NULL,
    .write = NULL,
    .exec = NULL,
    .snapshot = NULL,
    .restore = NULL,
    .get_size = NULL,
    .on_reference = NULL,
    .on_release = NULL,
    .on_modify = NULL,
};

/* ============================================================================
 * Funções auxiliares
 * ============================================================================ */

/* Gera ID único para objeto */
static inline u64 objectfs_generate_id(void)
{
    static atomic64_t next_id = ATOMIC64_INIT(1);
    u64 id = atomic64_inc_return(&next_id);
    /* Adiciona timestamp nos bits altos */
    return (ktime_get_real_ns() << 16) ^ (id & 0xFFFF);
}

/* Obtém timestamp atual */
static inline u64 objectfs_timestamp(void)
{
    return ktime_get_real_ns();
}

/* Verifica se objeto está vivo */
static inline bool objectfs_is_alive(struct objectfs_object *obj)
{
    return obj && (obj->state == OBJECT_STATE_ACTIVE ||
                   obj->state == OBJECT_STATE_SUSPENDED);
}

/* ============================================================================
 * Gerenciamento de referências
 * ============================================================================ */

/* Incrementa referência do objeto */
struct objectfs_object *objectfs_get_object(struct objectfs_object *obj)
{
    if (!obj || !objectfs_is_alive(obj))
        return NULL;
    
    if (refcount_inc_not_zero(&obj->refcount))
        return obj;
    
    return NULL;
}
EXPORT_SYMBOL(objectfs_get_object);

/* Decrementa referência do objeto */
void objectfs_put_object(struct objectfs_object *obj)
{
    if (!obj)
        return;
    
    if (refcount_dec_and_test(&obj->refcount)) {
        /* Marca para destruição */
        if (obj->state != OBJECT_STATE_DYING) {
            obj->state = OBJECT_STATE_DYING;
            obj->flags |= OBJECT_FLAG_DESTROYING;
            
            /* Callback de destruição */
            if (obj->destructor)
                obj->destructor(obj);
            
            /* Notifica destruição */
            if (obj->notify)
                obj->notify(obj, 0xDEAD, NULL);
            
            /* Remove de estruturas globais */
            if (obj->namespace) {
                /* Remove do namespace */
                /* ... */
            }
            
            /* Libera memória */
            kfree_rcu(obj, rcu);
        }
    }
}
EXPORT_SYMBOL(objectfs_put_object);

/* ============================================================================
 * Criação e destruição de objetos
 * ============================================================================ */

/* Cria um novo objeto */
struct objectfs_object *objectfs_create_object(u32 type, u32 flags,
                                                 const char *name,
                                                 struct objectfs_namespace *ns,
                                                 void *init_data, size_t init_len)
{
    struct objectfs_object *obj;
    int ret = 0;
    
    if (!ns)
        return ERR_PTR(-EINVAL);
    
    obj = kmem_cache_alloc(objectfs_sb->object_cache, GFP_KERNEL);
    if (!obj)
        return ERR_PTR(-ENOMEM);
    
    memset(obj, 0, sizeof(*obj));
    
    obj->id = objectfs_generate_id();
    obj->type = type;
    obj->flags = flags;
    obj->state = OBJECT_STATE_NEW;
    obj->permissions = OBJECT_PERM_OWNER | OBJECT_PERM_READ | OBJECT_PERM_WRITE;
    
    if (name)
        strscpy(obj->name, name, sizeof(obj->name));
    else
        snprintf(obj->name, sizeof(obj->name), "obj_%llx", obj->id);
    
    obj->namespace = ns;
    obj->created_at = objectfs_timestamp();
    obj->accessed_at = obj->created_at;
    obj->modified_at = obj->created_at;
    
    init_rwsem(&obj->sem);
    spin_lock_init(&obj->lock);
    mutex_init(&obj->mutex);
    refcount_set(&obj->refcount, 1);
    atomic_set(&obj->handle_count, 0);
    INIT_LIST_HEAD(&obj->reference_list);
    
    /* Dados específicos por tipo */
    switch (type) {
    case OBJECT_TYPE_GENERIC:
        /* Nada específico */
        break;
        
    case OBJECT_TYPE_MEMORY:
        if (init_data && init_len > 0) {
            obj->data.memory_obj.memory_ptr = kmalloc(init_len, GFP_KERNEL);
            if (obj->data.memory_obj.memory_ptr) {
                memcpy(obj->data.memory_obj.memory_ptr, init_data, init_len);
                obj->data.memory_obj.memory_size = init_len;
            } else {
                ret = -ENOMEM;
            }
        }
        break;
        
    case OBJECT_TYPE_CUSTOM:
        if (init_data && init_len > 0) {
            obj->data.custom.private_data = kmalloc(init_len, GFP_KERNEL);
            if (obj->data.custom.private_data) {
                memcpy(obj->data.custom.private_data, init_data, init_len);
                obj->data.custom.private_size = init_len;
            }
        }
        break;
        
    default:
        break;
    }
    
    if (ret == 0) {
        obj->state = OBJECT_STATE_ACTIVE;
        obj->flags |= OBJECT_FLAG_INITIALIZED;
        
        atomic_inc(&objectfs_sb->total_objects);
        objectfs_sb->memory_used += sizeof(*obj);
        
        /* Adiciona ao namespace */
        down_write(&ns->sem);
        list_add_tail(&obj->namespace_list, &ns->objects);
        /* Adiciona à árvore por nome */
        /* ... */
        up_write(&ns->sem);
    } else {
        kmem_cache_free(objectfs_sb->object_cache, obj);
        obj = ERR_PTR(ret);
    }
    
    return obj;
}
EXPORT_SYMBOL(objectfs_create_object);

/* Destrói um objeto */
int objectfs_destroy_object(struct objectfs_object *obj)
{
    if (!obj)
        return -EINVAL;
    
    if (!objectfs_is_alive(obj))
        return -ENOENT;
    
    down_write(&obj->sem);
    obj->state = OBJECT_STATE_DYING;
    
    /* Libera dados específicos */
    switch (obj->type) {
    case OBJECT_TYPE_MEMORY:
        if (obj->data.memory_obj.memory_ptr)
            kfree(obj->data.memory_obj.memory_ptr);
        break;
        
    case OBJECT_TYPE_CUSTOM:
        if (obj->data.custom.private_data)
            kfree(obj->data.custom.private_data);
        break;
    }
    
    up_write(&obj->sem);
    
    objectfs_put_object(obj);
    
    return 0;
}
EXPORT_SYMBOL(objectfs_destroy_object);

/* ============================================================================
 * Operações em objetos
 * ============================================================================ */

/* Lê dados de um objeto */
ssize_t objectfs_read_object(struct objectfs_object *obj, void *buf,
                              size_t offset, size_t len)
{
    ssize_t ret = -EINVAL;
    
    if (!obj || !buf)
        return -EINVAL;
    
    if (!objectfs_is_alive(obj))
        return -ENOENT;
    
    if (!(obj->permissions & OBJECT_PERM_READ))
        return -EACCES;
    
    down_read(&obj->sem);
    
    switch (obj->type) {
    case OBJECT_TYPE_GENERIC:
        /* Para objetos genéricos, retorna metadados */
        ret = min_t(size_t, len, sizeof(obj->id));
        memcpy(buf, &obj->id, ret);
        break;
        
    case OBJECT_TYPE_MEMORY:
        if (offset < obj->data.memory_obj.memory_size) {
            size_t available = obj->data.memory_obj.memory_size - offset;
            ret = min_t(size_t, len, available);
            memcpy(buf, (char *)obj->data.memory_obj.memory_ptr + offset, ret);
        } else {
            ret = 0;
        }
        break;
        
    default:
        if (obj->data.custom.ops && obj->data.custom.ops->read)
            ret = obj->data.custom.ops->read(obj, buf, offset, len);
        else
            ret = -ENOTSUPP;
        break;
    }
    
    if (ret > 0) {
        obj->accessed_at = objectfs_timestamp();
        atomic64_inc(&obj->read_count);
    }
    
    up_read(&obj->sem);
    
    return ret;
}
EXPORT_SYMBOL(objectfs_read_object);

/* Escreve dados em um objeto */
ssize_t objectfs_write_object(struct objectfs_object *obj, const void *buf,
                               size_t offset, size_t len)
{
    ssize_t ret = -EINVAL;
    
    if (!obj || !buf)
        return -EINVAL;
    
    if (!objectfs_is_alive(obj))
        return -ENOENT;
    
    if (!(obj->permissions & OBJECT_PERM_WRITE))
        return -EACCES;
    
    if (obj->flags & OBJECT_FLAG_READONLY)
        return -EROFS;
    
    down_write(&obj->sem);
    
    switch (obj->type) {
    case OBJECT_TYPE_MEMORY:
        if (offset + len > obj->data.memory_obj.memory_size) {
            /* Expande a alocação */
            size_t new_size = max(offset + len, obj->data.memory_obj.memory_size * 2);
            void *new_ptr = krealloc(obj->data.memory_obj.memory_ptr, new_size, GFP_KERNEL);
            if (new_ptr) {
                obj->data.memory_obj.memory_ptr = new_ptr;
                obj->data.memory_obj.memory_size = new_size;
            } else {
                ret = -ENOMEM;
                goto out;
            }
        }
        memcpy((char *)obj->data.memory_obj.memory_ptr + offset, buf, len);
        ret = len;
        break;
        
    default:
        if (obj->data.custom.ops && obj->data.custom.ops->write)
            ret = obj->data.custom.ops->write(obj, buf, offset, len);
        else
            ret = -ENOTSUPP;
        break;
    }
    
    if (ret > 0) {
        obj->modified_at = objectfs_timestamp();
        obj->accessed_at = obj->modified_at;
        atomic64_inc(&obj->write_count);
        
        if (obj->data.custom.ops && obj->data.custom.ops->on_modify)
            obj->data.custom.ops->on_modify(obj);
    }
    
out:
    up_write(&obj->sem);
    
    return ret;
}
EXPORT_SYMBOL(objectfs_write_object);

/* Executa uma operação em um objeto */
int objectfs_exec_object(struct objectfs_object *obj, void *args, size_t args_len)
{
    int ret = -EINVAL;
    
    if (!obj)
        return -EINVAL;
    
    if (!objectfs_is_alive(obj))
        return -ENOENT;
    
    if (!(obj->permissions & OBJECT_PERM_EXEC))
        return -EACCES;
    
    down_read(&obj->sem);
    
    switch (obj->type) {
    case OBJECT_TYPE_TASK:
        /* Executa uma operação na task */
        if (obj->data.linux_obj.task) {
            /* ... */
            ret = 0;
        }
        break;
        
    case OBJECT_TYPE_CUSTOM:
        if (obj->data.custom.ops && obj->data.custom.ops->exec)
            ret = obj->data.custom.ops->exec(obj, args, args_len);
        else
            ret = -ENOTSUPP;
        break;
        
    default:
        ret = -ENOTSUPP;
        break;
    }
    
    if (ret == 0) {
        atomic64_inc(&obj->exec_count);
    }
    
    up_read(&obj->sem);
    
    return ret;
}
EXPORT_SYMBOL(objectfs_exec_object);

/* ============================================================================
 * Handles e acesso via pathname
 * ============================================================================ */

/* Abre um objeto via pathname */
struct objectfs_handle *objectfs_open(const char *path, u32 permissions)
{
    struct objectfs_object *obj = NULL;
    struct objectfs_handle *handle;
    char *path_copy, *token, *saveptr;
    struct objectfs_namespace *ns;
    int ret = 0;
    
    if (!path || !objectfs_sb)
        return ERR_PTR(-EINVAL);
    
    path_copy = kstrdup(path, GFP_KERNEL);
    if (!path_copy)
        return ERR_PTR(-ENOMEM);
    
    ns = objectfs_sb->root_namespace;
    down_read(&objectfs_sb->namespace_sem);
    
    /* Parse do pathname */
    token = strtok_r(path_copy, "/", &saveptr);
    while (token && ns) {
        struct objectfs_object *found = NULL;
        
        /* Busca objeto no namespace */
        down_read(&ns->sem);
        list_for_each_entry(obj, &ns->objects, namespace_list) {
            if (strcmp(obj->name, token) == 0) {
                found = obj;
                break;
            }
        }
        up_read(&ns->sem);
        
        if (!found) {
            ret = -ENOENT;
            break;
        }
        
        obj = found;
        token = strtok_r(NULL, "/", &saveptr);
        
        /* Se é namespace e há mais tokens, continua */
        /* ... */
    }
    
    up_read(&objectfs_sb->namespace_sem);
    kfree(path_copy);
    
    if (ret < 0)
        return ERR_PTR(ret);
    
    if (!obj || !objectfs_is_alive(obj))
        return ERR_PTR(-ENOENT);
    
    /* Verifica permissões */
    if ((permissions & ~obj->permissions) != 0)
        return ERR_PTR(-EACCES);
    
    /* Cria handle */
    handle = kmem_cache_alloc(objectfs_sb->handle_cache, GFP_KERNEL);
    if (!handle)
        return ERR_PTR(-ENOMEM);
    
    handle->id = objectfs_generate_id();
    handle->object = objectfs_get_object(obj);
    handle->permissions = permissions;
    handle->opened_at = objectfs_timestamp();
    handle->private_data = NULL;
    
    atomic_inc(&objectfs_sb->total_handles);
    atomic_inc(&obj->handle_count);
    
    return handle;
}
EXPORT_SYMBOL(objectfs_open);

/* Fecha um handle */
void objectfs_close(struct objectfs_handle *handle)
{
    if (!handle || !handle->object)
        return;
    
    atomic_dec(&handle->object->handle_count);
    objectfs_put_object(handle->object);
    atomic_dec(&objectfs_sb->total_handles);
    
    kmem_cache_free(objectfs_sb->handle_cache, handle);
}
EXPORT_SYMBOL(objectfs_close);

/* ============================================================================
 * Namespace management
 * ============================================================================ */

/* Cria um novo namespace */
struct objectfs_namespace *objectfs_create_namespace(const char *name,
                                                       struct objectfs_namespace *parent)
{
    struct objectfs_namespace *ns;
    
    ns = kzalloc(sizeof(*ns), GFP_KERNEL);
    if (!ns)
        return ERR_PTR(-ENOMEM);
    
    ns->id = objectfs_generate_id();
    strscpy(ns->name, name ?: "unnamed", sizeof(ns->name));
    ns->parent = parent;
    INIT_LIST_HEAD(&ns->children);
    INIT_LIST_HEAD(&ns->objects);
    ns->objects_by_name = RB_ROOT;
    hash_init(ns->objects_by_id);
    init_rwsem(&ns->sem);
    spin_lock_init(&ns->lock);
    refcount_set(&ns->refcount, 1);
    
    if (parent) {
        down_write(&parent->sem);
        list_add_tail(&ns->children, &parent->children);
        up_write(&parent->sem);
    }
    
    return ns;
}
EXPORT_SYMBOL(objectfs_create_namespace);

/* Destrói um namespace */
void objectfs_destroy_namespace(struct objectfs_namespace *ns)
{
    struct objectfs_object *obj, *tmp;
    
    if (!ns)
        return;
    
    /* Destrói todos os objetos no namespace */
    down_write(&ns->sem);
    list_for_each_entry_safe(obj, tmp, &ns->objects, namespace_list) {
        objectfs_destroy_object(obj);
    }
    up_write(&ns->sem);
    
    /* Remove do pai */
    if (ns->parent) {
        down_write(&ns->parent->sem);
        list_del(&ns->children);
        up_write(&ns->parent->sem);
    }
    
    kfree(ns);
}
EXPORT_SYMBOL(objectfs_destroy_namespace);

/* ============================================================================
 * Garbage collection
 * ============================================================================ */

/* Trabalho de garbage collection */
static void objectfs_gc_work(struct work_struct *work)
{
    struct objectfs_sb_info *sb = container_of(work, struct objectfs_sb_info,
                                                gc_work.work);
    struct objectfs_namespace *ns = sb->root_namespace;
    struct objectfs_object *obj, *tmp;
    u64 now = objectfs_timestamp();
    u64 timeout = 60ULL * NSEC_PER_SEC;  /* 60 segundos */
    
    if (!ns)
        return;
    
    down_read(&ns->sem);
    list_for_each_entry_safe(obj, tmp, &ns->objects, namespace_list) {
        /* Objetos voláteis sem referências e não usados recentemente */
        if ((obj->flags & OBJECT_FLAG_VOLATILE) &&
            !(obj->flags & OBJECT_FLAG_NOGC) &&
            refcount_read(&obj->refcount) <= 1 &&
            (now - obj->last_use) > timeout) {
            
            objectfs_destroy_object(obj);
        }
    }
    up_read(&ns->sem);
    
    /* Reagenda */
    queue_delayed_work(sb->gc_wq, &sb->gc_work, HZ * 60);
}

/* ============================================================================
 * Interface de depuração via debugfs
 * ============================================================================ */

#ifdef CONFIG_DEBUG_FS

static int objectfs_debug_show(struct seq_file *m, void *v)
{
    struct objectfs_sb_info *sb = m->private;
    struct objectfs_namespace *ns;
    struct objectfs_object *obj;
    
    if (!sb)
        return 0;
    
    seq_printf(m, "ObjectFS Debug Information\n");
    seq_printf(m, "===========================\n\n");
    
    seq_printf(m, "Total objects:   %d\n",
               atomic_read(&sb->total_objects));
    seq_printf(m, "Total handles:   %d\n",
               atomic_read(&sb->total_handles));
    seq_printf(m, "Memory used:     %zu bytes\n",
               sb->memory_used);
    seq_printf(m, "Memory limit:    %zu bytes\n",
               sb->memory_limit);
    
    seq_printf(m, "\nObjects:\n");
    ns = sb->root_namespace;
    if (ns) {
        down_read(&ns->sem);
        list_for_each_entry(obj, &ns->objects, namespace_list) {
            seq_printf(m, "  [%s] id=%llx type=%u refs=%d state=%u\n",
                       obj->name, obj->id, obj->type,
                       refcount_read(&obj->refcount), obj->state);
        }
        up_read(&ns->sem);
    }
    
    return 0;
}

static int objectfs_debug_open(struct inode *inode, struct file *file)
{
    return single_open(file, objectfs_debug_show, inode->i_private);
}

static const struct file_operations objectfs_debug_fops = {
    .open = objectfs_debug_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

#endif /* CONFIG_DEBUG_FS */

/* ============================================================================
 * Filesystem VFS operations (mount/umount)
 * ============================================================================ */

static int objectfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct objectfs_fs_context *ctx = fc->fs_private;
    struct objectfs_sb_info *sbi;
    
    sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
    if (!sbi)
        return -ENOMEM;
    
    sb->s_fs_info = sbi;
    sb->s_magic = OBJECTFS_SUPER_MAGIC;
    sb->s_blocksize = PAGE_SIZE;
    sb->s_blocksize_bits = PAGE_SHIFT;
    
    /* Inicializa caches */
    sbi->object_cache = kmem_cache_create("objectfs_object",
                                           sizeof(struct objectfs_object),
                                           __alignof__(struct objectfs_object),
                                           SLAB_PANIC | SLAB_ACCOUNT,
                                           NULL);
    if (!sbi->object_cache)
        goto out_free;
    
    sbi->handle_cache = kmem_cache_create("objectfs_handle",
                                           sizeof(struct objectfs_handle),
                                           __alignof__(struct objectfs_handle),
                                           SLAB_PANIC,
                                           NULL);
    if (!sbi->handle_cache)
        goto out_destroy_object_cache;
    
    INIT_RADIX_TREE(&sbi->objects_by_id, GFP_KERNEL);
    sbi->objects_by_name = RB_ROOT;
    mutex_init(&sbi->global_lock);
    init_rwsem(&sbi->namespace_sem);
    atomic_set(&sbi->total_objects, 0);
    atomic_set(&sbi->max_objects, ctx->max_objects ?: 65536);
    atomic_set(&sbi->total_handles, 0);
    sbi->memory_used = 0;
    sbi->memory_limit = ctx->cache_size ?: (512 * 1024 * 1024);
    
    /* Cria namespace raiz */
    sbi->root_namespace = objectfs_create_namespace("root", NULL);
    if (IS_ERR(sbi->root_namespace)) {
        goto out_destroy_handle_cache;
    }
    
    /* Cria workqueue para GC */
    sbi->gc_wq = alloc_workqueue("objectfs_gc", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
    if (!sbi->gc_wq)
        goto out_destroy_namespace;
    
    INIT_DELAYED_WORK(&sbi->gc_work, objectfs_gc_work);
    queue_delayed_work(sbi->gc_wq, &sbi->gc_work, HZ * 60);
    
    objectfs_sb = sbi;
    
    return 0;

out_destroy_namespace:
    objectfs_destroy_namespace(sbi->root_namespace);
out_destroy_handle_cache:
    kmem_cache_destroy(sbi->handle_cache);
out_destroy_object_cache:
    kmem_cache_destroy(sbi->object_cache);
out_free:
    kfree(sbi);
    return -ENOMEM;
}

static void objectfs_kill_sb(struct super_block *sb)
{
    struct objectfs_sb_info *sbi = sb->s_fs_info;
    
    if (sbi) {
        cancel_delayed_work_sync(&sbi->gc_work);
        if (sbi->gc_wq)
            destroy_workqueue(sbi->gc_wq);
        
        objectfs_destroy_namespace(sbi->root_namespace);
        kmem_cache_destroy(sbi->object_cache);
        kmem_cache_destroy(sbi->handle_cache);
        kfree(sbi);
    }
    
    kill_litter_super(sb);
}

static int objectfs_init_fs_context(struct fs_context *fc)
{
    struct objectfs_fs_context *ctx;
    
    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;
    
    ctx->max_objects = 65536;
    ctx->cache_size = 512 * 1024 * 1024;
    ctx->flags = 0;
    
    fc->fs_private = ctx;
    fc->ops = &objectfs_fs_context_ops;
    
    return 0;
}

static const struct fs_context_operations objectfs_fs_context_ops = {
    .free = objectfs_free_fs_context,
    .parse_param = objectfs_parse_param,
    .get_tree = objectfs_get_tree,
};

static struct file_system_type objectfs_type = {
    .name = "objectfs",
    .init_fs_context = objectfs_init_fs_context,
    .kill_sb = objectfs_kill_sb,
    .fs_flags = FS_USERNS_MOUNT,
};

/* ============================================================================
 * Inicialização e finalização
 * ============================================================================ */

static int __init objectfs_init(void)
{
    int ret;
    
    printk(KERN_INFO "ObjectFS: Initializing object filesystem\n");
    
    ret = register_filesystem(&objectfs_type);
    if (ret) {
        printk(KERN_ERR "ObjectFS: Failed to register filesystem\n");
        return ret;
    }
    
#ifdef CONFIG_DEBUG_FS
    debugfs_create_file("objectfs", 0444, NULL, NULL, &objectfs_debug_fops);
#endif
    
    printk(KERN_INFO "ObjectFS: Initialized successfully\n");
    
    return 0;
}

static void __exit objectfs_exit(void)
{
    printk(KERN_INFO "ObjectFS: Shutting down\n");
    
    unregister_filesystem(&objectfs_type);
    
#ifdef CONFIG_DEBUG_FS
    debugfs_remove(NULL);
#endif
    
    printk(KERN_INFO "ObjectFS: Shut down\n");
}

module_init(objectfs_init);
module_exit(objectfs_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LIH Project");
MODULE_DESCRIPTION("ObjectFS - In-memory object filesystem for LIH");
MODULE_VERSION("1.0");
MODULE_ALIAS_FS("objectfs");
