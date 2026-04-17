/*
 * linux/kernel/vfs.c - LIH Virtual Object System
 * 
 * Sistema de gerenciamento de objetos com filosofia "tudo é objeto"
 * (não "tudo é arquivo").
 * 
 * Características:
 *   - Objetos em vez de arquivos (objetos podem ser tasks, ports, memória, etc)
 *   - Paths no estilo Windows: "C:\", "D:\Pasta\Objeto"
 *   - Case-insensitive: "ABC" e "abc" são o mesmo objeto
 *   - Múltiplas unidades (A:, B:, C:, etc)
 *   - Namespace hierárquico com objetos e containers
 *   - Objetos podem ser montados/desmontados
 *   - Suporte a symlinks (objetos de referência)
 *   - Suporte a hardlinks (múltiplos nomes para o mesmo objeto)
 *   - ACLs e permissões estendidas
 *   - Notificações de mudança (ReadDirectoryChangesW-like)
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
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/hashtable.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/random.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/rcupdate.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/fsnotify.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

/* Headers do GNU Mach */
#include <mach/mach_types.h>

/* ============================================================================
 * Constantes e definições
 * ============================================================================ */

/* Letras de unidade suportadas (A: a Z:) */
#define LIH_DRIVE_LETTER_MIN    'A'
#define LIH_DRIVE_LETTER_MAX    'Z'
#define LIH_DRIVE_COUNT         (LIH_DRIVE_LETTER_MAX - LIH_DRIVE_LETTER_MIN + 1)

/* Tipos de objeto */
#define LIH_OBJ_TYPE_NONE       0x0000
#define LIH_OBJ_TYPE_CONTAINER  0x0001   /* Diretório/Container (pode conter objetos) */
#define LIH_OBJ_TYPE_OBJECT     0x0002   /* Objeto genérico */
#define LIH_OBJ_TYPE_SYMLINK    0x0003   /* Link simbólico */
#define LIH_OBJ_TYPE_HARDLINK   0x0004   /* Hard link */
#define LIH_OBJ_TYPE_DEVICE     0x0005   /* Dispositivo */
#define LIH_OBJ_TYPE_PIPE       0x0006   /* Pipe */
#define LIH_OBJ_TYPE_SOCKET     0x0007   /* Socket */
#define LIH_OBJ_TYPE_TASK       0x0008   /* Task/Processo */
#define LIH_OBJ_TYPE_THREAD     0x0009   /* Thread */
#define LIH_OBJ_TYPE_PORT       0x000A   /* Mach port */
#define LIH_OBJ_TYPE_MEMORY     0x000B   /* Região de memória */
#define LIH_OBJ_TYPE_SEMAPHORE  0x000C   /* Semáforo */
#define LIH_OBJ_TYPE_MUTEX      0x000D   /* Mutex */
#define LIH_OBJ_TYPE_EVENT      0x000E   /* Evento */
#define LIH_OBJ_TYPE_TIMER      0x000F   /* Timer */
#define LIH_OBJ_TYPE_SHARED_MEM 0x0010   /* Memória compartilhada */
#define LIH_OBJ_TYPE_CUSTOM     0x8000   /* Tipo personalizado */

/* Flags de objeto */
#define LIH_OBJ_FLAG_READONLY   0x0001   /* Somente leitura */
#define LIH_OBJ_FLAG_HIDDEN     0x0002   /* Oculto */
#define LIH_OBJ_FLAG_SYSTEM     0x0004   /* Objeto do sistema */
#define LIH_OBJ_FLAG_ARCHIVE    0x0008   /* Arquivo (para backup) */
#define LIH_OBJ_FLAG_TEMPORARY  0x0010   /* Temporário */
#define LIH_OBJ_FLAG_COMPRESSED 0x0020   /* Comprimido */
#define LIH_OBJ_FLAG_ENCRYPTED  0x0040   /* Criptografado */
#define LIH_OBJ_FLAG_IMMUTABLE  0x0080   /* Imutável (não pode ser modificado) */
#define LIH_OBJ_FLAG_APPEND_ONLY 0x0100  /* Append only */
#define LIH_OBJ_FLAG_NO_CACHE   0x0200   /* Não usar cache */
#define LIH_OBJ_FLAG_VOLATILE   0x0400   /* Volátil (desaparece no reboot) */
#define LIH_OBJ_FLAG_PERSISTENT 0x0800   /* Persistente */
#define LIH_OBJ_FLAG_MOUNTPOINT 0x1000   /* Ponto de montagem */

/* Permissões de objeto (ACL estilo Windows) */
#define LIH_OBJ_PERM_NONE       0x00000000
#define LIH_OBJ_PERM_READ       0x00000001   /* Leitura */
#define LIH_OBJ_PERM_WRITE      0x00000002   /* Escrita */
#define LIH_OBJ_PERM_EXECUTE    0x00000004   /* Execução */
#define LIH_OBJ_PERM_DELETE     0x00000008   /* Deleção */
#define LIH_OBJ_PERM_LIST       0x00000010   /* Listar conteúdo (container) */
#define LIH_OBJ_PERM_TRAVERSE   0x00000020   /* Atravessar container */
#define LIH_OBJ_PERM_READ_ATTR  0x00000040   /* Ler atributos */
#define LIH_OBJ_PERM_WRITE_ATTR 0x00000080   /* Escrever atributos */
#define LIH_OBJ_PERM_READ_ACL   0x00000100   /* Ler ACL */
#define LIH_OBJ_PERM_WRITE_ACL  0x00000200   /* Escrever ACL */
#define LIH_OBJ_PERM_OWNER      0x00000400   /* Tomar posse */
#define LIH_OBJ_PERM_SYNCHRONIZE 0x00000800  /* Sincronização */
#define LIH_OBJ_PERM_FULL_CONTROL 0x00000FFF /* Controle total */

/* ACE (Access Control Entry) tipos */
#define LIH_ACE_TYPE_ALLOW      0x00
#define LIH_ACE_TYPE_DENY       0x01
#define LIH_ACE_TYPE_AUDIT      0x02
#define LIH_ACE_TYPE_ALARM      0x03

/* Notificações de mudança */
#define LIH_NOTIFY_FILE_NAME    0x0001   /* Nome do arquivo mudou */
#define LIH_NOTIFY_DIR_NAME     0x0002   /* Nome do diretório mudou */
#define LIH_NOTIFY_ATTRIBUTES   0x0004   /* Atributos mudaram */
#define LIH_NOTIFY_SIZE         0x0008   /* Tamanho mudou */
#define LIH_NOTIFY_LAST_WRITE   0x0010   /* Última escrita mudou */
#define LIH_NOTIFY_LAST_ACCESS  0x0020   /* Último acesso mudou */
#define LIH_NOTIFY_CREATION     0x0040   /* Objeto criado */
#define LIH_NOTIFY_DELETE       0x0080   /* Objeto deletado */
#define LIH_NOTIFY_RENAME       0x0100   /* Objeto renomeado */
#define LIH_NOTIFY_SECURITY     0x0200   /* Segurança mudou */
#define LIH_NOTIFY_ALL          0x0FFF   /* Todas as notificações */

/* Máximo do sistema */
#define LIH_MAX_PATH            32768    /* Caminho máximo (Windows: 32767) */
#define LIH_MAX_OBJECT_NAME     255      /* Nome máximo de objeto */
#define LIH_MAX_OBJECTS_PER_DIR 1048576  /* Máximo objetos por diretório */
#define LIH_MAX_OPEN_HANDLES    65536    /* Máximo handles abertos */
#define LIH_MAX_SYMLINK_DEPTH   32       /* Profundidade máxima de symlinks */

/* ============================================================================
 * Estruturas de dados
 * ============================================================================ */

/* Forward declarations */
struct lih_object;
struct lih_container;
struct lih_handle;
struct lih_acl_entry;
struct lih_notify_entry;

/* ACE (Access Control Entry) */
struct lih_ace {
    u32 type;                       /* LIH_ACE_TYPE_* */
    u32 flags;
    u32 mask;                       /* LIH_OBJ_PERM_* */
    uid_t uid;                      /* Usuário ou grupo */
    gid_t gid;
    struct list_head list;
};

/* ACL (Access Control List) */
struct lih_acl {
    struct list_head entries;
    atomic_t refcount;
    spinlock_t lock;
};

/* Timestamps (estilo Windows) */
struct lih_timestamps {
    u64 creation_time;              /* FileTime (100ns desde 1601-01-01) */
    u64 last_access_time;
    u64 last_write_time;
    u64 change_time;
};

/* Atributos estendidos */
struct lih_ea {
    char name[64];
    void *data;
    size_t size;
    struct list_head list;
};

/* Notificação de mudança */
struct lih_notify_entry {
    u32 filter;
    u32 action;
    char name[LIH_MAX_OBJECT_NAME];
    u64 timestamp;
    struct lih_object *target;
    struct list_head list;
};

/* Handle para objeto aberto */
struct lih_handle {
    u64 id;
    struct lih_object *obj;
    u32 desired_access;
    u32 share_mode;
    u32 flags;
    u64 creation_time;
    pid_t pid;
    struct task_struct *task;
    struct list_head list;
    atomic_t refcount;
    spinlock_t lock;
};

/* Objeto base (todos os objetos herdam isso) */
struct lih_object {
    u64 id;                         /* ID único do objeto */
    u32 type;                       /* LIH_OBJ_TYPE_* */
    u32 flags;                      /* LIH_OBJ_FLAG_* */
    char name[LIH_MAX_OBJECT_NAME]; /* Nome do objeto (case-insensitive) */
    
    /* Hierarquia */
    struct lih_container *parent;   /* Container pai */
    struct lih_drive *drive;        /* Unidade que contém o objeto */
    
    /* Permissões e segurança */
    struct lih_acl *acl;
    uid_t owner_uid;
    gid_t owner_gid;
    u32 default_perms;
    
    /* Timestamps */
    struct lih_timestamps timestamps;
    
    /* Tamanho (para objetos que têm tamanho) */
    u64 size;
    u64 allocated_size;
    
    /* Atributos estendidos */
    struct list_head ea_list;
    spinlock_t ea_lock;
    
    /* Dados específicos do tipo */
    union {
        /* Container (diretório) */
        struct {
            struct rb_root children;        /* Objetos filhos por nome */
            struct list_head child_list;    /* Lista de objetos filhos */
            u32 child_count;
            struct lih_object *parent_obj;
        } container;
        
        /* Objeto genérico */
        struct {
            void *data;
            size_t data_size;
            void *private;
        } generic;
        
        /* Symlink */
        struct {
            char target_path[LIH_MAX_PATH];
            struct lih_object *target_obj;
        } symlink;
        
        /* Hardlink */
        struct {
            struct lih_object *target_obj;
        } hardlink;
        
        /* Task/Processo */
        struct {
            struct task_struct *task;
            pid_t pid;
            char comm[TASK_COMM_LEN];
        } task;
        
        /* Thread */
        struct {
            struct task_struct *thread;
            pid_t tid;
            struct lih_object *parent_task;
        } thread;
        
        /* Mach port */
        struct {
            mach_port_t port;
            char port_name[64];
        } port;
        
        /* Memória */
        struct {
            void *address;
            size_t size;
            unsigned long flags;
        } memory;
        
        /* Sincronização */
        struct {
            struct mutex *mutex;
            struct semaphore *sem;
            struct completion *completion;
        } sync;
        
        /* Timer */
        struct {
            struct timer_list timer;
            u64 interval_ns;
            u64 expiry_time;
        } timer;
        
        /* Dados personalizados */
        struct {
            void *private_data;
            void (*dtor)(void *);
        } custom;
    } specific;
    
    /* Notificações */
    struct list_head notify_list;
    spinlock_t notify_lock;
    
    /* Handles abertos */
    struct list_head handles;
    atomic_t handle_count;
    
    /* Callbacks */
    int (*open)(struct lih_object *obj, struct lih_handle *handle);
    int (*close)(struct lih_handle *handle);
    ssize_t (*read)(struct lih_handle *handle, void *buf, size_t offset, size_t len);
    ssize_t (*write)(struct lih_handle *handle, const void *buf, size_t offset, size_t len);
    int (*ioctl)(struct lih_handle *handle, u32 cmd, void *arg);
    int (*delete)(struct lih_object *obj);
    int (*rename)(struct lih_object *obj, const char *new_name);
    
    /* Sincronização */
    struct rw_semaphore rwsem;
    spinlock_t lock;
    atomic_t refcount;
    struct rcu_head rcu;
    
    /* Estatísticas */
    u64 access_count;
    u64 modify_count;
    u64 last_access_pid;
};

/* Unidade (drive) - A:, B:, C:, etc */
struct lih_drive {
    char letter;                    /* Letra da unidade (A-Z) */
    char name[8];                   /* "C:", "D:", etc */
    struct lih_container *root;     /* Objeto raiz da unidade */
    u32 flags;
    u32 type;                       /* Local, removable, network, ram */
    u64 total_space;
    u64 free_space;
    char volume_label[64];
    char volume_serial[32];
    struct list_head list;
    spinlock_t lock;
    atomic_t refcount;
};

/* VFS principal */
struct lih_vfs {
    /* Unidades montadas */
    struct lih_drive *drives[LIH_DRIVE_COUNT];
    struct list_head drive_list;
    struct mutex drive_lock;
    
    /* Objetos globais */
    struct lih_container *global_root;
    struct lih_object *system_object;
    
    /* Handles abertos */
    struct idr handles;
    spinlock_t handle_lock;
    atomic_t handle_count;
    
    /* Estatísticas */
    struct {
        atomic64_t total_objects;
        atomic64_t total_containers;
        atomic64_t total_handles_opened;
        atomic64_t total_handles_closed;
        atomic64_t total_accesses;
        atomic64_t total_modifications;
        atomic64_t total_errors;
    } stats;
    
    /* Cache de path (resolução de paths) */
    struct kmem_cache *object_cache;
    struct kmem_cache *container_cache;
    struct kmem_cache *handle_cache;
    struct kmem_cache *ace_cache;
    struct kmem_cache *ea_cache;
    
    /* Configuração */
    struct {
        int case_insensitive;       /* 1 = case-insensitive */
        int preserve_case;          /* 1 = preserva case original */
        int long_paths;             /* 1 = suporta paths longos */
        int acl_enabled;            /* 1 = ACL ativado */
        int notify_enabled;         /* 1 = notificações ativadas */
    } config;
    
    /* Sincronização global */
    struct mutex global_lock;
    
    /* Debug */
    struct dentry *debugfs_root;
    struct proc_dir_entry *proc_entry;
};

/* ============================================================================
 * Variáveis globais
 * ============================================================================ */

static struct lih_vfs *lih_vfs;
static DEFINE_MUTEX(lih_vfs_global_lock);

/* Tabela de letras de unidade */
static const char drive_letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/* ============================================================================
 * Funções auxiliares
 * ============================================================================ */

/* Converte string para lowercase (case-insensitive) */
static void lih_str_lower(char *dst, const char *src, size_t len)
{
    size_t i;
    for (i = 0; i < len && src[i]; i++) {
        dst[i] = tolower(src[i]);
    }
    if (i < len)
        dst[i] = '\0';
}

/* Compara duas strings case-insensitive */
static int lih_strcmp_ci(const char *a, const char *b)
{
    return strcasecmp(a, b);
}

/* Compara duas strings case-insensitive com tamanho */
static int lih_strncmp_ci(const char *a, const char *b, size_t n)
{
    return strncasecmp(a, b, n);
}

/* Hash para nome case-insensitive */
static u32 lih_hash_name(const char *name)
{
    u32 hash = 0;
    while (*name) {
        hash = hash * 31 + tolower(*name);
        name++;
    }
    return hash;
}

/* Normaliza path (converte para lowercase, remove trailing slashes) */
static int lih_normalize_path(const char *path, char *normalized, size_t len)
{
    char *p = normalized;
    const char *s = path;
    int had_slash = 0;
    
    if (!path || !normalized || len < 2)
        return -EINVAL;
    
    /* Verifica se tem letra de unidade */
    if (isalpha(s[0]) && s[1] == ':') {
        *p++ = toupper(s[0]);
        *p++ = ':';
        s += 2;
        
        if (*s == '\\' || *s == '/')
            s++;
    }
    
    /* Normaliza o resto do path */
    while (*s && (size_t)(p - normalized) < len - 1) {
        if (*s == '\\' || *s == '/') {
            if (!had_slash) {
                *p++ = '\\';
                had_slash = 1;
            }
        } else {
            *p++ = tolower(*s);
            had_slash = 0;
        }
        s++;
    }
    
    /* Remove trailing slash se não for raiz */
    if (p > normalized + 2 && *(p - 1) == '\\')
        p--;
    
    *p = '\0';
    
    /* Garante que tem um path mínimo */
    if (p == normalized)
        return -EINVAL;
    
    return 0;
}

/* Divide path em drive e path relativo */
static int lih_split_path(const char *path, char *drive, char *relpath, size_t maxlen)
{
    const char *p = path;
    
    if (!path || !drive || !relpath)
        return -EINVAL;
    
    /* Extrai letra da unidade */
    if (isalpha(p[0]) && p[1] == ':') {
        drive[0] = toupper(p[0]);
        drive[1] = ':';
        drive[2] = '\0';
        p += 2;
        
        if (*p == '\\' || *p == '/')
            p++;
    } else {
        /* Sem letra de unidade, assume unidade atual */
        drive[0] = '\0';
    }
    
    /* Copia path relativo */
    strscpy(relpath, p, maxlen);
    
    return 0;
}

/* Converte FileTime (100ns desde 1601) para timestamp do kernel */
static u64 lih_filetime_to_kernel(u64 filetime)
{
    /* Diferença entre 1601-01-01 e 1970-01-01 em 100ns */
    const u64 EPOCH_DIFF = 116444736000000000ULL;
    return (filetime - EPOCH_DIFF) / 10;
}

/* Converte timestamp do kernel para FileTime */
static u64 lih_kernel_to_filetime(u64 ns)
{
    const u64 EPOCH_DIFF = 116444736000000000ULL;
    return ns * 10 + EPOCH_DIFF;
}

/* Gera ID único */
static u64 lih_generate_id(void)
{
    static atomic64_t next_id = ATOMIC64_INIT(1);
    return atomic64_inc_return(&next_id);
}

/* ============================================================================
 * Gerenciamento de objetos
 * ============================================================================ */

/* Cria um novo objeto */
static struct lih_object *lih_object_alloc(u32 type, const char *name, 
                                             struct lih_container *parent)
{
    struct lih_object *obj;
    char lower_name[LIH_MAX_OBJECT_NAME];
    
    obj = kmem_cache_alloc(lih_vfs->object_cache, GFP_KERNEL);
    if (!obj)
        return ERR_PTR(-ENOMEM);
    
    memset(obj, 0, sizeof(*obj));
    
    obj->id = lih_generate_id();
    obj->type = type;
    obj->flags = LIH_OBJ_FLAG_VOLATILE;
    obj->parent = parent;
    
    /* Normaliza nome (case-insensitive storage) */
    lih_str_lower(lower_name, name ?: "unnamed", sizeof(lower_name));
    strscpy(obj->name, lower_name, sizeof(obj->name));
    
    /* Timestamps */
    u64 now = lih_kernel_to_filetime(ktime_get_real_ns());
    obj->timestamps.creation_time = now;
    obj->timestamps.last_access_time = now;
    obj->timestamps.last_write_time = now;
    obj->timestamps.change_time = now;
    
    /* Permissões padrão */
    obj->owner_uid = current_uid().val;
    obj->owner_gid = current_gid().val;
    obj->default_perms = LIH_OBJ_PERM_FULL_CONTROL;
    
    INIT_LIST_HEAD(&obj->ea_list);
    INIT_LIST_HEAD(&obj->notify_list);
    INIT_LIST_HEAD(&obj->handles);
    init_rwsem(&obj->rwsem);
    spin_lock_init(&obj->lock);
    spin_lock_init(&obj->ea_lock);
    spin_lock_init(&obj->notify_lock);
    atomic_set(&obj->refcount, 1);
    atomic_set(&obj->handle_count, 0);
    
    /* Inicializa parte específica do tipo */
    if (type == LIH_OBJ_TYPE_CONTAINER) {
        obj->specific.container.children = RB_ROOT;
        INIT_LIST_HEAD(&obj->specific.container.child_list);
        obj->specific.container.child_count = 0;
    }
    
    return obj;
}

/* Incrementa referência do objeto */
static struct lih_object *lih_object_get(struct lih_object *obj)
{
    if (obj && atomic_inc_not_zero(&obj->refcount))
        return obj;
    return NULL;
}

/* Decrementa referência do objeto */
static void lih_object_put(struct lih_object *obj)
{
    if (!obj)
        return;
    
    if (atomic_dec_and_test(&obj->refcount)) {
        /* Notifica mudança */
        /* Libera ACL */
        if (obj->acl && atomic_dec_and_test(&obj->acl->refcount)) {
            struct lih_ace *ace, *tmp;
            list_for_each_entry_safe(ace, tmp, &obj->acl->entries, list) {
                list_del(&ace->list);
                kmem_cache_free(lih_vfs->ace_cache, ace);
            }
            kfree(obj->acl);
        }
        
        /* Libera atributos estendidos */
        struct lih_ea *ea, *ea_tmp;
        list_for_each_entry_safe(ea, ea_tmp, &obj->ea_list, list) {
            list_del(&ea->list);
            kfree(ea->data);
            kmem_cache_free(lih_vfs->ea_cache, ea);
        }
        
        /* Libera dados específicos */
        if (obj->type == LIH_OBJ_TYPE_CUSTOM && obj->specific.custom.dtor) {
            obj->specific.custom.dtor(obj->specific.custom.private_data);
        }
        
        kmem_cache_free(lih_vfs->object_cache, obj);
    }
}

/* ============================================================================
 * Gerenciamento de containers (diretórios)
 * ============================================================================ */

/* Busca objeto por nome em um container (case-insensitive) */
static struct lih_object *lih_container_find(struct lih_container *container,
                                              const char *name)
{
    struct rb_node *node = container->specific.container.children.rb_node;
    char lower_name[LIH_MAX_OBJECT_NAME];
    struct lih_object *obj;
    
    if (!container)
        return NULL;
    
    lih_str_lower(lower_name, name, sizeof(lower_name));
    
    while (node) {
        obj = rb_entry(node, struct lih_object, specific.container.node);
        int cmp = strcmp(obj->name, lower_name);
        
        if (cmp < 0)
            node = node->rb_left;
        else if (cmp > 0)
            node = node->rb_right;
        else
            return obj;
    }
    
    return NULL;
}

/* Insere objeto em um container */
static int lih_container_insert(struct lih_container *container,
                                 struct lih_object *obj)
{
    struct rb_node **new = &container->specific.container.children.rb_node;
    struct rb_node *parent = NULL;
    struct lih_object *existing;
    char *name = obj->name;
    
    while (*new) {
        parent = *new;
        existing = rb_entry(parent, struct lih_object, specific.container.node);
        int cmp = strcmp(existing->name, name);
        
        if (cmp < 0)
            new = &parent->rb_left;
        else if (cmp > 0)
            new = &parent->rb_right;
        else
            return -EEXIST;
    }
    
    rb_link_node(&obj->specific.container.node, parent, new);
    rb_insert_color(&obj->specific.container.node, 
                     &container->specific.container.children);
    list_add_tail(&obj->specific.container.list_entry, 
                   &container->specific.container.child_list);
    container->specific.container.child_count++;
    
    return 0;
}

/* Remove objeto de um container */
static void lih_container_remove(struct lih_container *container,
                                  struct lih_object *obj)
{
    rb_erase(&obj->specific.container.node, 
              &container->specific.container.children);
    list_del(&obj->specific.container.list_entry);
    container->specific.container.child_count--;
}

/* ============================================================================
 * Gerenciamento de unidades (drives)
 * ============================================================================ */

/* Monta uma unidade */
static int lih_mount_drive(char letter, const char *volume_label, u32 type)
{
    struct lih_drive *drive;
    struct lih_container *root;
    int idx;
    
    if (!lih_vfs)
        return -ENODEV;
    
    if (letter < LIH_DRIVE_LETTER_MIN || letter > LIH_DRIVE_LETTER_MAX)
        return -EINVAL;
    
    idx = letter - LIH_DRIVE_LETTER_MIN;
    
    mutex_lock(&lih_vfs->drive_lock);
    
    if (lih_vfs->drives[idx]) {
        mutex_unlock(&lih_vfs->drive_lock);
        return -EBUSY;
    }
    
    /* Cria objeto raiz da unidade */
    root = (struct lih_container *)lih_object_alloc(LIH_OBJ_TYPE_CONTAINER,
                                                      "\\", NULL);
    if (IS_ERR(root)) {
        mutex_unlock(&lih_vfs->drive_lock);
        return PTR_ERR(root);
    }
    
    /* Cria unidade */
    drive = kzalloc(sizeof(*drive), GFP_KERNEL);
    if (!drive) {
        lih_object_put((struct lih_object *)root);
        mutex_unlock(&lih_vfs->drive_lock);
        return -ENOMEM;
    }
    
    drive->letter = letter;
    snprintf(drive->name, sizeof(drive->name), "%c:", letter);
    drive->root = root;
    drive->type = type;
    drive->flags = 0;
    drive->total_space = 1024ULL * 1024 * 1024 * 1024; /* 1TB padrão */
    drive->free_space = drive->total_space;
    strscpy(drive->volume_label, volume_label ?: "Local Disk", 
            sizeof(drive->volume_label));
    spin_lock_init(&drive->lock);
    atomic_set(&drive->refcount, 1);
    
    lih_vfs->drives[idx] = drive;
    list_add_tail(&drive->list, &lih_vfs->drive_list);
    
    mutex_unlock(&lih_vfs->drive_lock);
    
    lih_info(LIH_LOG_INFO, "VFS: Mounted %c: \"%s\"\n", 
             letter, drive->volume_label);
    
    return 0;
}

/* Desmonta uma unidade */
static int lih_umount_drive(char letter)
{
    struct lih_drive *drive;
    int idx;
    
    if (!lih_vfs)
        return -ENODEV;
    
    if (letter < LIH_DRIVE_LETTER_MIN || letter > LIH_DRIVE_LETTER_MAX)
        return -EINVAL;
    
    idx = letter - LIH_DRIVE_LETTER_MIN;
    
    mutex_lock(&lih_vfs->drive_lock);
    
    drive = lih_vfs->drives[idx];
    if (!drive) {
        mutex_unlock(&lih_vfs->drive_lock);
        return -ENODEV;
    }
    
    lih_vfs->drives[idx] = NULL;
    list_del(&drive->list);
    
    mutex_unlock(&lih_vfs->drive_lock);
    
    lih_object_put((struct lih_object *)drive->root);
    kfree(drive);
    
    lih_info(LIH_LOG_INFO, "VFS: Unmounted %c:\n", letter);
    
    return 0;
}

/* Obtém unidade por letra */
static struct lih_drive *lih_get_drive(char letter)
{
    int idx;
    
    if (!lih_vfs)
        return NULL;
    
    if (letter < LIH_DRIVE_LETTER_MIN || letter > LIH_DRIVE_LETTER_MAX)
        return NULL;
    
    idx = letter - LIH_DRIVE_LETTER_MIN;
    
    return lih_vfs->drives[idx];
}

/* ============================================================================
 * Resolução de paths
 * ============================================================================ */

/* Resolve um path para um objeto */
static struct lih_object *lih_resolve_path(const char *path, 
                                             struct lih_drive **out_drive)
{
    struct lih_drive *drive = NULL;
    struct lih_container *current;
    struct lih_object *obj = NULL;
    char normalized[LIH_MAX_PATH];
    char drive_letter[8];
    char relpath[LIH_MAX_PATH];
    char *token, *saveptr;
    char workpath[LIH_MAX_PATH];
    int ret;
    
    if (!path || !lih_vfs)
        return ERR_PTR(-EINVAL);
    
    /* Normaliza path */
    ret = lih_normalize_path(path, normalized, sizeof(normalized));
    if (ret < 0)
        return ERR_PTR(ret);
    
    /* Divide em drive e path relativo */
    ret = lih_split_path(normalized, drive_letter, relpath, sizeof(relpath));
    if (ret < 0)
        return ERR_PTR(ret);
    
    /* Obtém unidade */
    if (drive_letter[0]) {
        drive = lih_get_drive(drive_letter[0]);
        if (!drive)
            return ERR_PTR(-ENOENT);
    } else {
        /* Sem letra de unidade - usa unidade padrão (C:) */
        drive = lih_get_drive('C');
        if (!drive)
            return ERR_PTR(-ENOENT);
    }
    
    if (out_drive)
        *out_drive = drive;
    
    /* Começa na raiz da unidade */
    current = drive->root;
    lih_object_get((struct lih_object *)current);
    
    /* Se path é apenas a raiz */
    if (relpath[0] == '\0') {
        return (struct lih_object *)current;
    }
    
    /* Tokeniza o path */
    strscpy(workpath, relpath, sizeof(workpath));
    
    token = strtok_r(workpath, "\\", &saveptr);
    while (token) {
        struct lih_object *next;
        
        /* Busca próximo objeto no container atual */
        next = lih_container_find(current, token);
        if (!next) {
            lih_object_put((struct lih_object *)current);
            return ERR_PTR(-ENOENT);
        }
        
        lih_object_get(next);
        lih_object_put((struct lih_object *)current);
        current = (struct lih_container *)next;
        
        /* Resolve symlinks */
        if (next->type == LIH_OBJ_TYPE_SYMLINK && next->specific.symlink.target_obj) {
            /* Segue symlink recursivamente */
            struct lih_object *target = next->specific.symlink.target_obj;
            lih_object_get(target);
            lih_object_put(next);
            current = (struct lih_container *)target;
        }
        
        token = strtok_r(NULL, "\\", &saveptr);
    }
    
    return (struct lih_object *)current;
}

/* ============================================================================
 * Operações em objetos
 * ============================================================================ */

/* Cria um novo objeto em um container */
static int lih_create_object(const char *path, u32 type, const char *name,
                              void *init_data, size_t init_size)
{
    struct lih_drive *drive;
    struct lih_object *parent;
    struct lih_object *obj;
    char parent_path[LIH_MAX_PATH];
    char *last_slash;
    int ret;
    
    if (!path || !name)
        return -EINVAL;
    
    /* Separa path do container pai */
    strscpy(parent_path, path, sizeof(parent_path));
    last_slash = strrchr(parent_path, '\\');
    if (last_slash) {
        *last_slash = '\0';
    } else {
        parent_path[0] = '\0';
    }
    
    /* Resolve container pai */
    parent = lih_resolve_path(parent_path[0] ? parent_path : "\\", &drive);
    if (IS_ERR(parent))
        return PTR_ERR(parent);
    
    if (parent->type != LIH_OBJ_TYPE_CONTAINER) {
        lih_object_put(parent);
        return -ENOTDIR;
    }
    
    /* Verifica se objeto já existe */
    if (lih_container_find((struct lih_container *)parent, name)) {
        lih_object_put(parent);
        return -EEXIST;
    }
    
    /* Cria objeto */
    obj = lih_object_alloc(type, name, (struct lih_container *)parent);
    if (IS_ERR(obj)) {
        lih_object_put(parent);
        return PTR_ERR(obj);
    }
    
    /* Inicializa dados específicos */
    if (type == LIH_OBJ_TYPE_GENERIC && init_data && init_size) {
        obj->specific.generic.data = kmalloc(init_size, GFP_KERNEL);
        if (obj->specific.generic.data) {
            memcpy(obj->specific.generic.data, init_data, init_size);
            obj->specific.generic.data_size = init_size;
        }
    }
    
    /* Insere no container */
    ret = lih_container_insert((struct lih_container *)parent, obj);
    if (ret < 0) {
        lih_object_put(obj);
        lih_object_put(parent);
        return ret;
    }
    
    /* Atualiza timestamps do pai */
    parent->timestamps.change_time = lih_kernel_to_filetime(ktime_get_real_ns());
    
    /* Notifica criação */
    /* ... */
    
    lih_object_put(obj);
    lih_object_put(parent);
    
    atomic64_inc(&lih_vfs->stats.total_objects);
    
    return 0;
}

/* Deleta um objeto */
static int lih_delete_object(const char *path)
{
    struct lih_drive *drive;
    struct lih_object *obj;
    struct lih_container *parent;
    int ret = 0;
    
    obj = lih_resolve_path(path, &drive);
    if (IS_ERR(obj))
        return PTR_ERR(obj);
    
    parent = obj->parent;
    if (!parent) {
        lih_object_put(obj);
        return -EACCES;
    }
    
    /* Verifica permissão de escrita no pai e deleção no objeto */
    /* ... */
    
    /* Container não vazio? */
    if (obj->type == LIH_OBJ_TYPE_CONTAINER && 
        obj->specific.container.child_count > 0) {
        lih_object_put(obj);
        return -ENOTEMPTY;
    }
    
    /* Remove do pai */
    lih_container_remove(parent, obj);
    
    /* Atualiza timestamps do pai */
    parent->timestamps.change_time = lih_kernel_to_filetime(ktime_get_real_ns());
    
    /* Marca para deleção */
    if (obj->delete) {
        ret = obj->delete(obj);
    }
    
    lih_object_put(obj);
    lih_object_put((struct lih_object *)parent);
    
    atomic64_dec(&lih_vfs->stats.total_objects);
    
    return ret;
}

/* ============================================================================
 * Handles e acesso a objetos
 * ============================================================================ */

/* Abre um objeto */
static struct lih_handle *lih_open(const char *path, u32 desired_access, 
                                     u32 share_mode, u32 flags)
{
    struct lih_drive *drive;
    struct lih_object *obj;
    struct lih_handle *handle;
    unsigned long irq_flags;
    int ret;
    
    obj = lih_resolve_path(path, &drive);
    if (IS_ERR(obj))
        return ERR_PTR(PTR_ERR(obj));
    
    /* Verifica permissões */
    /* ... */
    
    /* Cria handle */
    handle = kmem_cache_alloc(lih_vfs->handle_cache, GFP_KERNEL);
    if (!handle) {
        lih_object_put(obj);
        return ERR_PTR(-ENOMEM);
    }
    
    handle->id = lih_generate_id();
    handle->obj = obj;
    handle->desired_access = desired_access;
    handle->share_mode = share_mode;
    handle->flags = flags;
    handle->creation_time = ktime_get_real_ns();
    handle->pid = current->pid;
    handle->task = current;
    spin_lock_init(&handle->lock);
    atomic_set(&handle->refcount, 1);
    
    /* Abre objeto */
    if (obj->open) {
        ret = obj->open(obj, handle);
        if (ret < 0) {
            kmem_cache_free(lih_vfs->handle_cache, handle);
            lih_object_put(obj);
            return ERR_PTR(ret);
        }
    }
    
    /* Adiciona à lista do objeto */
    spin_lock_irqsave(&obj->lock, irq_flags);
    list_add_tail(&handle->list, &obj->handles);
    atomic_inc(&obj->handle_count);
    spin_unlock_irqrestore(&obj->lock, irq_flags);
    
    /* Registra globalmente */
    spin_lock(&lih_vfs->handle_lock);
    idr_alloc(&lih_vfs->handles, handle, (int)handle->id, 
              (int)handle->id + 1, GFP_ATOMIC);
    spin_unlock(&lih_vfs->handle_lock);
    
    atomic_inc(&lih_vfs->handle_count);
    atomic64_inc(&lih_vfs->stats.total_handles_opened);
    
    /* Atualiza timestamp de acesso */
    obj->timestamps.last_access_time = lih_kernel_to_filetime(ktime_get_real_ns());
    obj->access_count++;
    obj->last_access_pid = current->pid;
    
    return handle;
}

/* Fecha um handle */
static int lih_close(struct lih_handle *handle)
{
    struct lih_object *obj;
    unsigned long irq_flags;
    
    if (!handle)
        return -EINVAL;
    
    obj = handle->obj;
    
    if (obj->close) {
        obj->close(handle);
    }
    
    /* Remove da lista do objeto */
    spin_lock_irqsave(&obj->lock, irq_flags);
    list_del(&handle->list);
    atomic_dec(&obj->handle_count);
    spin_unlock_irqrestore(&obj->lock, irq_flags);
    
    /* Remove do registro global */
    spin_lock(&lih_vfs->handle_lock);
    idr_remove(&lih_vfs->handles, (int)handle->id);
    spin_unlock(&lih_vfs->handle_lock);
    
    lih_object_put(obj);
    kmem_cache_free(lih_vfs->handle_cache, handle);
    
    atomic_dec(&lih_vfs->handle_count);
    atomic64_inc(&lih_vfs->stats.total_handles_closed);
    
    return 0;
}

/* Lê de um objeto */
static ssize_t lih_read(struct lih_handle *handle, void *buf, 
                         size_t offset, size_t len)
{
    struct lih_object *obj = handle->obj;
    ssize_t ret;
    
    if (!(handle->desired_access & LIH_OBJ_PERM_READ))
        return -EACCES;
    
    if (obj->read) {
        ret = obj->read(handle, buf, offset, len);
    } else if (obj->type == LIH_OBJ_TYPE_GENERIC && obj->specific.generic.data) {
        /* Leitura padrão para objetos genéricos */
        if (offset >= obj->specific.generic.data_size)
            return 0;
        size_t available = obj->specific.generic.data_size - offset;
        ret = min(len, available);
        memcpy(buf, (char *)obj->specific.generic.data + offset, ret);
    } else {
        ret = -ENOTSUPP;
    }
    
    if (ret > 0) {
        obj->timestamps.last_access_time = lih_kernel_to_filetime(ktime_get_real_ns());
        atomic64_add(ret, &lih_vfs->stats.total_accesses);
    }
    
    return ret;
}

/* Escreve em um objeto */
static ssize_t lih_write(struct lih_handle *handle, const void *buf,
                          size_t offset, size_t len)
{
    struct lih_object *obj = handle->obj;
    ssize_t ret;
    
    if (!(handle->desired_access & LIH_OBJ_PERM_WRITE))
        return -EACCES;
    
    if (obj->flags & LIH_OBJ_FLAG_READONLY)
        return -EROFS;
    
    if (obj->write) {
        ret = obj->write(handle, buf, offset, len);
    } else if (obj->type == LIH_OBJ_TYPE_GENERIC) {
        /* Escrita padrão para objetos genéricos */
        size_t new_size = offset + len;
        if (new_size > obj->specific.generic.data_size) {
            void *new_data = krealloc(obj->specific.generic.data, new_size, GFP_KERNEL);
            if (!new_data)
                return -ENOMEM;
            obj->specific.generic.data = new_data;
            obj->specific.generic.data_size = new_size;
        }
        memcpy((char *)obj->specific.generic.data + offset, buf, len);
        ret = len;
        obj->size = new_size;
    } else {
        ret = -ENOTSUPP;
    }
    
    if (ret > 0) {
        obj->timestamps.last_write_time = lih_kernel_to_filetime(ktime_get_real_ns());
        obj->timestamps.change_time = obj->timestamps.last_write_time;
        obj->modify_count++;
        atomic64_add(ret, &lih_vfs->stats.total_modifications);
    }
    
    return ret;
}

/* ============================================================================
 * Interface /proc e debugfs
 * ============================================================================ */

#ifdef CONFIG_PROC_FS

static int lih_vfs_proc_show(struct seq_file *m, void *v)
{
    struct lih_drive *drive;
    
    if (!lih_vfs)
        return 0;
    
    seq_printf(m, "LIH Virtual Object System (VFS)\n");
    seq_printf(m, "================================\n\n");
    
    seq_printf(m, "Config:\n");
    seq_printf(m, "  Case Insensitive: %d\n", lih_vfs->config.case_insensitive);
    seq_printf(m, "  Preserve Case: %d\n", lih_vfs->config.preserve_case);
    seq_printf(m, "  Long Paths: %d\n", lih_vfs->config.long_paths);
    seq_printf(m, "  ACL Enabled: %d\n", lih_vfs->config.acl_enabled);
    
    seq_printf(m, "\nStatistics:\n");
    seq_printf(m, "  Total Objects: %lld\n", 
               atomic64_read(&lih_vfs->stats.total_objects));
    seq_printf(m, "  Total Containers: %lld\n",
               atomic64_read(&lih_vfs->stats.total_containers));
    seq_printf(m, "  Open Handles: %d\n",
               atomic_read(&lih_vfs->handle_count));
    seq_printf(m, "  Handles Opened: %lld\n",
               atomic64_read(&lih_vfs->stats.total_handles_opened));
    seq_printf(m, "  Total Accesses: %lld\n",
               atomic64_read(&lih_vfs->stats.total_accesses));
    seq_printf(m, "  Total Modifications: %lld\n",
               atomic64_read(&lih_vfs->stats.total_modifications));
    
    seq_printf(m, "\nDrives:\n");
    mutex_lock(&lih_vfs->drive_lock);
    list_for_each_entry(drive, &lih_vfs->drive_list, list) {
        seq_printf(m, "  %c: - %s (Type: %d, Free: %llu/%llu)\n",
                   drive->letter, drive->volume_label,
                   drive->type, drive->free_space, drive->total_space);
    }
    mutex_unlock(&lih_vfs->drive_lock);
    
    return 0;
}

static int lih_vfs_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, lih_vfs_proc_show, NULL);
}

static const struct proc_ops lih_vfs_proc_ops = {
    .proc_open = lih_vfs_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

#endif /* CONFIG_PROC_FS */

/* ============================================================================
 * Inicialização e finalização
 * ============================================================================ */

static int __init lih_vfs_init(void)
{
    int ret, i;
    
    printk(KERN_INFO "LIH Virtual Object System initializing...\n");
    
    lih_vfs = kzalloc(sizeof(*lih_vfs), GFP_KERNEL);
    if (!lih_vfs)
        return -ENOMEM;
    
    /* Inicializa estruturas */
    mutex_init(&lih_vfs->drive_lock);
    INIT_LIST_HEAD(&lih_vfs->drive_list);
    idr_init(&lih_vfs->handles);
    spin_lock_init(&lih_vfs->handle_lock);
    mutex_init(&lih_vfs->global_lock);
    
    /* Configuração padrão */
    lih_vfs->config.case_insensitive = 1;
    lih_vfs->config.preserve_case = 1;
    lih_vfs->config.long_paths = 1;
    lih_vfs->config.acl_enabled = 1;
    lih_vfs->config.notify_enabled = 1;
    
    /* Cria caches SLAB */
    lih_vfs->object_cache = kmem_cache_create("lih_object",
                                                sizeof(struct lih_object),
                                                __alignof__(struct lih_object),
                                                SLAB_PANIC | SLAB_ACCOUNT,
                                                NULL);
    if (!lih_vfs->object_cache) {
        ret = -ENOMEM;
        goto out_free;
    }
    
    lih_vfs->handle_cache = kmem_cache_create("lih_handle",
                                                sizeof(struct lih_handle),
                                                __alignof__(struct lih_handle),
                                                SLAB_PANIC,
                                                NULL);
    if (!lih_vfs->handle_cache) {
        ret = -ENOMEM;
        goto out_destroy_object_cache;
    }
    
    lih_vfs->ace_cache = kmem_cache_create("lih_ace",
                                            sizeof(struct lih_ace),
                                            __alignof__(struct lih_ace),
                                            SLAB_PANIC,
                                            NULL);
    if (!lih_vfs->ace_cache) {
        ret = -ENOMEM;
        goto out_destroy_handle_cache;
    }
    
    lih_vfs->ea_cache = kmem_cache_create("lih_ea",
                                           sizeof(struct lih_ea),
                                           __alignof__(struct lih_ea),
                                           SLAB_PANIC,
                                           NULL);
    if (!lih_vfs->ea_cache) {
        ret = -ENOMEM;
        goto out_destroy_ace_cache;
    }
    
    /* Monta unidades padrão */
    lih_mount_drive('C', "Local Disk", 0);   /* Disco local */
    lih_mount_drive('D', "Data", 0);         /* Disco de dados */
    lih_mount_drive('Z', "RAM Disk", 3);     /* RAM disk */
    
#ifdef CONFIG_PROC_FS
    proc_create("lih_vfs", 0444, NULL, &lih_vfs_proc_ops);
#endif
    
    atomic64_set(&lih_vfs->stats.total_objects, 0);
    atomic64_set(&lih_vfs->stats.total_containers, 0);
    atomic_set(&lih_vfs->handle_count, 0);
    
    printk(KERN_INFO "LIH Virtual Object System initialized\n");
    printk(KERN_INFO "  - Drives: C:, D:, Z:\n");
    printk(KERN_INFO "  - Case-insensitive: enabled\n");
    printk(KERN_INFO "  - Object cache: %zu bytes\n", sizeof(struct lih_object));
    
    return 0;

out_destroy_ace_cache:
    kmem_cache_destroy(lih_vfs->ace_cache);
out_destroy_handle_cache:
    kmem_cache_destroy(lih_vfs->handle_cache);
out_destroy_object_cache:
    kmem_cache_destroy(lih_vfs->object_cache);
out_free:
    kfree(lih_vfs);
    lih_vfs = NULL;
    
    return ret;
}

static void __exit lih_vfs_exit(void)
{
    int i;
    
    if (!lih_vfs)
        return;
    
    printk(KERN_INFO "LIH Virtual Object System shutting down...\n");
    
    /* Desmonta unidades */
    for (i = 0; i < LIH_DRIVE_COUNT; i++) {
        if (lih_vfs->drives[i]) {
            lih_umount_drive(LIH_DRIVE_LETTER_MIN + i);
        }
    }
    
#ifdef CONFIG_PROC_FS
    remove_proc_entry("lih_vfs", NULL);
#endif
    
    /* Destroi caches */
    kmem_cache_destroy(lih_vfs->object_cache);
    kmem_cache_destroy(lih_vfs->handle_cache);
    kmem_cache_destroy(lih_vfs->ace_cache);
    kmem_cache_destroy(lih_vfs->ea_cache);
    
    idr_destroy(&lih_vfs->handles);
    kfree(lih_vfs);
    lih_vfs = NULL;
    
    printk(KERN_INFO "LIH Virtual Object System shut down\n");
}

module_init(lih_vfs_init);
module_exit(lih_vfs_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LIH Project");
MODULE_DESCRIPTION("LIH Virtual Object System - Object-based VFS with Windows-style paths");
MODULE_VERSION("1.0");
