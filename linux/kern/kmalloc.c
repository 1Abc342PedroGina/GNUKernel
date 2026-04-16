/*
 * linux/kernel/kmalloc.c - LIH Hybrid Memory Allocator
 * 
 * Redireciona chamadas de alocação de memória do Linux para o allocador do GNU Mach:
 *   - kmalloc()  -> kalloc() do Mach
 *   - kzalloc()  -> zalloc() do Mach (zero-filled)
 *   - kfree()    -> kfree() do Mach
 *   - krealloc() -> krealloc() via Mach
 * 
 * Mantém compatibilidade total com a API do Linux enquanto usa o 
 * gerenciamento de memória do microkernel Mach.
 * 
 * Parte do projeto LIH (Linux Is Hybrid)
 * 
 * Licença: GPLv2
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/preempt.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/kmemleak.h>
#include <linux/kasan.h>
#include <linux/kmsan.h>
#include <linux/random.h>
#include <linux/sort.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/cache.h>
#include <linux/log2.h>
#include <linux/err.h>
#include <asm/page.h>
#include <asm/cacheflush.h>

/* Headers do GNU Mach */
#include <mach/mach_types.h>
#include <mach/memory_object.h>
#include <mach/vm_param.h>
#include <mach/vm_statistics.h>
#include <mach/kalloc.h>
#include <mach/zalloc.h>

/* ============================================================================
 * Constantes e definições
 * ============================================================================ */

/* Constantes de alinhamento */
#define LIH_CACHE_LINE_SIZE     (64)
#define LIH_MIN_ALIGNMENT       (8)
#define LIH_MAX_ALIGNMENT       (PAGE_SIZE)

/* Constantes de tamanho */
#define LIH_KMALLOC_MAX_SIZE    (128 * 1024 * 1024)  /* 128MB máximo via kmalloc */
#define LIH_KMALLOC_MIN_SIZE    (8)
#define LIH_KMALLOC_CACHE_SIZE  (4096)

/* Constantes de zona */
#define LIH_ZONE_NORMAL         0x0001
#define LIH_ZONE_DMA            0x0002
#define LIH_ZONE_DMA32          0x0004
#define LIH_ZONE_HIGHMEM        0x0008

/* Flags de alocação (mapeamento GFP -> Mach) */
#define LIH_MACH_WAITOK         0x0001  /* Pode dormir (M_WAITOK) */
#define LIH_MACH_NOWAIT         0x0002  /* Não dormir (M_NOWAIT) */
#define LIH_MACH_ZERO           0x0004  /* Zerar memória */
#define LIH_MACH_CONTIG         0x0008  /* Memória contígua */
#define LIH_MACH_PHYSICAL       0x0010  /* Endereço físico */
#define LIH_MACH_TEMP           0x0020  /* Alocação temporária */
#define LIH_MACH_PAGEABLE       0x0040  /* Pageable memory */
#define LIH_MACH_INTERRUPT      0x0080  /* Contexto de interrupção */

/* Tabela de mapeamento GFP -> Mach flags */
static const unsigned long gfp_to_mach_flags[] = {
    [GFP_KERNEL]        = LIH_MACH_WAITOK,
    [GFP_ATOMIC]        = LIH_MACH_NOWAIT,
    [GFP_NOWAIT]        = LIH_MACH_NOWAIT,
    [GFP_DMA]           = LIH_MACH_CONTIG | LIH_MACH_PHYSICAL,
    [GFP_DMA32]         = LIH_MACH_CONTIG | LIH_MACH_PHYSICAL,
    [GFP_HIGHUSER]      = LIH_MACH_PAGEABLE,
    [GFP_USER]          = LIH_MACH_WAITOK | LIH_MACH_PAGEABLE,
    [GFP_TRANSHUGE]     = LIH_MACH_CONTIG,
};

/* ============================================================================
 * Estruturas de dados
 * ============================================================================ */

/* Cabeçalho de alocação para tracking */
struct lih_alloc_header {
    u64 magic;                      /* Magic number para validação */
    size_t size;                    /* Tamanho original solicitado */
    size_t aligned_size;            /* Tamanho real alinhado */
    unsigned long flags;            /* Flags de alocação */
    void *original_ptr;             /* Ponteiro original do Mach */
    int cpu;                        /* CPU que alocou */
    pid_t pid;                      /* Processo que alocou */
    u64 timestamp;                  /* Timestamp da alocação */
    unsigned long stack_hash;       /* Hash da stack trace (debug) */
    
    /* Para debugging */
    const char *caller_file;        /* Arquivo do chamador */
    int caller_line;                /* Linha do chamador */
    const char *caller_func;        /* Função do chamador */
    
    /* Lista para tracking de leaks */
    struct list_head list;
};

#define LIH_ALLOC_MAGIC             0x4C49484D454D0001ULL  /* "LIHMEM\0\1" */
#define LIH_ALLOC_MAGIC_FREE        0xDEADBEEFDEADBEEFULL

/* Cache de tamanhos para kmalloc (compatibilidade) */
struct lih_kmalloc_cache {
    size_t size;                    /* Tamanho do cache */
    struct kmem_cache *cache;       /* Cache do Linux (fallback) */
    const char *name;               /* Nome do cache */
    atomic_t allocations;           /* Contador de alocações */
    atomic_t frees;                 /* Contador de liberações */
};

/* Estatísticas globais */
struct lih_alloc_stats {
    atomic64_t total_allocations;
    atomic64_t total_frees;
    atomic64_t total_bytes_allocated;
    atomic64_t total_bytes_freed;
    atomic64_t current_bytes_allocated;
    atomic_t current_allocations;
    atomic_t max_allocations;
    atomic64_t max_bytes_allocated;
    atomic_t allocation_failures;
    atomic_t invalid_frees;
    atomic_t double_frees;
    atomic_t corruption_detected;
};

/* Lista global de alocações para debug */
static LIST_HEAD(lih_alloc_list);
static DEFINE_SPINLOCK(lih_alloc_list_lock);

/* Caches de tamanhos fixos (compatibilidade com Linux) */
static struct lih_kmalloc_cache lih_caches[] = {
    { .size = 8,     .name = "lih-8" },
    { .size = 16,    .name = "lih-16" },
    { .size = 32,    .name = "lih-32" },
    { .size = 48,    .name = "lih-48" },
    { .size = 64,    .name = "lih-64" },
    { .size = 80,    .name = "lih-80" },
    { .size = 96,    .name = "lih-96" },
    { .size = 112,   .name = "lih-112" },
    { .size = 128,   .name = "lih-128" },
    { .size = 192,   .name = "lih-192" },
    { .size = 256,   .name = "lih-256" },
    { .size = 512,   .name = "lih-512" },
    { .size = 1024,  .name = "lih-1k" },
    { .size = 2048,  .name = "lih-2k" },
    { .size = 4096,  .name = "lih-4k" },
    { .size = 8192,  .name = "lih-8k" },
    { .size = 16384, .name = "lih-16k" },
    { .size = 32768, .name = "lih-32k" },
    { .size = 65536, .name = "lih-64k" },
    { .size = 131072, .name = "lih-128k" },
};

#define LIH_NUM_CACHES (ARRAY_SIZE(lih_caches))

/* Estatísticas globais */
static struct lih_alloc_stats lih_stats;

/* Flag para usar fallback para Linux (emergência) */
static bool lih_use_linux_fallback = false;

/* Proteção para operações concorrentes */
static DEFINE_SPINLOCK(lih_mach_lock);
static DEFINE_PER_CPU(atomic_t, lih_cpu_allocation_count);

/* ============================================================================
 * Funções auxiliares
 * ============================================================================ */

/* Alinha tamanho para próximo power of two (como kmalloc original) */
static inline size_t lih_align_size(size_t size)
{
    if (size < LIH_KMALLOC_MIN_SIZE)
        size = LIH_KMALLOC_MIN_SIZE;
    
    if (size <= 64)
        return roundup_pow_of_two(size);
    else if (size <= 128)
        return roundup_pow_of_two(size);
    else if (size <= 256)
        return roundup_pow_of_two(size);
    else if (size <= 512)
        return roundup_pow_of_two(size);
    else if (size <= 1024)
        return roundup_pow_of_two(size);
    else
        return roundup_pow_of_two(size);
}

/* Converte flags GFP do Linux para flags do Mach */
static inline unsigned long lih_gfp_to_mach_flags(gfp_t gfp_flags)
{
    unsigned long mach_flags = 0;
    
    /* Verifica flags de espera */
    if (gfp_flags & __GFP_DIRECT_RECLAIM)
        mach_flags |= LIH_MACH_WAITOK;
    else
        mach_flags |= LIH_MACH_NOWAIT;
    
    /* Verifica flags de zero */
    if (gfp_flags & __GFP_ZERO)
        mach_flags |= LIH_MACH_ZERO;
    
    /* Verifica flags de DMA/contiguidade */
    if (gfp_flags & __GFP_DMA)
        mach_flags |= LIH_MACH_CONTIG | LIH_MACH_PHYSICAL;
    
    if (gfp_flags & __GFP_DMA32)
        mach_flags |= LIH_MACH_CONTIG | LIH_MACH_PHYSICAL;
    
    /* Verifica highmem */
    if (gfp_flags & __GFP_HIGHMEM)
        mach_flags |= LIH_MACH_PAGEABLE;
    
    /* Contexto de interrupção */
    if (in_interrupt() || in_atomic())
        mach_flags |= LIH_MACH_INTERRUPT;
    
    return mach_flags;
}

/* Calcula hash da stack trace para debug */
static unsigned long lih_stack_hash(void)
{
    unsigned long hash = 0;
    unsigned long stack[8];
    int depth;
    
    depth = stack_trace_save(stack, 8, 2);
    hash = hash_start;
    for (int i = 0; i < depth; i++)
        hash = hash_long(stack[i], hash);
    
    return hash;
}

/* Adiciona alocação à lista de tracking */
static void lih_track_allocation(void *ptr, size_t size, size_t aligned_size,
                                  unsigned long flags, const char *file,
                                  int line, const char *func)
{
    struct lih_alloc_header *header;
    unsigned long irq_flags;
    
    if (!ptr)
        return;
    
    header = (struct lih_alloc_header *)((char *)ptr - sizeof(*header));
    
    spin_lock_irqsave(&lih_alloc_list_lock, irq_flags);
    list_add(&header->list, &lih_alloc_list);
    spin_unlock_irqrestore(&lih_alloc_list_lock, irq_flags);
}

/* Remove alocação do tracking */
static void lih_untrack_allocation(void *ptr)
{
    struct lih_alloc_header *header;
    unsigned long irq_flags;
    
    if (!ptr)
        return;
    
    header = (struct lih_alloc_header *)((char *)ptr - sizeof(*header));
    
    spin_lock_irqsave(&lih_alloc_list_lock, irq_flags);
    list_del(&header->list);
    spin_unlock_irqrestore(&lih_alloc_list_lock, irq_flags);
}

/* Valida um ponteiro antes de liberar */
static int lih_validate_ptr(void *ptr)
{
    struct lih_alloc_header *header;
    
    if (!ptr)
        return 0;
    
    header = (struct lih_alloc_header *)((char *)ptr - sizeof(*header));
    
    /* Verifica magic number */
    if (header->magic != LIH_ALLOC_MAGIC) {
        printk(KERN_ERR "LIH: Invalid magic in pointer %p (magic=0x%llx)\n",
               ptr, header->magic);
        atomic_inc(&lih_stats.corruption_detected);
        return -EINVAL;
    }
    
    /* Verifica se já foi liberado */
    if (header->magic == LIH_ALLOC_MAGIC_FREE) {
        printk(KERN_ERR "LIH: Double free detected on pointer %p\n", ptr);
        atomic_inc(&lih_stats.double_frees);
        return -EINVAL;
    }
    
    return 0;
}

/* ============================================================================
 * Alocações via Mach - Implementação principal
 * ============================================================================ */

/**
 * lih_kalloc_via_mach - Aloca memória via kalloc() do Mach
 * @size: Tamanho a alocar
 * @flags: Flags do Mach
 * 
 * Retorna: Ponteiro alocado ou NULL
 */
static void *lih_kalloc_via_mach(size_t size, unsigned long flags)
{
    void *ptr = NULL;
    unsigned long mach_flags = 0;
    
    /* Decide flags baseado no contexto */
    if (flags & LIH_MACH_WAITOK)
        mach_flags = KALLOC_WAITOK;
    else if (flags & LIH_MACH_NOWAIT)
        mach_flags = KALLOC_NOWAIT;
    
    if (flags & LIH_MACH_ZERO)
        mach_flags |= KALLOC_ZERO;
    
    /* Chama kalloc do Mach */
    ptr = kalloc(size, mach_flags);
    
    return ptr;
}

/**
 * lih_zalloc_via_mach - Aloca memória zerada via zalloc() do Mach
 * @size: Tamanho a alocar
 * @flags: Flags do Mach
 * 
 * Retorna: Ponteiro alocado (zerado) ou NULL
 */
static void *lih_zalloc_via_mach(size_t size, unsigned long flags)
{
    void *ptr = NULL;
    unsigned long mach_flags = 0;
    
    if (flags & LIH_MACH_WAITOK)
        mach_flags = ZALLOC_WAITOK;
    else if (flags & LIH_MACH_NOWAIT)
        mach_flags = ZALLOC_NOWAIT;
    
    /* zalloc já retorna memória zerada */
    ptr = zalloc(size, mach_flags);
    
    return ptr;
}

/**
 * lih_kfree_via_mach - Libera memória via kfree() do Mach
 * @ptr: Ponteiro a liberar
 * @size: Tamanho (opcional, para validação)
 */
static void lih_kfree_via_mach(void *ptr, size_t size)
{
    if (!ptr)
        return;
    
    /* kfree do Mach não precisa de tamanho */
    kfree(ptr);
}

/* ============================================================================
 * API principal - kmalloc / kzalloc / kfree
 * ============================================================================ */

/**
 * lih_kmalloc - Aloca memória via Mach (substitui kmalloc do Linux)
 * @size: Tamanho a alocar
 * @flags: GFP flags do Linux
 * 
 * Retorna: Ponteiro alocado ou NULL
 */
void *lih_kmalloc(size_t size, gfp_t flags)
{
    void *ptr = NULL;
    struct lih_alloc_header *header;
    size_t aligned_size;
    unsigned long mach_flags;
    unsigned long irq_flags;
    int ret;
    
    /* Valida tamanho */
    if (size == 0)
        return NULL;
    
    if (unlikely(size > LIH_KMALLOC_MAX_SIZE)) {
        printk_once(KERN_WARNING "LIH: kmalloc size %zu exceeds max %d\n",
                    size, LIH_KMALLOC_MAX_SIZE);
        if (lih_use_linux_fallback)
            return kmalloc(size, flags);
        return NULL;
    }
    
    /* Alinha tamanho */
    aligned_size = lih_align_size(size);
    
    /* Adiciona espaço para cabeçalho */
    aligned_size += sizeof(struct lih_alloc_header);
    
    /* Converte flags */
    mach_flags = lih_gfp_to_mach_flags(flags);
    
    /* Tenta alocar via Mach primeiro */
    if (flags & __GFP_ZERO)
        ptr = lih_zalloc_via_mach(aligned_size, mach_flags);
    else
        ptr = lih_kalloc_via_mach(aligned_size, mach_flags);
    
    /* Fallback para Linux se Mach falhar */
    if (!ptr) {
        atomic_inc(&lih_stats.allocation_failures);
        
        if (lih_use_linux_fallback) {
            printk_once(KERN_INFO "LIH: Falling back to Linux allocator\n");
            return kmalloc(size, flags);
        }
        
        return NULL;
    }
    
    /* Preenche cabeçalho */
    header = (struct lih_alloc_header *)ptr;
    header->magic = LIH_ALLOC_MAGIC;
    header->size = size;
    header->aligned_size = aligned_size;
    header->flags = mach_flags;
    header->original_ptr = ptr;
    header->cpu = raw_smp_processor_id();
    header->pid = current->pid;
    header->timestamp = local_clock();
    header->stack_hash = lih_stack_hash();
    
    /* Informação do chamador (se disponível) */
#ifdef CONFIG_DEBUG_SLAB
    header->caller_file = __FILE__;
    header->caller_line = __LINE__;
    header->caller_func = __func__;
#endif
    
    /* Atualiza estatísticas */
    atomic64_inc(&lih_stats.total_allocations);
    atomic64_add(size, &lih_stats.total_bytes_allocated);
    atomic64_add(size, &lih_stats.current_bytes_allocated);
    atomic_inc(&lih_stats.current_allocations);
    
    if (atomic_read(&lih_stats.current_allocations) > 
        atomic_read(&lih_stats.max_allocations)) {
        atomic_set(&lih_stats.max_allocations, 
                   atomic_read(&lih_stats.current_allocations));
    }
    
    if (atomic64_read(&lih_stats.current_bytes_allocated) > 
        atomic64_read(&lih_stats.max_bytes_allocated)) {
        atomic64_set(&lih_stats.max_bytes_allocated,
                     atomic64_read(&lih_stats.current_bytes_allocated));
    }
    
    /* Tracking para debug */
    if (flags & __GFP_ZERO) {
        /* Memória já está zerada pelo zalloc */
    } else if (flags & __GFP_ZERO) {
        /* Garante zero se a flag foi passada mas não usamos zalloc */
        memset((char *)ptr + sizeof(*header), 0, size);
    }
    
    /* Adiciona à lista de tracking (se debug) */
    if (unlikely(lih_use_linux_fallback == false)) {
        lih_track_allocation((char *)ptr + sizeof(*header), size, aligned_size,
                             mach_flags, __FILE__, __LINE__, __func__);
    }
    
    /* Retorna ponteiro após o cabeçalho */
    return (char *)ptr + sizeof(*header);
}
EXPORT_SYMBOL(lih_kmalloc);

/**
 * lih_kzalloc - Aloca memória zerada via zalloc() do Mach
 * @size: Tamanho a alocar
 * @flags: GFP flags do Linux
 * 
 * Retorna: Ponteiro alocado (zerado) ou NULL
 */
void *lih_kzalloc(size_t size, gfp_t flags)
{
    /* Adiciona flag de zero e chama kmalloc */
    return lih_kmalloc(size, flags | __GFP_ZERO);
}
EXPORT_SYMBOL(lih_kzalloc);

/**
 * lih_kfree - Libera memória via kfree() do Mach
 * @ptr: Ponteiro a liberar
 */
void lih_kfree(const void *ptr)
{
    struct lih_alloc_header *header;
    void *real_ptr;
    size_t size;
    int ret;
    
    if (!ptr)
        return;
    
    /* Valida ponteiro */
    ret = lih_validate_ptr((void *)ptr);
    if (ret) {
        atomic_inc(&lih_stats.invalid_frees);
        
        /* Tenta liberar via Linux como fallback */
        if (lih_use_linux_fallback) {
            kfree(ptr);
        }
        return;
    }
    
    /* Obtém cabeçalho */
    header = (struct lih_alloc_header *)((char *)ptr - sizeof(*header));
    real_ptr = header->original_ptr;
    size = header->size;
    
    /* Marca como liberado (para detectar double free) */
    header->magic = LIH_ALLOC_MAGIC_FREE;
    
    /* Remove do tracking */
    lih_untrack_allocation((void *)ptr);
    
    /* Libera via Mach */
    lih_kfree_via_mach(real_ptr, header->aligned_size);
    
    /* Atualiza estatísticas */
    atomic64_inc(&lih_stats.total_frees);
    atomic64_add(size, &lih_stats.total_bytes_freed);
    atomic64_sub(size, &lih_stats.current_bytes_allocated);
    atomic_dec(&lih_stats.current_allocations);
}
EXPORT_SYMBOL(lih_kfree);

/**
 * lih_krealloc - Realoca memória via Mach
 * @ptr: Ponteiro original (pode ser NULL)
 * @new_size: Novo tamanho
 * @flags: GFP flags
 * 
 * Retorna: Novo ponteiro ou NULL
 */
void *lih_krealloc(const void *ptr, size_t new_size, gfp_t flags)
{
    void *new_ptr;
    struct lih_alloc_header *old_header;
    size_t old_size;
    size_t copy_size;
    
    if (!ptr)
        return lih_kmalloc(new_size, flags);
    
    if (new_size == 0) {
        lih_kfree(ptr);
        return NULL;
    }
    
    /* Valida ponteiro antigo */
    if (lih_validate_ptr((void *)ptr)) {
        if (lih_use_linux_fallback)
            return krealloc(ptr, new_size, flags);
        return NULL;
    }
    
    /* Obtém tamanho antigo */
    old_header = (struct lih_alloc_header *)((char *)ptr - sizeof(*old_header));
    old_size = old_header->size;
    
    /* Aloca novo bloco */
    new_ptr = lih_kmalloc(new_size, flags);
    if (!new_ptr)
        return NULL;
    
    /* Copia dados */
    copy_size = min(old_size, new_size);
    memcpy(new_ptr, ptr, copy_size);
    
    /* Libera antigo */
    lih_kfree(ptr);
    
    return new_ptr;
}
EXPORT_SYMBOL(lih_krealloc);

/* ============================================================================
 * API de debug e estatísticas
 * ============================================================================ */

/**
 * lih_get_stats - Retorna estatísticas do allocator
 * @stats: Estrutura para preencher
 */
void lih_get_stats(struct lih_alloc_stats *stats)
{
    if (!stats)
        return;
    
    memcpy(stats, &lih_stats, sizeof(*stats));
}
EXPORT_SYMBOL(lih_get_stats);

/**
 * lih_print_stats - Imprime estatísticas no console
 */
void lih_print_stats(void)
{
    printk(KERN_INFO "LIH Allocator Statistics:\n");
    printk(KERN_INFO "  Total allocations:   %llu\n",
           atomic64_read(&lih_stats.total_allocations));
    printk(KERN_INFO "  Total frees:         %llu\n",
           atomic64_read(&lih_stats.total_frees));
    printk(KERN_INFO "  Current allocations: %d\n",
           atomic_read(&lih_stats.current_allocations));
    printk(KERN_INFO "  Max allocations:     %d\n",
           atomic_read(&lih_stats.max_allocations));
    printk(KERN_INFO "  Total bytes allocated: %llu\n",
           atomic64_read(&lih_stats.total_bytes_allocated));
    printk(KERN_INFO "  Current bytes:       %llu\n",
           atomic64_read(&lih_stats.current_bytes_allocated));
    printk(KERN_INFO "  Max bytes:           %llu\n",
           atomic64_read(&lih_stats.max_bytes_allocated));
    printk(KERN_INFO "  Allocation failures: %d\n",
           atomic_read(&lih_stats.allocation_failures));
    printk(KERN_INFO "  Invalid frees:       %d\n",
           atomic_read(&lih_stats.invalid_frees));
    printk(KERN_INFO "  Double frees:        %d\n",
           atomic_read(&lih_stats.double_frees));
    printk(KERN_INFO "  Corruptions:         %d\n",
           atomic_read(&lih_stats.corruption_detected));
}
EXPORT_SYMBOL(lih_print_stats);

/**
 * lih_check_leaks - Verifica vazamentos de memória
 */
void lih_check_leaks(void)
{
    struct lih_alloc_header *header;
    unsigned long irq_flags;
    int count = 0;
    
    spin_lock_irqsave(&lih_alloc_list_lock, irq_flags);
    
    if (!list_empty(&lih_alloc_list)) {
        printk(KERN_WARNING "LIH: Memory leaks detected:\n");
        list_for_each_entry(header, &lih_alloc_list, list) {
            printk(KERN_WARNING "  Leak: %zu bytes at %p (pid=%d, cpu=%d)\n",
                   header->size, 
                   (char *)header + sizeof(*header),
                   header->pid, header->cpu);
            count++;
        }
    } else {
        printk(KERN_INFO "LIH: No memory leaks detected\n");
    }
    
    spin_unlock_irqrestore(&lih_alloc_list_lock, irq_flags);
    
    if (count)
        printk(KERN_WARNING "LIH: Total %d leaked allocations\n", count);
}
EXPORT_SYMBOL(lih_check_leaks);

/* ============================================================================
 * Inicialização do subsistema de alocação
 * ============================================================================ */

static int __init lih_kmalloc_init(void)
{
    int i;
    
    printk(KERN_INFO "LIH Hybrid Allocator: Inicializando...\n");
    
    /* Inicializa estatísticas */
    memset(&lih_stats, 0, sizeof(lih_stats));
    
    /* Inicializa lista de tracking */
    INIT_LIST_HEAD(&lih_alloc_list);
    
    /* Verifica se Mach está disponível */
    if (!kalloc || !zalloc || !kfree) {
        printk(KERN_WARNING "LIH: Mach allocator not available, using Linux fallback\n");
        lih_use_linux_fallback = true;
    } else {
        printk(KERN_INFO "LIH: Mach allocator detected and ready\n");
        lih_use_linux_fallback = false;
    }
    
    /* Inicializa caches de tamanho (compatibilidade) */
    for (i = 0; i < LIH_NUM_CACHES; i++) {
        if (lih_use_linux_fallback) {
            lih_caches[i].cache = kmem_cache_create(lih_caches[i].name,
                                                     lih_caches[i].size,
                                                     lih_caches[i].size,
                                                     SLAB_PANIC,
                                                     NULL);
        }
        atomic_set(&lih_caches[i].allocations, 0);
        atomic_set(&lih_caches[i].frees, 0);
    }
    
    printk(KERN_INFO "LIH Hybrid Allocator: Inicializado\n");
    printk(KERN_INFO "  - Max allocation size: %d bytes\n", LIH_KMALLOC_MAX_SIZE);
    printk(KERN_INFO "  - Alignment: %d bytes\n", LIH_MIN_ALIGNMENT);
    printk(KERN_INFO "  - Number of caches: %d\n", LIH_NUM_CACHES);
    printk(KERN_INFO "  - Fallback mode: %s\n", 
           lih_use_linux_fallback ? "Linux" : "Mach");
    
    return 0;
}

static void __exit lih_kmalloc_exit(void)
{
    int i;
    
    printk(KERN_INFO "LIH Hybrid Allocator: Finalizando...\n");
    
    /* Verifica leaks */
    lih_check_leaks();
    
    /* Imprime estatísticas finais */
    lih_print_stats();
    
    /* Destroi caches */
    for (i = 0; i < LIH_NUM_CACHES; i++) {
        if (lih_caches[i].cache) {
            kmem_cache_destroy(lih_caches[i].cache);
        }
    }
    
    printk(KERN_INFO "LIH Hybrid Allocator: Finalizado\n");
}

module_init(lih_kmalloc_init);
module_exit(lih_kmalloc_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LIH Project");
MODULE_DESCRIPTION("LIH Hybrid Memory Allocator - kmalloc/kzalloc via GNU Mach");
MODULE_VERSION("1.0");
