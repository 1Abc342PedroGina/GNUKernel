/*
 * linux/kernel/memorystatus.c - LIH Memory Status & Management
 * 
 * Subsistema de gerenciamento de memória que unifica:
 *   - Status de memória do Linux (vmstat, meminfo)
 *   - Status de memória do GNU Mach (vm_statistics, zone_info)
 *   - Gerenciamento de pressão de memória (PSI, pressure stall information)
 *   - Políticas de swapping entre Linux e Mach
 *   - Memória compartilhada entre os dois kernels
 *   - Detecção de vazamentos e corrupção
 * 
 * Parte do projeto LIH (Linux Is Hybrid)
 * 
 * Licença: GPLv2
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/vmstat.h>
#include <linux/memcontrol.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/pagewalk.h>
#include <linux/hugetlb.h>
#include <linux/ksm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/oom.h>
#include <linux/psi.h>
#include <linux/pressure.h>
#include <linux/mempolicy.h>
#include <linux/migrate.h>
#include <linux/compaction.h>
#include <linux/vmalloc.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/debugfs.h>
#include <linux/sysctl.h>
#include <linux/uaccess.h>
#include <linux/cma.h>
#include <linux/memory_hotplug.h>
#include <linux/memory_merging.h>
#include <linux/memory-tiers.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/page.h>

/* Headers do GNU Mach */
#include <mach/mach_types.h>
#include <mach/vm_statistics.h>
#include <mach/vm_param.h>
#include <mach/vm_page_size.h>
#include <mach/vm_prot.h>
#include <mach/vm_inherit.h>
#include <mach/vm_purgable.h>
#include <mach/vm_behavior.h>
#include <mach/memory_object.h>
#include <mach/mach_host.h>
#include <mach/host_info.h>
#include <mach/task_info.h>
#include <mach/zone_info.h>

/* ============================================================================
 * Constantes e definições
 * ============================================================================ */

/* Tipos de memória */
#define LIH_MEM_TYPE_LINUX       0x0001  /* Memória gerenciada pelo Linux */
#define LIH_MEM_TYPE_MACH        0x0002  /* Memória gerenciada pelo Mach */
#define LIH_MEM_TYPE_SHARED      0x0004  /* Memória compartilhada */
#define LIH_MEM_TYPE_DMA         0x0008  /* Memória DMA */
#define LIH_MEM_TYPE_HUGETLB     0x0010  /* HugeTLB pages */
#define LIH_MEM_TYPE_TRANSHUGE   0x0020  /* Transparent huge pages */
#define LIH_MEM_TYPE_PERSISTENT  0x0040  /* Memória persistente (PMEM) */

/* Estados de pressão de memória */
#define LIH_MEM_PRESSURE_NONE    0       /* Sem pressão */
#define LIH_MEM_PRESSURE_LOW     1       /* Baixa pressão */
#define LIH_MEM_PRESSURE_MEDIUM  2       /* Pressão média */
#define LIH_MEM_PRESSURE_HIGH    3       /* Alta pressão */
#define LIH_MEM_PRESSURE_CRITICAL 4      /* Pressão crítica (OOM iminente) */

/* Ações de resposta à pressão */
#define LIH_MEM_ACTION_NONE      0       /* Nenhuma ação */
#define LIH_MEM_ACTION_RECLAIM   1       /* Reclamar memória */
#define LIH_MEM_ACTION_SWAP      2       /* Swapping */
#define LIH_MEM_ACTION_COMPACT   3       /* Compactação */
#define LIH_MEM_ACTION_OOM_KILL  4       /* Matar processo */
#define LIH_MEM_ACTION_MIGRATE   5       /* Migrar para outro nó */
#define LIH_MEM_ACTION_COMPRESS  6       /* Comprimir páginas (zswap) */

/* Zonas de memória */
#define LIH_MEM_ZONE_NORMAL      0
#define LIH_MEM_ZONE_DMA         1
#define LIH_MEM_ZONE_DMA32       2
#define LIH_MEM_ZONE_HIGHMEM     3
#define LIH_MEM_ZONE_MOVABLE     4
#define LIH_MEM_ZONE_DEVICE      5

/* Thresholds para pressão de memória (bytes) */
#define LIH_MEM_PRESSURE_LOW_THRESHOLD    (10 * 1024 * 1024)   /* 10MB */
#define LIH_MEM_PRESSURE_MEDIUM_THRESHOLD (5 * 1024 * 1024)    /* 5MB */
#define LIH_MEM_PRESSURE_HIGH_THRESHOLD   (2 * 1024 * 1024)    /* 2MB */
#define LIH_MEM_PRESSURE_CRITICAL_THRESHOLD (512 * 1024)       /* 512KB */

/* Intervalos de monitoramento (ms) */
#define LIH_MEM_MONITOR_INTERVAL_FAST     100   /* 100ms */
#define LIH_MEM_MONITOR_INTERVAL_NORMAL   1000  /* 1s */
#define LIH_MEM_MONITOR_INTERVAL_SLOW     10000 /* 10s */

/* Estatísticas de amostragem */
#define LIH_MEM_SAMPLE_WINDOW      60     /* Janela de 60 amostras */
#define LIH_MEM_HISTORY_SIZE       300    /* 5 minutos (60*5) */

/* ============================================================================
 * Estruturas de dados
 * ============================================================================ */

/* Estatísticas detalhadas de memória do sistema */
struct lih_memory_stats {
    /* Estatísticas gerais */
    u64 total_ram;
    u64 free_ram;
    u64 total_swap;
    u64 free_swap;
    u64 cached;
    u64 buffers;
    u64 slab;
    u64 shmem;
    u64 kernel_stack;
    u64 page_tables;
    u64 vmalloc_used;
    
    /* Estatísticas por zona */
    struct {
        u64 total;
        u64 free;
        u64 used;
        u64 reserved;
    } zones[LIH_MEM_ZONE_DEVICE + 1];
    
    /* Estatísticas de página */
    u64 total_pages;
    u64 free_pages;
    u64 active_pages;
    u64 inactive_pages;
    u64 dirty_pages;
    u64 writeback_pages;
    u64 unevictable_pages;
    u64 mlocked_pages;
    
    /* Estatísticas de swap */
    u64 swap_pages_in;
    u64 swap_pages_out;
    u64 swap_pages_total;
    u64 swap_pages_used;
    
    /* Estatísticas de pressão */
    int pressure_level;
    u64 pressure_some_10;
    u64 pressure_some_60;
    u64 pressure_some_300;
    u64 pressure_full_10;
    u64 pressure_full_60;
    u64 pressure_full_300;
    
    /* Estatísticas do Mach */
    u64 mach_free_count;
    u64 mach_active_count;
    u64 mach_inactive_count;
    u64 mach_wire_count;
    u64 mach_compressor_count;
    u64 mach_pageout_count;
    
    /* Estatísticas de alocação */
    u64 alloc_success;
    u64 alloc_fail;
    u64 alloc_high;
    u64 alloc_normal;
    u64 alloc_dma;
    
    /* Tempo de coleta */
    u64 timestamp;
    ktime_t collection_time;
};

/* Amostra histórica de memória */
struct lih_memory_sample {
    u64 timestamp;
    u64 free_memory;
    u64 free_swap;
    int pressure_level;
    struct lih_memory_stats stats;
};

/* Estatísticas por processo */
struct lih_process_memory {
    pid_t pid;
    char comm[TASK_COMM_LEN];
    
    /* RSS/PSS/USS */
    unsigned long rss;
    unsigned long pss;
    unsigned long uss;
    unsigned long swap;
    
    /* Detalhamento por tipo */
    unsigned long anonymous;
    unsigned long file_backed;
    unsigned long shmem;
    unsigned long stack;
    unsigned long heap;
    unsigned long code;
    unsigned long data;
    
    /* Page flags */
    unsigned long dirty;
    unsigned long writeback;
    unsigned long swap_entries;
    
    /* Estatísticas Mach associadas */
    task_t mach_task;
    vm_size_t mach_virtual_size;
    vm_size_t mach_resident_size;
    
    struct list_head list;
};

/* Configuração do subsistema de memória */
struct lih_memory_config {
    int pressure_threshold_low;
    int pressure_threshold_medium;
    int pressure_threshold_high;
    int pressure_threshold_critical;
    
    int monitor_interval_ms;
    int sample_window_seconds;
    int history_size;
    
    bool enable_psi_monitoring;
    bool enable_mach_sync;
    bool enable_swap_trending;
    bool enable_oom_protection;
    bool enable_memory_compaction;
    bool enable_ksm;
    bool enable_damon;
    
    unsigned long min_free_kbytes;
    unsigned long extra_free_kbytes;
    unsigned long watermark_scale_factor;
    
    int swappiness;
    int vfs_cache_pressure;
    int dirty_ratio;
    int dirty_background_ratio;
};

/* Subsistema principal */
struct lih_memory_subsystem {
    int state;
    struct lih_memory_config config;
    
    /* Estatísticas atuais */
    struct lih_memory_stats current_stats;
    struct lih_memory_stats delta_stats;
    
    /* Histórico de amostras */
    struct lih_memory_sample *samples;
    int sample_head;
    int sample_count;
    spinlock_t sample_lock;
    
    /* Estatísticas por processo */
    struct list_head process_list;
    spinlock_t process_lock;
    
    /* Comunicação com Mach */
    host_t mach_host;
    vm_statistics_data_t mach_vm_stats;
    vm_statistics64_data_t mach_vm_stats64;
    zone_info_t mach_zone_info;
    
    /* Workqueues e timers */
    struct delayed_work monitor_work;
    struct delayed_work pressure_work;
    struct timer_list stats_timer;
    struct workqueue_struct *monitor_wq;
    
    /* Notificações */
    struct blocking_notifier_head notifier_chain;
    struct srcu_notifier_head pressure_notifier;
    
    /* OOM protection */
    struct task_struct *oom_protected_tasks[32];
    int oom_protected_count;
    spinlock_t oom_lock;
    
    /* Estatísticas globais */
    struct {
        atomic64_t total_collections;
        atomic64_t total_pressure_events;
        atomic64_t total_oom_kills;
        atomic64_t total_reclaims;
        atomic64_t total_compactions;
        atomic64_t total_migrations;
        
        u64 start_time;
        u64 last_collection;
        u64 last_pressure_event;
    } stats;
    
    /* Debug */
    struct dentry *debugfs_root;
    struct proc_dir_entry *proc_entry;
    
    /* Ratelimit para logs */
    struct ratelimit_state ratelimit;
};

/* ============================================================================
 * Variáveis globais
 * ============================================================================ */

static struct lih_memory_subsystem *lih_memory;
static DEFINE_MUTEX(lih_memory_global_lock);

/* ============================================================================
 * Funções auxiliares
 * ============================================================================ */

/* Obtém timestamp em nanosegundos */
static inline u64 lih_memory_timestamp(void)
{
    return ktime_get_real_ns();
}

/* Converte páginas para bytes */
static inline u64 pages_to_bytes(unsigned long pages)
{
    return (u64)pages << PAGE_SHIFT;
}

/* Converte bytes para páginas */
static inline unsigned long bytes_to_pages(u64 bytes)
{
    return (unsigned long)(bytes >> PAGE_SHIFT);
}

/* Obtém nível de pressão baseado na memória livre */
static int lih_memory_calculate_pressure(u64 free_memory)
{
    if (free_memory <= lih_memory->config.pressure_threshold_critical)
        return LIH_MEM_PRESSURE_CRITICAL;
    else if (free_memory <= lih_memory->config.pressure_threshold_high)
        return LIH_MEM_PRESSURE_HIGH;
    else if (free_memory <= lih_memory->config.pressure_threshold_medium)
        return LIH_MEM_PRESSURE_MEDIUM;
    else if (free_memory <= lih_memory->config.pressure_threshold_low)
        return LIH_MEM_PRESSURE_LOW;
    
    return LIH_MEM_PRESSURE_NONE;
}

/* ============================================================================
 * Coleta de estatísticas do Linux
 * ============================================================================ */

/* Coleta estatísticas de memória do Linux */
static void lih_collect_linux_stats(struct lih_memory_stats *stats)
{
    struct sysinfo i;
    struct vm_area_struct *vma;
    struct zone *zone;
    pg_data_t *pgdat;
    unsigned long active, inactive, dirty, writeback;
    int nid, zid;
    
    if (!stats)
        return;
    
    /* Estatísticas básicas do sistema */
    si_meminfo(&i);
    si_swapinfo(&i);
    
    stats->total_ram = pages_to_bytes(i.totalram);
    stats->free_ram = pages_to_bytes(i.freeram);
    stats->total_swap = pages_to_bytes(i.totalswap);
    stats->free_swap = pages_to_bytes(i.freeswap);
    stats->cached = pages_to_bytes(i.bufferram);  /* Aproximado */
    
    /* Estatísticas detalhadas de página */
    global_node_page_state(NR_ACTIVE_ANON, &active);
    global_node_page_state(NR_ACTIVE_FILE, &active);
    global_node_page_state(NR_INACTIVE_ANON, &inactive);
    global_node_page_state(NR_INACTIVE_FILE, &inactive);
    global_node_page_state(NR_FILE_DIRTY, &dirty);
    global_node_page_state(NR_WRITEBACK, &writeback);
    
    stats->active_pages = pages_to_bytes(active);
    stats->inactive_pages = pages_to_bytes(inactive);
    stats->dirty_pages = pages_to_bytes(dirty);
    stats->writeback_pages = pages_to_bytes(writeback);
    
    stats->total_pages = stats->total_ram >> PAGE_SHIFT;
    stats->free_pages = stats->free_ram >> PAGE_SHIFT;
    
    /* Estatísticas por zona */
    for_each_online_pgdat(pgdat) {
        for (zid = 0; zid < MAX_NR_ZONES; zid++) {
            zone = &pgdat->node_zones[zid];
            if (zone_idx(zone) > LIH_MEM_ZONE_DEVICE)
                continue;
            
            stats->zones[zid].total += pages_to_bytes(zone->spanned_pages);
            stats->zones[zid].free += pages_to_bytes(zone->free_pages);
        }
    }
    
    /* Slab e kernel */
    stats->slab = pages_to_bytes(global_node_page_state(NR_SLAB_RECLAIMABLE) +
                                  global_node_page_state(NR_SLAB_UNRECLAIMABLE));
    stats->kernel_stack = pages_to_bytes(global_node_page_state(NR_KERNEL_STACK_KB));
    stats->page_tables = pages_to_bytes(global_node_page_state(NR_PAGETABLE));
    
    /* Vmalloc */
    stats->vmalloc_used = (u64)vmalloc_nr_pages() << PAGE_SHIFT;
    
    stats->timestamp = lih_memory_timestamp();
}

/* Coleta estatísticas de pressão (PSI) */
static void lih_collect_pressure_stats(struct lih_memory_stats *stats)
{
    struct psi_group *group = &psi_system;
    
    if (!lih_memory->config.enable_psi_monitoring)
        return;
    
    /* Coleta estatísticas de pressão (se disponível) */
#ifdef CONFIG_PSI
    stats->pressure_some_10 = group->some[PSI_MEM].avg10;
    stats->pressure_some_60 = group->some[PSI_MEM].avg60;
    stats->pressure_some_300 = group->some[PSI_MEM].avg300;
    stats->pressure_full_10 = group->full[PSI_MEM].avg10;
    stats->pressure_full_60 = group->full[PSI_MEM].avg60;
    stats->pressure_full_300 = group->full[PSI_MEM].avg300;
#endif
}

/* ============================================================================
 * Coleta de estatísticas do Mach
 * ============================================================================ */

/* Coleta estatísticas de memória do GNU Mach */
static void lih_collect_mach_stats(struct lih_memory_stats *stats)
{
    kern_return_t kr;
    mach_msg_type_number_t count;
    host_t host;
    vm_size_t page_size;
    
    if (!stats || !lih_memory->config.enable_mach_sync)
        return;
    
    host = lih_memory->mach_host;
    if (host == MACH_PORT_NULL)
        return;
    
    page_size = vm_page_size;
    
    /* Coleta vm_statistics */
    count = HOST_VM_INFO_COUNT;
    kr = host_statistics(host, HOST_VM_INFO,
                         (host_info_t)&lih_memory->mach_vm_stats,
                         &count);
    if (kr == KERN_SUCCESS) {
        stats->mach_free_count = lih_memory->mach_vm_stats.free_count * page_size;
        stats->mach_active_count = lih_memory->mach_vm_stats.active_count * page_size;
        stats->mach_inactive_count = lih_memory->mach_vm_stats.inactive_count * page_size;
        stats->mach_wire_count = lih_memory->mach_vm_stats.wire_count * page_size;
        stats->mach_compressor_count = lih_memory->mach_vm_stats.compressor_page_count * page_size;
        stats->mach_pageout_count = lih_memory->mach_vm_stats.pageout_count;
    }
    
    /* Coleta vm_statistics64 para informações mais detalhadas */
    count = HOST_VM_INFO64_COUNT;
    kr = host_statistics64(host, HOST_VM_INFO64,
                           (host_info64_t)&lih_memory->mach_vm_stats64,
                           &count);
}

/* ============================================================================
 * Estatísticas por processo
 * ============================================================================ */

/* Coleta estatísticas de memória por processo */
static int lih_collect_process_memory(pid_t pid, struct lih_process_memory *mem)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long rss = 0, pss = 0, uss = 0, swap = 0;
    unsigned long anonymous = 0, file_backed = 0, shmem = 0;
    unsigned long stack = 0, heap = 0, code = 0, data = 0;
    
    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    
    get_task_struct(task);
    rcu_read_unlock();
    
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -ESRCH;
    }
    
    /* Percorre VMA's para coletar estatísticas */
    mmap_read_lock(mm);
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        unsigned long pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
        
        /* RSS/PSS/USS requerem walk_page_range (simplificado aqui) */
        rss += pages;
        
        /* Classificação por tipo */
        if (vma->vm_flags & VM_STACK)
            stack += pages;
        else if (vma->vm_flags & VM_GROWSDOWN)
            stack += pages;
        else if (vma->vm_flags & VM_HEAP)
            heap += pages;
        
        if (vma->vm_file) {
            if (vma->vm_flags & VM_EXEC)
                code += pages;
            else
                file_backed += pages;
        } else {
            anonymous += pages;
        }
    }
    mmap_read_unlock(mm);
    
    /* Preenche estrutura */
    mem->pid = pid;
    strscpy(mem->comm, task->comm, TASK_COMM_LEN);
    mem->rss = rss << PAGE_SHIFT;
    mem->pss = rss << PAGE_SHIFT;  /* Aproximação */
    mem->uss = rss << PAGE_SHIFT;  /* Aproximação */
    mem->anonymous = anonymous << PAGE_SHIFT;
    mem->file_backed = file_backed << PAGE_SHIFT;
    mem->stack = stack << PAGE_SHIFT;
    mem->heap = heap << PAGE_SHIFT;
    mem->code = code << PAGE_SHIFT;
    
    /* Swap (simplificado) */
    mem->swap = get_mm_counter(mm, MM_SWAPENTS) << PAGE_SHIFT;
    
    mmput(mm);
    put_task_struct(task);
    
    return 0;
}

/* Atualiza lista de processos com estatísticas */
static void lih_update_process_stats(void)
{
    struct lih_process_memory *entry, *tmp;
    struct task_struct *task;
    pid_t pid;
    unsigned long flags;
    
    /* Limpa lista antiga */
    spin_lock_irqsave(&lih_memory->process_lock, flags);
    list_for_each_entry_safe(entry, tmp, &lih_memory->process_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    INIT_LIST_HEAD(&lih_memory->process_list);
    spin_unlock_irqrestore(&lih_memory->process_lock, flags);
    
    /* Coleta novos dados */
    rcu_read_lock();
    for_each_process(task) {
        pid = task->pid;
        if (pid <= 0)
            continue;
        
        entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
        if (!entry)
            continue;
        
        if (lih_collect_process_memory(pid, entry) == 0) {
            spin_lock_irqsave(&lih_memory->process_lock, flags);
            list_add_tail(&entry->list, &lih_memory->process_list);
            spin_unlock_irqrestore(&lih_memory->process_lock, flags);
        } else {
            kfree(entry);
        }
    }
    rcu_read_unlock();
}

/* ============================================================================
 * Monitoramento e pressão de memória
 * ============================================================================ */

/* Verifica e responde à pressão de memória */
static void lih_check_memory_pressure(void)
{
    int pressure_level;
    int old_level;
    u64 free_memory;
    unsigned long flags;
    
    free_memory = lih_memory->current_stats.free_ram +
                  lih_memory->current_stats.free_swap;
    
    pressure_level = lih_memory_calculate_pressure(free_memory);
    old_level = lih_memory->current_stats.pressure_level;
    
    if (pressure_level != old_level) {
        lih_memory->current_stats.pressure_level = pressure_level;
        atomic64_inc(&lih_memory->stats.total_pressure_events);
        lih_memory->stats.last_pressure_event = lih_memory_timestamp();
        
        /* Notifica listeners */
        srcu_notifier_call_chain(&lih_memory->pressure_notifier,
                                  pressure_level, NULL);
        
        /* Log de mudança de pressão */
        if (pressure_level >= LIH_MEM_PRESSURE_HIGH) {
            printk_ratelimited(KERN_WARNING
                "LIH Memory: Pressure level %d, free=%llu\n",
                pressure_level, free_memory);
        }
    }
    
    /* Ações baseadas no nível de pressão */
    switch (pressure_level) {
    case LIH_MEM_PRESSURE_MEDIUM:
        if (lih_memory->config.enable_swap_trending) {
            /* Aumenta swappiness temporariamente */
            vm_swappiness = min(200, vm_swappiness + 10);
        }
        break;
        
    case LIH_MEM_PRESSURE_HIGH:
        /* Força reclaim */
        atomic64_inc(&lih_memory->stats.total_reclaims);
        try_to_free_pages(&def_zone->zone_pgdat->node_zones[0],
                          GFP_KERNEL, 0);
        
        if (lih_memory->config.enable_memory_compaction) {
            atomic64_inc(&lih_memory->stats.total_compactions);
            wakeup_kcompactd(NODE_DATA(0), 0, 0);
        }
        break;
        
    case LIH_MEM_PRESSURE_CRITICAL:
        /* Ações críticas - pode disparar OOM */
        if (lih_memory->config.enable_oom_protection) {
            /* Verifica processos protegidos */
            unsigned long flags;
            int i;
            
            spin_lock_irqsave(&lih_memory->oom_lock, flags);
            for (i = 0; i < lih_memory->oom_protected_count; i++) {
                struct task_struct *p = lih_memory->oom_protected_tasks[i];
                if (p && p->mm) {
                    /* Marca como OOM protegido */
                    set_bit(MMF_OOM_SKIP, &p->mm->flags);
                }
            }
            spin_unlock_irqrestore(&lih_memory->oom_lock, flags);
        }
        break;
    }
}

/* Trabalho de monitoramento periódico */
static void lih_monitor_work(struct work_struct *work)
{
    struct lih_memory_stats new_stats;
    unsigned long flags;
    int idx;
    
    /* Coleta estatísticas */
    memset(&new_stats, 0, sizeof(new_stats));
    lih_collect_linux_stats(&new_stats);
    lih_collect_pressure_stats(&new_stats);
    lih_collect_mach_stats(&new_stats);
    
    /* Atualiza estatísticas atuais */
    spin_lock_irqsave(&lih_memory->sample_lock, flags);
    
    /* Calcula delta */
    memcpy(&lih_memory->delta_stats, &lih_memory->current_stats,
           sizeof(lih_memory->delta_stats));
    lih_memory->delta_stats.free_ram = new_stats.free_ram -
                                        lih_memory->current_stats.free_ram;
    lih_memory->delta_stats.free_swap = new_stats.free_swap -
                                         lih_memory->current_stats.free_swap;
    
    /* Adiciona ao histórico */
    idx = (lih_memory->sample_head + 1) % lih_memory->config.history_size;
    memcpy(&lih_memory->samples[idx], &new_stats,
           sizeof(struct lih_memory_sample));
    lih_memory->sample_head = idx;
    if (lih_memory->sample_count < lih_memory->config.history_size)
        lih_memory->sample_count++;
    
    memcpy(&lih_memory->current_stats, &new_stats, sizeof(new_stats));
    
    spin_unlock_irqrestore(&lih_memory->sample_lock, flags);
    
    /* Atualiza estatísticas de processos (periodicamente) */
    static int process_counter = 0;
    if (++process_counter >= 10) {  /* A cada 10 ciclos */
        lih_update_process_stats();
        process_counter = 0;
    }
    
    /* Verifica pressão de memória */
    lih_check_memory_pressure();
    
    atomic64_inc(&lih_memory->stats.total_collections);
    lih_memory->stats.last_collection = lih_memory_timestamp();
    
    /* Reagenda */
    queue_delayed_work(lih_memory->monitor_wq,
                       &lih_memory->monitor_work,
                       msecs_to_jiffies(lih_memory->config.monitor_interval_ms));
}

/* ============================================================================
 * Notificações e callbacks
 * ============================================================================ */

/* Registra callback para eventos de pressão de memória */
int lih_memory_register_pressure_notifier(struct notifier_block *nb)
{
    return srcu_notifier_chain_register(&lih_memory->pressure_notifier, nb);
}
EXPORT_SYMBOL(lih_memory_register_pressure_notifier);

/* Remove callback de pressão */
int lih_memory_unregister_pressure_notifier(struct notifier_block *nb)
{
    return srcu_notifier_chain_unregister(&lih_memory->pressure_notifier, nb);
}
EXPORT_SYMBOL(lih_memory_unregister_pressure_notifier);

/* Registra processo protegido contra OOM */
int lih_memory_oom_protect(pid_t pid)
{
    struct task_struct *task;
    unsigned long flags;
    int ret = -ESRCH;
    
    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task) {
        get_task_struct(task);
        
        spin_lock_irqsave(&lih_memory->oom_lock, flags);
        if (lih_memory->oom_protected_count < 32) {
            lih_memory->oom_protected_tasks[lih_memory->oom_protected_count++] = task;
            ret = 0;
        } else {
            put_task_struct(task);
            ret = -ENOMEM;
        }
        spin_unlock_irqrestore(&lih_memory->oom_lock, flags);
    }
    rcu_read_unlock();
    
    return ret;
}
EXPORT_SYMBOL(lih_memory_oom_protect);

/* Remove proteção OOM */
int lih_memory_oom_unprotect(pid_t pid)
{
    unsigned long flags;
    int i;
    int ret = -ESRCH;
    
    spin_lock_irqsave(&lih_memory->oom_lock, flags);
    for (i = 0; i < lih_memory->oom_protected_count; i++) {
        struct task_struct *task = lih_memory->oom_protected_tasks[i];
        if (task && task->pid == pid) {
            put_task_struct(task);
            lih_memory->oom_protected_tasks[i] =
                lih_memory->oom_protected_tasks[--lih_memory->oom_protected_count];
            ret = 0;
            break;
        }
    }
    spin_unlock_irqrestore(&lih_memory->oom_lock, flags);
    
    return ret;
}
EXPORT_SYMBOL(lih_memory_oom_unprotect);

/* ============================================================================
 * Interface com Mach - memória compartilhada
 * ============================================================================ */

/* Aloca memória compartilhada entre Linux e Mach */
void *lih_memory_shared_alloc(size_t size, gfp_t gfp_flags)
{
    void *ptr;
    struct page *page;
    unsigned long order;
    
    if (size == 0)
        return NULL;
    
    order = get_order(size);
    page = alloc_pages(gfp_flags | __GFP_COMP, order);
    if (!page)
        return NULL;
    
    ptr = page_address(page);
    
    /* Mapeia para o espaço do Mach (implementação depende do Mach) */
    if (lih_memory->config.enable_mach_sync) {
        /* TODO: vm_map para o espaço do Mach */
    }
    
    return ptr;
}
EXPORT_SYMBOL(lih_memory_shared_alloc);

/* Libera memória compartilhada */
void lih_memory_shared_free(void *ptr, size_t size)
{
    struct page *page;
    
    if (!ptr)
        return;
    
    page = virt_to_head_page(ptr);
    if (page) {
        /* Desmapeia do Mach */
        if (lih_memory->config.enable_mach_sync) {
            /* TODO: vm_deallocate */
        }
        
        __free_pages(page, get_order(size));
    }
}
EXPORT_SYMBOL(lih_memory_shared_free);

/* ============================================================================
 * Interface /proc e debugfs
 * ============================================================================ */

#ifdef CONFIG_PROC_FS

/* Mostra informações de memória no /proc/lih_memory */
static int lih_memory_proc_show(struct seq_file *m, void *v)
{
    struct lih_memory_stats *s = &lih_memory->current_stats;
    
    if (!lih_memory)
        return 0;
    
    seq_printf(m, "LIH Memory Status\n");
    seq_printf(m, "=================\n\n");
    
    seq_printf(m, "Total RAM:        %8llu MB\n",
               s->total_ram >> 20);
    seq_printf(m, "Free RAM:         %8llu MB\n",
               s->free_ram >> 20);
    seq_printf(m, "Total Swap:       %8llu MB\n",
               s->total_swap >> 20);
    seq_printf(m, "Free Swap:        %8llu MB\n",
               s->free_swap >> 20);
    seq_printf(m, "Cached:           %8llu MB\n",
               s->cached >> 20);
    seq_printf(m, "Slab:             %8llu MB\n",
               s->slab >> 20);
    
    seq_printf(m, "\nPressure Level:   %d\n", s->pressure_level);
    seq_printf(m, "Pressure (10s):   %llu\n", s->pressure_some_10);
    seq_printf(m, "Pressure (60s):   %llu\n", s->pressure_some_60);
    seq_printf(m, "Pressure (300s):  %llu\n", s->pressure_some_300);
    
    seq_printf(m, "\nMach Statistics:\n");
    seq_printf(m, "  Free:    %llu MB\n", s->mach_free_count >> 20);
    seq_printf(m, "  Active:  %llu MB\n", s->mach_active_count >> 20);
    seq_printf(m, "  Inactive:%llu MB\n", s->mach_inactive_count >> 20);
    seq_printf(m, "  Wire:    %llu MB\n", s->mach_wire_count >> 20);
    
    return 0;
}

static int lih_memory_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, lih_memory_proc_show, NULL);
}

static const struct proc_ops lih_memory_proc_ops = {
    .proc_open = lih_memory_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

#endif /* CONFIG_PROC_FS */

#ifdef CONFIG_DEBUG_FS

/* Debugfs: mostra estatísticas detalhadas */
static int lih_memory_debug_show(struct seq_file *m, void *v)
{
    struct lih_memory_stats *s = &lih_memory->current_stats;
    struct lih_process_memory *proc;
    unsigned long flags;
    int i;
    
    seq_printf(m, "=== LIH Memory Debug Information ===\n\n");
    
    seq_printf(m, "Configuration:\n");
    seq_printf(m, "  Monitor interval: %d ms\n",
               lih_memory->config.monitor_interval_ms);
    seq_printf(m, "  History size: %d\n",
               lih_memory->config.history_size);
    seq_printf(m, "  PSI enabled: %d\n",
               lih_memory->config.enable_psi_monitoring);
    seq_printf(m, "  Mach sync: %d\n",
               lih_memory->config.enable_mach_sync);
    
    seq_printf(m, "\nGlobal Statistics:\n");
    seq_printf(m, "  Total collections: %llu\n",
               atomic64_read(&lih_memory->stats.total_collections));
    seq_printf(m, "  Pressure events: %llu\n",
               atomic64_read(&lih_memory->stats.total_pressure_events));
    seq_printf(m, "  OOM kills: %llu\n",
               atomic64_read(&lih_memory->stats.total_oom_kills));
    seq_printf(m, "  Reclaims: %llu\n",
               atomic64_read(&lih_memory->stats.total_reclaims));
    seq_printf(m, "  Compactions: %llu\n",
               atomic64_read(&lih_memory->stats.total_compactions));
    
    seq_printf(m, "\nMemory by Zone:\n");
    for (i = 0; i <= LIH_MEM_ZONE_DEVICE; i++) {
        if (s->zones[i].total > 0) {
            seq_printf(m, "  Zone %d: %llu MB total, %llu MB free\n",
                       i, s->zones[i].total >> 20, s->zones[i].free >> 20);
        }
    }
    
    seq_printf(m, "\nTop Processes by Memory:\n");
    spin_lock_irqsave(&lih_memory->process_lock, flags);
    list_for_each_entry(proc, &lih_memory->process_list, list) {
        seq_printf(m, "  %6d %-16s RSS:%8lu KB, PSS:%8lu KB, Swap:%8lu KB\n",
                   proc->pid, proc->comm,
                   proc->rss >> 10, proc->pss >> 10, proc->swap >> 10);
    }
    spin_unlock_irqrestore(&lih_memory->process_lock, flags);
    
    return 0;
}

static int lih_memory_debug_open(struct inode *inode, struct file *file)
{
    return single_open(file, lih_memory_debug_show, inode->i_private);
}

static const struct file_operations lih_memory_debug_fops = {
    .open = lih_memory_debug_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

#endif /* CONFIG_DEBUG_FS */

/* ============================================================================
 * Sysctl interface
 * ============================================================================ */

static struct ctl_table lih_memory_sysctls[] = {
    {
        .procname = "pressure_threshold_low",
        .data = &lih_memory->config.pressure_threshold_low,
        .maxlen = sizeof(int),
        .mode = 0644,
        .proc_handler = proc_dointvec,
    },
    {
        .procname = "pressure_threshold_high",
        .data = &lih_memory->config.pressure_threshold_high,
        .maxlen = sizeof(int),
        .mode = 0644,
        .proc_handler = proc_dointvec,
    },
    {
        .procname = "monitor_interval_ms",
        .data = &lih_memory->config.monitor_interval_ms,
        .maxlen = sizeof(int),
        .mode = 0644,
        .proc_handler = proc_dointvec,
    },
    {
        .procname = "enable_psi_monitoring",
        .data = &lih_memory->config.enable_psi_monitoring,
        .maxlen = sizeof(int),
        .mode = 0644,
        .proc_handler = proc_dointvec,
    },
    {
        .procname = "enable_mach_sync",
        .data = &lih_memory->config.enable_mach_sync,
        .maxlen = sizeof(int),
        .mode = 0644,
        .proc_handler = proc_dointvec,
    },
    {}
};

static struct ctl_table_header *lih_memory_sysctl_header;

/* ============================================================================
 * Inicialização e finalização
 * ============================================================================ */

static int __init lih_memory_init(void)
{
    int ret = 0;
    
    printk(KERN_INFO "LIH Memory Status subsystem initializing...\n");
    
    /* Aloca estrutura principal */
    lih_memory = kzalloc(sizeof(*lih_memory), GFP_KERNEL);
    if (!lih_memory)
        return -ENOMEM;
    
    /* Configuração padrão */
    lih_memory->config.pressure_threshold_low = LIH_MEM_PRESSURE_LOW_THRESHOLD;
    lih_memory->config.pressure_threshold_medium = LIH_MEM_PRESSURE_MEDIUM_THRESHOLD;
    lih_memory->config.pressure_threshold_high = LIH_MEM_PRESSURE_HIGH_THRESHOLD;
    lih_memory->config.pressure_threshold_critical = LIH_MEM_PRESSURE_CRITICAL_THRESHOLD;
    lih_memory->config.monitor_interval_ms = LIH_MEM_MONITOR_INTERVAL_NORMAL;
    lih_memory->config.sample_window_seconds = LIH_MEM_SAMPLE_WINDOW;
    lih_memory->config.history_size = LIH_MEM_HISTORY_SIZE;
    lih_memory->config.enable_psi_monitoring = true;
    lih_memory->config.enable_mach_sync = true;
    lih_memory->config.enable_swap_trending = true;
    lih_memory->config.enable_oom_protection = true;
    lih_memory->config.enable_memory_compaction = true;
    lih_memory->config.enable_ksm = false;
    lih_memory->config.enable_damon = false;
    lih_memory->config.min_free_kbytes = min_free_kbytes;
    lih_memory->config.extra_free_kbytes = extra_free_kbytes;
    lih_memory->config.watermark_scale_factor = watermark_scale_factor;
    lih_memory->config.swappiness = vm_swappiness;
    lih_memory->config.vfs_cache_pressure = vfs_cache_pressure;
    lih_memory->config.dirty_ratio = dirty_ratio;
    lih_memory->config.dirty_background_ratio = dirty_background_ratio;
    
    /* Aloca histórico de amostras */
    lih_memory->samples = kcalloc(lih_memory->config.history_size,
                                   sizeof(struct lih_memory_sample),
                                   GFP_KERNEL);
    if (!lih_memory->samples) {
        ret = -ENOMEM;
        goto out_free;
    }
    
    /* Inicializa estruturas de sincronização */
    spin_lock_init(&lih_memory->sample_lock);
    spin_lock_init(&lih_memory->process_lock);
    spin_lock_init(&lih_memory->oom_lock);
    INIT_LIST_HEAD(&lih_memory->process_list);
    BLOCKING_INIT_NOTIFIER_HEAD(&lih_memory->notifier_chain);
    srcu_init_notifier_head(&lih_memory->pressure_notifier);
    
    /* Obtém host do Mach */
    lih_memory->mach_host = mach_host_self();
    if (lih_memory->mach_host == MACH_PORT_NULL) {
        printk(KERN_WARNING "LIH Memory: Failed to get Mach host\n");
        lih_memory->config.enable_mach_sync = false;
    }
    
    /* Cria workqueue */
    lih_memory->monitor_wq = alloc_workqueue("lih_memory_wq",
                                              WQ_UNBOUND | WQ_MEM_RECLAIM,
                                              1);
    if (!lih_memory->monitor_wq) {
        ret = -ENOMEM;
        goto out_free_samples;
    }
    
    /* Inicializa work */
    INIT_DELAYED_WORK(&lih_memory->monitor_work, lih_monitor_work);
    
    /* Coleta inicial */
    lih_collect_linux_stats(&lih_memory->current_stats);
    lih_collect_pressure_stats(&lih_memory->current_stats);
    lih_collect_mach_stats(&lih_memory->current_stats);
    lih_memory->current_stats.pressure_level = LIH_MEM_PRESSURE_NONE;
    
    /* Inicia monitoramento */
    queue_delayed_work(lih_memory->monitor_wq,
                       &lih_memory->monitor_work,
                       msecs_to_jiffies(lih_memory->config.monitor_interval_ms));
    
    /* Inicializa estatísticas */
    lih_memory->stats.start_time = lih_memory_timestamp();
    ratelimit_state_init(&lih_memory->ratelimit, 5 * HZ, 10);
    
#ifdef CONFIG_PROC_FS
    /* Cria entrada /proc/lih_memory */
    lih_memory->proc_entry = proc_create("lih_memory", 0444, NULL,
                                          &lih_memory_proc_ops);
#endif
    
#ifdef CONFIG_DEBUG_FS
    /* Cria debugfs */
    lih_memory->debugfs_root = debugfs_create_dir("lih_memory", NULL);
    if (!IS_ERR(lih_memory->debugfs_root)) {
        debugfs_create_file("status", 0444, lih_memory->debugfs_root,
                            NULL, &lih_memory_debug_fops);
        debugfs_create_u32("pressure_level", 0444, lih_memory->debugfs_root,
                           (u32 *)&lih_memory->current_stats.pressure_level);
        debugfs_create_u64("free_ram", 0444, lih_memory->debugfs_root,
                           &lih_memory->current_stats.free_ram);
        debugfs_create_u64("free_swap", 0444, lih_memory->debugfs_root,
                           &lih_memory->current_stats.free_swap);
    }
#endif
    
    /* Registra sysctls */
    lih_memory_sysctl_header = register_sysctl("vm/lih_memory",
                                                 lih_memory_sysctls);
    
    lih_memory->state = 1;
    
    printk(KERN_INFO "LIH Memory Status initialized\n");
    printk(KERN_INFO "  - Total RAM: %llu MB\n",
           lih_memory->current_stats.total_ram >> 20);
    printk(KERN_INFO "  - Monitor interval: %d ms\n",
           lih_memory->config.monitor_interval_ms);
    printk(KERN_INFO "  - History size: %d samples\n",
           lih_memory->config.history_size);
    printk(KERN_INFO "  - Mach sync: %s\n",
           lih_memory->config.enable_mach_sync ? "enabled" : "disabled");
    
    return 0;

out_free_samples:
    kfree(lih_memory->samples);
out_free:
    kfree(lih_memory);
    lih_memory = NULL;
    
    return ret;
}

static void __exit lih_memory_exit(void)
{
    if (!lih_memory)
        return;
    
    printk(KERN_INFO "LIH Memory Status shutting down...\n");
    
    lih_memory->state = 0;
    
    /* Para monitoramento */
    cancel_delayed_work_sync(&lih_memory->monitor_work);
    
    /* Destroi workqueue */
    if (lih_memory->monitor_wq)
        destroy_workqueue(lih_memory->monitor_wq);
    
    /* Libera processos */
    lih_update_process_stats();  /* Limpa lista */
    
    /* Libera OOM protegidos */
    for (int i = 0; i < lih_memory->oom_protected_count; i++) {
        if (lih_memory->oom_protected_tasks[i])
            put_task_struct(lih_memory->oom_protected_tasks[i]);
    }
    
    /* Remove notifiers */
    srcu_cleanup_notifier_head(&lih_memory->pressure_notifier);
    
#ifdef CONFIG_PROC_FS
    if (lih_memory->proc_entry)
        remove_proc_entry("lih_memory", NULL);
#endif
    
#ifdef CONFIG_DEBUG_FS
    debugfs_remove_recursive(lih_memory->debugfs_root);
#endif
    
    /* Remove sysctls */
    if (lih_memory_sysctl_header)
        unregister_sysctl_table(lih_memory_sysctl_header);
    
    /* Libera memória */
    kfree(lih_memory->samples);
    kfree(lih_memory);
    lih_memory = NULL;
    
    printk(KERN_INFO "LIH Memory Status shut down\n");
}

module_init(lih_memory_init);
module_exit(lih_memory_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LIH Project");
MODULE_DESCRIPTION("LIH Memory Status - Unified memory management for Linux+Mach");
MODULE_VERSION("1.0");
