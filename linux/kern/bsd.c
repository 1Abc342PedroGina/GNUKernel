/*
 * linux/kernel/bsd.c - BSD Process to Linux Thread Translation Layer
 * 
 * Traduz estruturas de processos BSD (sys/proc.h do FreeBSD 15) 
 * para task_struct do Linux
 * 
 * Parte do projeto LIH (Linux Is Hybrid) - integração Linux + Mach
 * 
 * Licença: GPLv2 (compatível com FreeBSD)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/rculist.h>
#include <linux/idr.h>
#include <linux/random.h>
#include <asm/atomic.h>

/* Headers BSD (FreeBSD 15) que são usados pelo kernel Mach */
/* Estes headers estão em /usr/include/bsd/sys/ no ambiente LIH */
#include <bsd/sys/param.h>
#include <bsd/sys/proc.h>
#include <bsd/sys/user.h>
#include <bsd/sys/resource.h>
#include <bsd/sys/signalvar.h>
#include <bsd/sys/filedesc.h>
#include <bsd/sys/vnode.h>
#include <bsd/sys/mutex.h>
#include <bsd/sys/sx.h>
#include <bsd/sys/kthread.h>

/* ============================================================================
 * Constantes e definições
 * ============================================================================ */

#define BSD_MAX_PROCESSES      65536   /* Máximo de processos BSD */
#define BSD_TID_TO_PID_SHIFT   16      /* Shift para converter TID -> PID BSD */
#define LINUX_TASK_COMM_LEN    16      /* Comando do Linux (TASK_COMM_LEN) */

/* Mapeamento de estados BSD para Linux */
static const int bsd_state_to_linux[] = {
    [0]                     = TASK_RUNNING,        /* Unused */
    [SIDL]                  = TASK_NEW,            /* Processo em criação */
    [SRUN]                  = TASK_RUNNING,        /* Executando */
    [SSLEEP]                = TASK_INTERRUPTIBLE,  /* Dormindo */
    [SSTOP]                 = TASK_STOPPED,        /* Parado */
    [SZOMB]                 = TASK_DEAD,           /* Zombie */
    [SWAIT]                 = TASK_UNINTERRUPTIBLE,/* Esperando */
    [SLOCK]                 = TASK_UNINTERRUPTIBLE /* Locked */
};

/* Mapeamento de prioridades BSD para Linux (nice value) */
static inline int bsd_prio_to_linux_nice(priority_t bsd_prio)
{
    /* BSD: 0 (max) a 127 (min) -> Linux: -20 (max) a 19 (min) */
    int nice = (bsd_prio - PUSER) / 4;
    return clamp(nice, -20, 19);
}

/* Mapeamento de flags BSD para Linux */
#define BSD_P_CONTROLT       0x0001  /* Has controlling terminal */
#define BSD_P_INEXEC         0x0002  /* In exec() */
#define BSD_P_PPWAIT         0x0004  /* Parent waiting for child exec/exit */
#define BSD_P_PROFDESC       0x0008  /* Has profiling descriptor */
#define BSD_P_STOPPROF       0x0010  /* Has stopped profiling */
#define BSD_P_HADTHREADS     0x0020  /* Historically had threads */
#define BSD_P_SUGID          0x0040  /* Had set id privileges */
#define BSD_P_SYSTEM         0x0080  /* System process (no sigs, etc) */
#define BSD_P_SINGLE_BOUNDARY 0x0100 /* Threads in single threading mode */
#define BSD_P_TRACE          0x0200  /* Process being traced */
#define BSD_P_WAITED         0x0400  /* Debugging process has waited */
#define BSD_P_WEXIT          0x0800  /* Working on exiting */
#define BSD_P_EXEC           0x1000  /* Process called exec */

#define BSD_TD_IDLE          0x0001  /* Thread is idle */
#define BSD_TD_SINTR         0x0002  /* Sleep is interruptible */
#define BSD_TD_ONCPU         0x0004  /* Thread is on CPU */
#define BSD_TD_UNUSED        0x0008  /* Unused */
#define BSD_TD_RUNQ          0x0010  /* Thread is on run queue */
#define BSD_TD_SLICE         0x0020  /* Has time slice */
#define BSD_TD_CAN_UNBIND    0x0040  /* Can be unbound from CPU */
#define BSD_TD_SCHED         0x0080  /* Thread is in scheduler */
#define BSD_TD_BOUND         0x0100  /* Bound to CPU */
#define BSD_TD_FPU           0x0200  /* FPU context is saved */
#define BSD_TD_OWEPREEMPT    0x0400  /* Kernel preemption enabled */
#define BSD_TD_SUSPENDED     0x0800  /* Thread is suspended */
#define BSD_TD_SLEEPABORT    0x1000  /* Sleep was aborted */

/* ============================================================================
 * Estruturas de dados do tradutor
 * ============================================================================ */

/* Contexto BSD para cada task_struct Linux */
struct bsd_process_context {
    /* Estrutura BSD original (mapeada/copiada) */
    struct proc *bsd_proc;           /* Ponteiro para struct proc do BSD */
    struct thread *bsd_thread;       /* Ponteiro para struct thread do BSD */
    
    /* Task Linux associada */
    struct task_struct *linux_task;
    
    /* Mapeamento de IDs */
    pid_t bsd_pid;                   /* PID no BSD */
    pid_t bsd_tid;                   /* TID no BSD (para threads) */
    
    /* Estado da tradução */
    spinlock_t lock;                 /* Lock para acesso concorrente */
    unsigned long translation_flags; /* Flags de estado da tradução */
    
    /* Recursos mapeados */
    struct files_struct *bsd_files;  /* Descritores de arquivo BSD mapeados */
    struct mm_struct *bsd_mm;        /* Memória BSD mapeada */
    struct signal_struct *bsd_signal; /* Sinais BSD mapeados */
    
    /* Cache de tradução */
    uid_t cached_uid;                /* UID em cache */
    gid_t cached_gid;                /* GID em cache */
    int cached_nice;                 /* Nice value em cache */
};

/* Tabela global de mapeamento BSD -> Linux */
static struct idr bsd_to_linux_idr;
static DEFINE_RWLOCK(bsd_translation_lock);

/* Fila de processos BSD aguardando tradução */
static LIST_HEAD(bsd_pending_queue);
static DEFINE_SPINLOCK(bsd_pending_lock);

/* ============================================================================
 * Funções de tradução de tipos BSD para Linux
 * ============================================================================ */

/* Traduz flags BSD para flags de task Linux */
static unsigned long translate_bsd_flags_to_linux(struct proc *p, struct thread *td)
{
    unsigned long linux_flags = 0;
    
    /* Traduz flags do processo BSD */
    if (p->p_flag & BSD_P_SYSTEM)
        linux_flags |= PF_KTHREAD;           /* Kernel thread */
    if (p->p_flag & BSD_P_TRACE)
        current->ptrace |= PT_PTRACED;       /* Being traced */
    if (p->p_flag & BSD_P_SUGID)
        linux_flags |= PF_SUPERPRIV;         /* Superuser privileges */
    
    /* Traduz flags da thread BSD */
    if (td->td_flags & BSD_TD_IDLE)
        linux_flags |= PF_IDLE;              /* Idle thread */
    if (td->td_flags & BSD_TD_SINTR)
        linux_flags |= PF_SIGNALED;          /* Interruptible sleep */
    if (td->td_flags & BSD_TD_ONCPU)
        linux_flags |= PF_KSOFTIRQD;         /* On CPU (softirq context) */
    
    return linux_flags;
}

/* Traduz credenciais BSD para credenciais Linux */
static void translate_bsd_creds_to_linux(struct proc *p, struct task_struct *task)
{
    struct cred *new_cred;
    
    new_cred = prepare_creds();
    if (!new_cred)
        return;
    
    /* UIDs */
    new_cred->uid.val = p->p_ucred->cr_uid;
    new_cred->gid.val = p->p_ucred->cr_gid;
    new_cred->suid.val = p->p_ucred->cr_uid;     /* BSD não tem saved uid separado */
    new_cred->sgid.val = p->p_ucred->cr_gid;
    new_cred->euid.val = p->p_ucred->cr_uid;
    new_cred->egid.val = p->p_ucred->cr_gid;
    new_cred->fsuid.val = p->p_ucred->cr_uid;
    new_cred->fsgid.val = p->p_ucred->cr_gid;
    
    /* Grupos suplementares */
    if (p->p_ucred->cr_ngroups > 0) {
        int i;
        new_cred->group_info = groups_alloc(p->p_ucred->cr_ngroups);
        if (new_cred->group_info) {
            for (i = 0; i < p->p_ucred->cr_ngroups; i++)
                new_cred->group_info->gid[i].val = p->p_ucred->cr_groups[i];
            set_groups(new_cred, new_cred->group_info);
        }
    }
    
    /* Capacidades (BSD não tem, então concede capacidades padrão) */
    cap_set_full(&new_cred->cap_effective);
    cap_set_full(&new_cred->cap_inheritable);
    cap_set_full(&new_cred->cap_permitted);
    
    commit_creds(new_cred);
}

/* Traduz a estrutura rusage BSD para Linux */
static void translate_bsd_rusage_to_linux(struct rusage_bsd *bsd_ru, 
                                           struct task_struct *task)
{
    struct task_io_accounting *io = &task->ioac;
    
    /* Tempo de usuário e sistema */
    task->utime = nsec_to_clock_t(
        bsd_ru->ru_utime.tv_sec * NSEC_PER_SEC + 
        bsd_ru->ru_utime.tv_usec * NSEC_PER_USEC);
    task->stime = nsec_to_clock_t(
        bsd_ru->ru_stime.tv_sec * NSEC_PER_SEC + 
        bsd_ru->ru_stime.tv_usec * NSEC_PER_USEC);
    
    /* I/O counters */
    io->rchar = bsd_ru->ru_inblock * 512;      /* Assume 512 bytes per block */
    io->wchar = bsd_ru->ru_oublock * 512;
    io->syscr = bsd_ru->ru_majflt;              /* Major faults */
    io->syscw = bsd_ru->ru_nvcsw;               /* Voluntary context switches */
}

/* Traduz sinal BSD para sinal Linux */
static int translate_bsd_signal_to_linux(int bsd_sig)
{
    /* Mapeamento de sinais BSD para Linux (maioria é idêntica) */
    static const int sig_map[NSIG] = {
        [0] = 0,
        [SIGHUP]    = SIGHUP,
        [SIGINT]    = SIGINT,
        [SIGQUIT]   = SIGQUIT,
        [SIGILL]    = SIGILL,
        [SIGTRAP]   = SIGTRAP,
        [SIGABRT]   = SIGABRT,
        [SIGEMT]    = SIGUSR1,     /* EMT trap -> mapeado para USR1 */
        [SIGFPE]    = SIGFPE,
        [SIGKILL]   = SIGKILL,
        [SIGBUS]    = SIGBUS,
        [SIGSEGV]   = SIGSEGV,
        [SIGSYS]    = SIGSYS,
        [SIGPIPE]   = SIGPIPE,
        [SIGALRM]   = SIGALRM,
        [SIGTERM]   = SIGTERM,
        [SIGURG]    = SIGURG,
        [SIGSTOP]   = SIGSTOP,
        [SIGTSTP]   = SIGTSTP,
        [SIGCONT]   = SIGCONT,
        [SIGCHLD]   = SIGCHLD,
        [SIGTTIN]   = SIGTTIN,
        [SIGTTOU]   = SIGTTOU,
        [SIGIO]     = SIGIO,
        [SIGXCPU]   = SIGXCPU,
        [SIGXFSZ]   = SIGXFSZ,
        [SIGVTALRM] = SIGVTALRM,
        [SIGPROF]   = SIGPROF,
        [SIGWINCH]  = SIGWINCH,
        [SIGINFO]   = SIGPWR,      /* SIGINFO -> SIGPWR */
        [SIGUSR1]   = SIGUSR1,
        [SIGUSR2]   = SIGUSR2
    };
    
    if (bsd_sig < 0 || bsd_sig >= NSIG)
        return 0;
    
    return sig_map[bsd_sig];
}

/* ============================================================================
 * Funções principais de tradução
 * ============================================================================ */

/**
 * bsd_proc_to_linux_task - Traduz struct proc BSD para task_struct Linux
 * @p: Ponteiro para struct proc do BSD
 * @td: Ponteiro para struct thread do BSD (opcional)
 * 
 * Retorna: Ponteiro para task_struct Linux ou ERR_PTR(-errno)
 */
struct task_struct *bsd_proc_to_linux_task(struct proc *p, struct thread *td)
{
    struct task_struct *task;
    struct bsd_process_context *ctx;
    unsigned long flags;
    int ret;
    
    if (!p)
        return ERR_PTR(-EINVAL);
    
    /* Verifica se já existe uma task Linux para este BSD proc */
    read_lock_irqsave(&bsd_translation_lock, flags);
    task = idr_find(&bsd_to_linux_idr, p->p_pid);
    read_unlock_irqrestore(&bsd_translation_lock, flags);
    
    if (task) {
        /* Já traduzido, apenas atualiza */
        ctx = (struct bsd_process_context *)task->bsd_context;
        if (ctx) {
            ctx->bsd_proc = p;
            if (td)
                ctx->bsd_thread = td;
        }
        return task;
    }
    
    /* Cria nova task_struct Linux */
    task = alloc_task_struct_node(NUMA_NO_NODE);
    if (!task)
        return ERR_PTR(-ENOMEM);
    
    /* Inicializa task_struct mínima */
    ret = arch_dup_task_struct(task, current);
    if (ret) {
        free_task_struct(task);
        return ERR_PTR(ret);
    }
    
    /* Configura campos básicos */
    task->pid = p->p_pid;
    task->tgid = p->p_pid;
    
    /* Nome do processo */
    strscpy(task->comm, p->p_comm, TASK_COMM_LEN);
    
    /* Estado */
    task->__state = bsd_state_to_linux[p->p_state];
    
    /* Prioridade e nice */
    task->static_prio = bsd_prio_to_linux_nice(p->p_priority);
    task->normal_prio = task->static_prio;
    task->prio = task->static_prio;
    
    /* Flags */
    task->flags = translate_bsd_flags_to_linux(p, td);
    
    /* Credenciais */
    translate_bsd_creds_to_linux(p, task);
    
    /* Tempos */
    task->start_time = ktime_get_ns();
    task->real_start_time = task->start_time;
    
    /* Cria contexto BSD */
    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) {
        free_task_struct(task);
        return ERR_PTR(-ENOMEM);
    }
    
    ctx->bsd_proc = p;
    ctx->bsd_thread = td;
    ctx->linux_task = task;
    ctx->bsd_pid = p->p_pid;
    ctx->bsd_tid = td ? td->td_tid : p->p_pid;
    spin_lock_init(&ctx->lock);
    
    task->bsd_context = ctx;
    
    /* Armazena no mapeamento global */
    write_lock_irqsave(&bsd_translation_lock, flags);
    idr_alloc(&bsd_to_linux_idr, task, p->p_pid, p->p_pid + 1, GFP_ATOMIC);
    write_unlock_irqrestore(&bsd_translation_lock, flags);
    
    return task;
}
EXPORT_SYMBOL(bsd_proc_to_linux_task);

/**
 * bsd_task_to_linux_task - Traduz thread BSD para task_struct Linux
 * @td: Ponteiro para struct thread do BSD
 * 
 * Retorna: Ponteiro para task_struct Linux
 */
struct task_struct *bsd_task_to_linux_task(struct thread *td)
{
    if (!td || !td->td_proc)
        return ERR_PTR(-EINVAL);
    
    return bsd_proc_to_linux_task(td->td_proc, td);
}
EXPORT_SYMBOL(bsd_task_to_linux_task);

/**
 * bsd_fork_translate - Traduz fork() BSD para clone() Linux
 * @parent_bsd: Processo BSD pai
 * @child_bsd: Processo BSD filho (já criado pelo Mach)
 * @flags: Flags de fork/clone
 * 
 * Retorna: task_struct do filho ou ERR_PTR
 */
struct task_struct *bsd_fork_translate(struct proc *parent_bsd, 
                                        struct proc *child_bsd,
                                        unsigned long flags)
{
    struct task_struct *parent_task;
    struct task_struct *child_task;
    struct bsd_process_context *parent_ctx;
    
    /* Obtém task do pai */
    parent_task = bsd_proc_to_linux_task(parent_bsd, NULL);
    if (IS_ERR(parent_task))
        return parent_task;
    
    parent_ctx = (struct bsd_process_context *)parent_task->bsd_context;
    
    /* Cria task do filho usando clone() */
    child_task = copy_process(NULL, 0, 0, NULL, NULL, flags);
    if (IS_ERR(child_task))
        return child_task;
    
    /* Associa ao BSD proc filho */
    child_task->bsd_context = parent_ctx; /* Reaproveita contexto por enquanto */
    child_task->pid = child_bsd->p_pid;
    child_task->tgid = child_bsd->p_pid;
    
    /* Cria novo contexto para o filho */
    struct bsd_process_context *child_ctx = kmemdup(parent_ctx, sizeof(*child_ctx), 
                                                     GFP_KERNEL);
    if (child_ctx) {
        child_ctx->bsd_proc = child_bsd;
        child_ctx->linux_task = child_task;
        child_ctx->bsd_pid = child_bsd->p_pid;
        child_task->bsd_context = child_ctx;
    }
    
    /* Registra no mapeamento */
    idr_replace(&bsd_to_linux_idr, child_task, child_bsd->p_pid);
    
    return child_task;
}
EXPORT_SYMBOL(bsd_fork_translate);

/* ============================================================================
 * Funções de sincronização e comunicação com Mach
 * ============================================================================ */

/**
 * bsd_sync_signal - Sincroniza sinal entre BSD e Linux
 * @p: Processo BSD
 * @sig: Sinal a sincronizar
 */
void bsd_sync_signal(struct proc *p, int sig)
{
    struct task_struct *task;
    int linux_sig;
    
    task = bsd_proc_to_linux_task(p, NULL);
    if (IS_ERR(task))
        return;
    
    linux_sig = translate_bsd_signal_to_linux(sig);
    if (linux_sig > 0)
        send_sig(linux_sig, task, 0);
}
EXPORT_SYMBOL(bsd_sync_signal);

/**
 * bsd_sync_resource_usage - Sincroniza uso de recursos BSD para Linux
 * @p: Processo BSD
 */
void bsd_sync_resource_usage(struct proc *p)
{
    struct task_struct *task;
    struct bsd_process_context *ctx;
    struct rusage_bsd bsd_ru;
    unsigned long flags;
    
    task = bsd_proc_to_linux_task(p, NULL);
    if (IS_ERR(task))
        return;
    
    ctx = (struct bsd_process_context *)task->bsd_context;
    if (!ctx)
        return;
    
    spin_lock_irqsave(&ctx->lock, flags);
    
    /* Coleta rusage do BSD */
    if (ctx->bsd_proc) {
        /* Chama função do BSD para preencher rusage */
        /* calcru_bsd(ctx->bsd_proc, &bsd_ru.ru_utime, &bsd_ru.ru_stime, NULL); */
        
        translate_bsd_rusage_to_linux(&bsd_ru, task);
    }
    
    spin_unlock_irqrestore(&ctx->lock, flags);
}
EXPORT_SYMBOL(bsd_sync_resource_usage);

/**
 * bsd_wait_translate - Traduz wait4() BSD para wait4() Linux
 * @p: Processo BSD que está esperando
 * @options: Opções de wait
 * @rusage: Ponteiro para rusage (saída)
 */
pid_t bsd_wait_translate(struct proc *p, int options, struct rusage *rusage)
{
    struct task_struct *task;
    struct task_struct *child;
    pid_t ret;
    
    task = bsd_proc_to_linux_task(p, NULL);
    if (IS_ERR(task))
        return PTR_ERR(task);
    
    /* Traduz e chama wait4 do Linux */
    ret = kernel_wait4(-1, NULL, options, rusage);
    
    if (ret > 0) {
        /* Encontra o child no mapeamento BSD */
        rcu_read_lock();
        child = find_task_by_vpid(ret);
        if (child && child->bsd_context) {
            /* Atualiza estado do processo BSD filho */
            struct bsd_process_context *child_ctx = child->bsd_context;
            if (child_ctx->bsd_proc)
                child_ctx->bsd_proc->p_state = SZOMB;
        }
        rcu_read_unlock();
    }
    
    return ret;
}
EXPORT_SYMBOL(bsd_wait_translate);

/* ============================================================================
 * Funções de gerenciamento de memória BSD -> Linux
 * ============================================================================ */

/**
 * bsd_map_vmspace - Mapeia espaço de memória BSD para Linux mm_struct
 * @p: Processo BSD
 * @linux_task: Task Linux alvo
 */
int bsd_map_vmspace(struct proc *p, struct task_struct *linux_task)
{
    struct vmspace *bsd_vm = p->p_vmspace;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct vm_map *map;
    struct vm_map_entry *entry;
    unsigned long start, end;
    
    if (!bsd_vm)
        return -EINVAL;
    
    /* Cria mm_struct vazio */
    mm = mm_alloc();
    if (!mm)
        return -ENOMEM;
    
    /* Obtém o mapa de memória BSD */
    map = &bsd_vm->vm_map;
    
    /* Itera sobre as entradas do mapa BSD */
    vm_map_lock_read(map);
    
    for (entry = map->header.next; 
         entry != &map->header; 
         entry = entry->next) {
        
        if (entry->is_a_map || entry->is_sub_map)
            continue;
        
        start = (unsigned long)entry->start;
        end = (unsigned long)entry->end;
        
        /* Cria VMA correspondente no Linux */
        vma = vm_area_alloc(mm);
        if (!vma) {
            vm_map_unlock_read(map);
            mmput(mm);
            return -ENOMEM;
        }
        
        vma->vm_start = start;
        vma->vm_end = end;
        vma->vm_flags = entry->protection;
        
        /* Mapeia para o Mach via VM remota */
        vma->vm_ops = &bsd_vm_ops;
        vma->vm_private_data = (void *)entry->object.uvm_object;
        
        /* Insere na árvore de VMAs */
        vm_area_insert(mm, vma);
    }
    
    vm_map_unlock_read(map);
    
    /* Troca o mm da task */
    linux_task->mm = mm;
    linux_task->active_mm = mm;
    
    return 0;
}
EXPORT_SYMBOL(bsd_map_vmspace);

/* ============================================================================
 * Inicialização e finalização
 * ============================================================================ */

static int __init bsd_translation_init(void)
{
    printk(KERN_INFO "BSD-Linux: Inicializando tradutor de processos\n");
    
    /* Inicializa IDR para mapeamento */
    idr_init(&bsd_to_linux_idr);
    
    printk(KERN_INFO "BSD-Linux: Tradutor inicializado (max %d processos)\n",
           BSD_MAX_PROCESSES);
    
    return 0;
}

static void __exit bsd_translation_exit(void)
{
    struct bsd_process_context *ctx;
    int id;
    void *p;
    
    printk(KERN_INFO "BSD-Linux: Finalizando tradutor\n");
    
    /* Limpa mapeamentos */
    idr_for_each_entry(&bsd_to_linux_idr, p, id) {
        struct task_struct *task = (struct task_struct *)p;
        if (task && task->bsd_context) {
            ctx = (struct bsd_process_context *)task->bsd_context;
            kfree(ctx);
            task->bsd_context = NULL;
        }
    }
    
    idr_destroy(&bsd_to_linux_idr);
    
    printk(KERN_INFO "BSD-Linux: Tradutor finalizado\n");
}

module_init(bsd_translation_init);
module_exit(bsd_translation_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LIH Project");
MODULE_DESCRIPTION("BSD Process to Linux Task Translation Layer");
MODULE_VERSION("1.0");
