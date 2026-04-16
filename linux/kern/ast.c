/*
 * linux/kernel/linuz_ast.c - Linux AST (Asynchronous System Trap) Handler
 * 
 * Comunicação com o microkernel GNU Mach via IPC
 * 
 * Licença: GPLv2
 * 
 * Este arquivo permite que o Linux receba e processe ASTs vindos do Mach
 * ASTs são usadas para: preempção de threads, sinais, eventos de timer,
 * notificações de página, interrupções, etc.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <asm/current.h>
#include <asm/ptrace.h>

/* Headers do GNU Mach (assumindo que estão em /usr/include/mach) */
#include <mach/message.h>
#include <mach/port.h>
#include <mach/ast.h>

/* ============================================================================
 * Constantes e definições
 * ============================================================================ */

/* Portas Mach para comunicação */
static mach_port_t linux_ast_port;          /* Porta onde Linux recebe ASTs */
static mach_port_t mach_kernel_port;        /* Porta do kernel Mach */

/* Tipos de AST suportados */
#define AST_TYPE_NONE           0
#define AST_TYPE_PREEMPT        1   /* Preempção de thread */
#define AST_TYPE_SIGNAL         2   /* Entrega de sinal */
#define AST_TYPE_TIMER          3   /* Timer expirou */
#define AST_TYPE_PAGE_FAULT     4   /* Page fault tratado pelo Mach */
#define AST_TYPE_INTERRUPT      5   /* Interrupção de hardware */
#define AST_TYPE_IPC            6   /* Mensagem IPC recebida */
#define AST_TYPE_DEADLINE       7   /* Deadline scheduling */
#define AST_TYPE_POWER          8   /* Evento de energia */
#define AST_TYPE_DEBUG          9   /* Breakpoint/trace */

/* Flags para controle de AST */
#define AST_PENDING_PREEMPT     (1 << 0)
#define AST_PENDING_SIGNAL      (1 << 1)
#define AST_PENDING_TIMER       (1 << 2)
#define AST_PENDING_IPC         (1 << 3)

/* ============================================================================
 * Estruturas de dados
 * ============================================================================ */

/* Estrutura de uma mensagem AST vinda do Mach */
struct mach_ast_message {
    mach_msg_header_t header;
    mach_msg_type_t type;
    int ast_type;                    /* Tipo de AST (AST_TYPE_*) */
    int thread_id;                   /* Thread ID do Linux */
    union {
        struct {
            int signo;               /* Número do sinal */
            siginfo_t siginfo;       /* Informação do sinal */
        } signal;
        struct {
            unsigned long deadline;  /* Deadline em ciclos */
            unsigned long period;    /* Período para timers periódicos */
        } timer;
        struct {
            unsigned long vaddr;     /* Endereço virtual do page fault */
            unsigned long flags;     /* Flags de proteção */
        } page_fault;
        struct {
            int irq;                 /* Número da IRQ */
            struct pt_regs regs;     /* Registros no momento da IRQ */
        } interrupt;
        struct {
            mach_port_t reply_port;  /* Porta para resposta */
            void *data;              /* Dados da mensagem */
            size_t data_len;         /* Tamanho dos dados */
        } ipc;
    } data;
};

/* Estrutura para controle de AST por thread */
struct linux_ast_context {
    unsigned long pending_ast;       /* ASTs pendentes (AST_PENDING_*) */
    spinlock_t lock;                 /* Lock para acesso aos pendentes */
    struct task_struct *task;        /* Task associada */
    mach_port_t thread_port;         /* Porta Mach desta thread */
    wait_queue_head_t ast_wait;      /* Fila de espera para ASTs */
};

/* Array de contextos AST (máximo 4096 threads) */
static struct linux_ast_context *ast_contexts[4096];
static DEFINE_SPINLOCK(ast_contexts_lock);

/* Fila de ASTs pendentes globais */
static struct list_head pending_ast_list;
static spinlock_t pending_ast_lock;

/* ============================================================================
 * Funções auxiliares
 * ============================================================================ */

/* Converte thread Linux para índice no array */
static inline int task_to_index(struct task_struct *task)
{
    return task->pid % 4096;
}

/* Obtém contexto AST para uma thread */
static struct linux_ast_context *get_ast_context(struct task_struct *task)
{
    int idx = task_to_index(task);
    struct linux_ast_context *ctx;
    
    spin_lock(&ast_contexts_lock);
    ctx = ast_contexts[idx];
    spin_unlock(&ast_contexts_lock);
    
    /* Se não existe, cria um novo */
    if (!ctx) {
        ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
        if (ctx) {
            memset(ctx, 0, sizeof(*ctx));
            spin_lock_init(&ctx->lock);
            ctx->task = task;
            init_waitqueue_head(&ctx->ast_wait);
            
            spin_lock(&ast_contexts_lock);
            ast_contexts[idx] = ctx;
            spin_unlock(&ast_contexts_lock);
            
            /* Registra a thread no Mach */
            mach_thread_self(&ctx->thread_port);
        }
    }
    
    return ctx;
}

/* ============================================================================
 * Comunicação IPC com o Mach
 * ============================================================================ */

/* Envia uma mensagem para o kernel Mach */
static int mach_send_message(mach_port_t port, void *data, size_t len, int msg_id)
{
    mach_msg_header_t *msg;
    int ret;
    
    msg = kmalloc(sizeof(*msg) + len, GFP_ATOMIC);
    if (!msg)
        return -ENOMEM;
    
    msg->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg->msgh_size = len + sizeof(*msg);
    msg->msgh_remote_port = port;
    msg->msgh_local_port = MACH_PORT_NULL;
    msg->msgh_id = msg_id;
    
    if (data && len)
        memcpy(msg + 1, data, len);
    
    ret = mach_msg_send(msg);
    kfree(msg);
    
    return ret;
}

/* Recebe uma mensagem do kernel Mach (bloqueante) */
static int mach_receive_message(mach_port_t port, void *buffer, size_t buffer_len)
{
    mach_msg_header_t *msg = buffer;
    
    msg->msgh_local_port = port;
    msg->msgh_size = buffer_len;
    
    return mach_msg_receive(msg);
}

/* ============================================================================
 * Handlers para cada tipo de AST
 * ============================================================================ */

/* Handler de preempção - força rescheduling */
static void handle_ast_preempt(struct linux_ast_context *ctx, 
                                struct mach_ast_message *msg)
{
    struct task_struct *task = ctx->task;
    
    if (task && task == current) {
        /* Marca necessidade de reschedule */
        set_tsk_need_resched(task);
        
        /* Se for RT thread, pode precisar de ação imediata */
        if (task->policy == SCHED_FIFO || task->policy == SCHED_RR) {
            preempt_schedule_irq();
        }
    }
}

/* Handler de sinal - entrega sinal ao processo Linux */
static void handle_ast_signal(struct linux_ast_context *ctx,
                               struct mach_ast_message *msg)
{
    struct task_struct *task = ctx->task;
    int signo = msg->data.signal.signo;
    
    if (task && signo > 0 && signo < _NSIG) {
        /* Gera sinal no processo */
        if (msg->data.signal.siginfo.si_signo) {
            send_sig_info(signo, &msg->data.signal.siginfo, task);
        } else {
            send_sig(signo, task, 1);
        }
        
        /* Acorda a thread se estiver esperando por sinais */
        if (task_is_stopped_or_traced(task)) {
            wake_up_process(task);
        }
    }
}

/* Handler de timer - atualiza timers do Linux */
static void handle_ast_timer(struct linux_ast_context *ctx,
                              struct mach_ast_message *msg)
{
    struct task_struct *task = ctx->task;
    unsigned long deadline = msg->data.timer.deadline;
    
    if (task) {
        /* Atualiza o timer de itimer se necessário */
        if (task->signal && task->signal->it_real_incr) {
            task->signal->it_real_value = deadline;
        }
        
        /* Acorda a thread se estiver esperando por timer */
        if (task->state == TASK_INTERRUPTIBLE && 
            timer_pending(&task->signal->real_timer)) {
            wake_up_process(task);
        }
    }
}

/* Handler de page fault - tratado pelo Mach */
static void handle_ast_page_fault(struct linux_ast_context *ctx,
                                   struct mach_ast_message *msg)
{
    struct task_struct *task = ctx->task;
    unsigned long vaddr = msg->data.page_fault.vaddr;
    
    if (task && task->mm) {
        struct vm_area_struct *vma;
        
        down_read(&task->mm->mmap_sem);
        vma = find_vma(task->mm, vaddr);
        
        if (vma && vma->vm_ops && vma->vm_ops->fault) {
            /* A página foi mapeada pelo Mach, atualiza VM do Linux */
            vm_fault_t ret = vma->vm_ops->fault(vma, 
                                                 &(struct vm_fault){
                                                     .vma = vma,
                                                     .address = vaddr,
                                                     .flags = msg->data.page_fault.flags
                                                 });
            if (ret & VM_FAULT_OOM) {
                printk(KERN_ERR "LINUX_AST: OOM no page fault em 0x%lx\n", vaddr);
            }
        }
        up_read(&task->mm->mmap_sem);
    }
}

/* Handler de interrupção - repassa IRQ ao Linux */
static void handle_ast_interrupt(struct linux_ast_context *ctx,
                                  struct mach_ast_message *msg)
{
    int irq = msg->data.interrupt.irq;
    struct pt_regs *regs = &msg->data.interrupt.regs;
    
    /* Chama o handler de IRQ do Linux */
    if (irq < NR_IRQS) {
        handle_irq(irq, regs);
    } else {
        printk(KERN_WARNING "LINUX_AST: IRQ inválido %d\n", irq);
    }
}

/* Handler de IPC - mensagem de outro processo */
static void handle_ast_ipc(struct linux_ast_context *ctx,
                            struct mach_ast_message *msg)
{
    struct task_struct *task = ctx->task;
    
    if (task) {
        /* Adiciona à fila de mensagens IPC do processo */
        spin_lock(&task->signal->ipc_lock);
        /* Implementação depende do subsistema IPC do Linux */
        spin_unlock(&task->signal->ipc_lock);
        
        /* Acorda processo se estiver bloqueado em msgrcv */
        if (task->state == TASK_INTERRUPTIBLE &&
            test_bit(TIF_SIGPENDING, &task->thread_info.flags) == 0) {
            wake_up_process(task);
        }
    }
}

/* ============================================================================
 * Processador principal de ASTs
 * ============================================================================ */

/* Processa um AST vindo do Mach */
static void process_ast_message(struct mach_ast_message *msg)
{
    struct linux_ast_context *ctx;
    int thread_id = msg->thread_id;
    
    /* Encontra o contexto da thread */
    rcu_read_lock();
    ctx = ast_contexts[thread_id % 4096];
    
    if (ctx && ctx->task) {
        switch (msg->ast_type) {
        case AST_TYPE_PREEMPT:
            handle_ast_preempt(ctx, msg);
            break;
        case AST_TYPE_SIGNAL:
            handle_ast_signal(ctx, msg);
            break;
        case AST_TYPE_TIMER:
            handle_ast_timer(ctx, msg);
            break;
        case AST_TYPE_PAGE_FAULT:
            handle_ast_page_fault(ctx, msg);
            break;
        case AST_TYPE_INTERRUPT:
            handle_ast_interrupt(ctx, msg);
            break;
        case AST_TYPE_IPC:
            handle_ast_ipc(ctx, msg);
            break;
        default:
            printk(KERN_WARNING "LINUX_AST: AST desconhecido %d\n", msg->ast_type);
        }
    }
    
    rcu_read_unlock();
}

/* Thread principal que escuta ASTs do Mach */
static int ast_listener_thread(void *unused)
{
    struct mach_ast_message msg;
    int ret;
    
    printk(KERN_INFO "LINUX_AST: Iniciando listener de ASTs\n");
    
    while (1) {
        /* Aguarda ASTs do Mach */
        ret = mach_receive_message(linux_ast_port, &msg, sizeof(msg));
        
        if (ret == MACH_MSG_SUCCESS) {
            process_ast_message(&msg);
        } else if (ret != MACH_RCV_TIMED_OUT) {
            printk(KERN_ERR "LINUX_AST: Erro no receive: %d\n", ret);
            set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(HZ);
        }
    }
    
    return 0;
}

/* ============================================================================
 * Funções exportadas para o resto do kernel Linux
 * ============================================================================ */

/**
 * linuz_ast_send - Envia um AST para o Mach
 * @task: Task Linux alvo
 * @ast_type: Tipo de AST
 * @data: Dados adicionais (opcional)
 * @len: Tamanho dos dados
 */
int linuz_ast_send(struct task_struct *task, int ast_type, void *data, size_t len)
{
    struct linux_ast_context *ctx;
    struct mach_ast_message msg;
    int ret = 0;
    
    if (!task)
        return -EINVAL;
    
    ctx = get_ast_context(task);
    if (!ctx)
        return -ENOMEM;
    
    memset(&msg, 0, sizeof(msg));
    msg.ast_type = ast_type;
    msg.thread_id = task->pid;
    
    if (data && len && len <= sizeof(msg.data))
        memcpy(&msg.data, data, len);
    
    ret = mach_send_message(mach_kernel_port, &msg, sizeof(msg), 
                            MACH_AST_MESSAGE_ID);
    
    return ret;
}
EXPORT_SYMBOL(linuz_ast_send);

/**
 * linuz_ast_pending - Verifica se há ASTs pendentes
 * @task: Task a verificar
 */
int linuz_ast_pending(struct task_struct *task)
{
    struct linux_ast_context *ctx = get_ast_context(task);
    
    if (!ctx)
        return 0;
    
    return ctx->pending_ast != 0;
}
EXPORT_SYMBOL(linuz_ast_pending);

/**
 * linuz_ast_wait - Aguarda um AST específico
 * @task: Task atual
 * @ast_type: Tipo de AST a esperar
 * @timeout: Timeout em jiffies (0 = infinito)
 */
int linuz_ast_wait(struct task_struct *task, int ast_type, long timeout)
{
    struct linux_ast_context *ctx = get_ast_context(task);
    unsigned long flags;
    int ret = 0;
    
    if (!ctx)
        return -ENOMEM;
    
    spin_lock_irqsave(&ctx->lock, flags);
    
    /* Verifica se já está pendente */
    if (ctx->pending_ast & (1 << ast_type)) {
        ctx->pending_ast &= ~(1 << ast_type);
        spin_unlock_irqrestore(&ctx->lock, flags);
        return 0;
    }
    
    spin_unlock_irqrestore(&ctx->lock, flags);
    
    /* Aguarda o AST */
    ret = wait_event_interruptible_timeout(ctx->ast_wait, 
                                            ctx->pending_ast & (1 << ast_type),
                                            timeout);
    
    if (ret > 0) {
        spin_lock_irqsave(&ctx->lock, flags);
        ctx->pending_ast &= ~(1 << ast_type);
        spin_unlock_irqrestore(&ctx->lock, flags);
        return 0;
    }
    
    return ret == 0 ? -ETIMEDOUT : -EINTR;
}
EXPORT_SYMBOL(linuz_ast_wait);

/**
 * linuz_ast_register_thread - Registra uma thread Linux no Mach
 * @task: Task a registrar
 */
int linuz_ast_register_thread(struct task_struct *task)
{
    struct linux_ast_context *ctx;
    
    ctx = get_ast_context(task);
    if (!ctx)
        return -ENOMEM;
    
    /* Registra a thread no scheduler do Mach */
    return mach_send_message(mach_kernel_port, &task->pid, sizeof(task->pid),
                             MACH_REGISTER_THREAD);
}
EXPORT_SYMBOL(linuz_ast_register_thread);

/**
 * linuz_ast_unregister_thread - Remove registro de thread
 * @task: Task a remover
 */
void linuz_ast_unregister_thread(struct task_struct *task)
{
    int idx = task_to_index(task);
    
    spin_lock(&ast_contexts_lock);
    if (ast_contexts[idx]) {
        kfree(ast_contexts[idx]);
        ast_contexts[idx] = NULL;
    }
    spin_unlock(&ast_contexts_lock);
}
EXPORT_SYMBOL(linuz_ast_unregister_thread);

/* ============================================================================
 * Inicialização do subsistema AST
 * ============================================================================ */

static int __init linuz_ast_init(void)
{
    int ret;
    
    printk(KERN_INFO "LINUX_AST: Inicializando comunicação AST Linux-Mach\n");
    
    /* Cria porta para receber ASTs */
    ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, 
                              &linux_ast_port);
    if (ret != KERN_SUCCESS) {
        printk(KERN_ERR "LINUX_AST: Falha ao alocar porta Mach\n");
        return -ENODEV;
    }
    
    /* Obtém porta do kernel Mach */
    mach_kernel_port = mach_host_self();
    
    /* Inicializa filas */
    INIT_LIST_HEAD(&pending_ast_list);
    spin_lock_init(&pending_ast_lock);
    
    /* Cria thread listener */
    ret = kernel_thread(ast_listener_thread, NULL, CLONE_FS | CLONE_FILES);
    if (ret < 0) {
        printk(KERN_ERR "LINUX_AST: Falha ao criar thread listener\n");
        mach_port_deallocate(mach_task_self(), linux_ast_port);
        return ret;
    }
    
    printk(KERN_INFO "LINUX_AST: Inicializado com sucesso, porta=%d\n", 
           linux_ast_port);
    
    return 0;
}

static void __exit linuz_ast_exit(void)
{
    printk(KERN_INFO "LINUX_AST: Finalizando...\n");
    
    /* Libera porta Mach */
    mach_port_deallocate(mach_task_self(), linux_ast_port);
    mach_port_deallocate(mach_task_self(), mach_kernel_port);
    
    printk(KERN_INFO "LINUX_AST: Finalizado\n");
}

module_init(linuz_ast_init);
module_exit(linuz_ast_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LIH Project");
MODULE_DESCRIPTION("Linux AST communication with GNU Mach microkernel");
MODULE_VERSION("0.1");
