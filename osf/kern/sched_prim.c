/* GNUKernel operating system
 * Copyright (c) 2026-2024 My House
 * All Rights Reserved 
 * Copyright (C) 2026  Pedro Emanuel
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */
/*
 * Mach Operating System
 * Copyright (c) 1993-1988 Carnegie Mellon University
 * All Rights Reserved.
 * License:DGPL-2.0-or-later
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 *	File:	sched_prim.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Scheduling primitives
 *
 */

/*
 * Mach Operating System
 * Copyright (c) 1993-2024 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Enhanced with EEVDF (Earliest Eligible Virtual Deadline First) Scheduler
 * Combining Mach and Linux scheduling concepts
 */

#include <kern/printf.h>
#include <mach/machine.h>
#include <machine/locore.h>
#include <machine/spl.h>
#include <machine/model_dep.h>
#include <kern/ast.h>
#include <kern/counters.h>
#include <kern/cpu_number.h>
#include <kern/debug.h>
#include <kern/lock.h>
#include <kern/mach_clock.h>
#include <kern/mach_factor.h>
#include <kern/macros.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <machine/machine.h>
#include <machine/pal.h>
#include <machine/md.h>
#include <kern/cpu_number.h>
#include <kern/processor.h>
#include <kern/smp.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <machine/srat.h>  /* For SRAT table parsing */
#include <kern/smp.h>
#include <kern/syscall_subr.h>
#include <kern/thread.h>
#include <kern/thread_swap.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <linux/sched.h>  /* Linux scheduling structures */

/*
 * EEVDF Scheduler Core Structures
 * Combines Mach thread management with Linux EEVDF algorithm
 */

/* EEVDF Scheduling Constants */
#define EEVDF_MIN_GRANULARITY_NS    1000000ULL      /* 1ms minimum granularity */
#define EEVDF_MAX_GRANULARITY_NS    10000000ULL     /* 10ms maximum granularity */
#define EEVDF_LATENCY_NS            6000000ULL      /* 6ms target latency */
#define EEVDF_MIN_VIRTUAL_TIME      0ULL
#define EEVDF_MAX_VIRTUAL_TIME      (~0ULL)
#define EEVDF_WEIGHT_SCALE          1024LL          /* Nice weight scale */
#define EEVDF_WEIGHT_SHIFT          10              /* Weight shift factor */
#define EEVDF_DEADLINE_MARGIN_NS    100000ULL       /* 100us deadline margin */
#define EEVDF_PREEMPTION_THRESHOLD  0               /* Preemption threshold */

/* EEVDF Task States */
typedef enum {
    EEVDF_TASK_RUNNING = 0,
    EEVDF_TASK_RUNNABLE,
    EEVDF_TASK_SLEEPING,
    EEVDF_TASK_STOPPED,
    EEVDF_TASK_ZOMBIE,
    EEVDF_TASK_DEAD
} eevdf_task_state_t;

/* EEVDF Scheduling Class */
typedef enum {
    SCHED_CLASS_IDLE = 0,
    SCHED_CLASS_NORMAL,
    SCHED_CLASS_RT,
    SCHED_CLASS_DEADLINE
} eevdf_sched_class_t;

/*
 * EEVDF Scheduling Entity
 * Embedded in thread structure
 */
struct eevdf_sched_entity {
    /* Virtual runtime tracking */
    unsigned long long vruntime;           /* Virtual runtime (nanoseconds) */
    unsigned long long min_vruntime;       /* Minimum vruntime in system */
    unsigned long long deadline;           /* Current deadline */
    unsigned long long eligible_time;      /* Time when entity becomes eligible */
    unsigned long long lag;                /* Scheduling lag */
    
    /* Execution tracking */
    unsigned long long sum_exec_runtime;   /* Total execution time */
    unsigned long long prev_sum_exec_runtime; /* Previous execution time */
    unsigned long long exec_start;         /* Last execution start time */
    unsigned long long slice;              /* Time slice length */
    unsigned long long slice_used;         /* Used portion of slice */
    
    /* Weight and priority */
    long weight;                            /* Scheduling weight */
    int priority;                          /* Static priority */
    int normal_priority;                   /* Normalized priority */
    int rt_priority;                       /* Real-time priority (1-99) */
    
    /* EEVDF specific fields */
    unsigned long long virtual_time;       /* EEVDF virtual time */
    unsigned long long deadline_vruntime;  /* Deadline vruntime */
    unsigned long long lag_threshold;      /* Lag threshold for preemption */
    unsigned int timeslice;                /* Timeslice in ms */
    unsigned int timeslice_used;           /* Used timeslice */
    
    /* Scheduling flags */
    unsigned int sched_flags;              /* Scheduling flags */
    boolean_t on_rq;                       /* On runqueue flag */
    boolean_t delayed;                     /* Delayed scheduling flag */
    boolean_t preempted;                   /* Preemption flag */
    
    /* CFS compatibility fields */
    unsigned int nr_cpus_allowed;          /* CPU affinity mask count */
    unsigned int nr_migrations;            /* Migration counter */
    unsigned int last_cpu;                 /* Last CPU executed */
    
    /* RB tree node for EEVDF queue */
    rb_node_t rb_node;
    
    /* Red-black tree key (vruntime) */
    unsigned long long rb_key;
    
    /* Scheduler class */
    eevdf_sched_class_t sched_class;
};

/*
 * EEVDF Run Queue
 * Per-CPU runqueue structure
 */
struct eevdf_rq {
    /* Red-black tree of runnable entities */
    rb_root_t tasks_timeline;              /* RB tree keyed by vruntime */
    rb_root_t tasks_deadline;              /* RB tree keyed by deadline */
    
    /* Queue statistics */
    unsigned int nr_running;               /* Number of running tasks */
    unsigned int nr_switches;              /* Number of context switches */
    unsigned long long nr_forced_switches; /* Forced preemptions */
    
    /* Virtual time tracking */
    unsigned long long min_vruntime;       /* Minimum vruntime in rq */
    unsigned long long max_vruntime;       /* Maximum vruntime in rq */
    unsigned long long avg_vruntime;       /* Average vruntime */
    
    /* Deadline tracking */
    unsigned long long earliest_deadline;  /* Earliest deadline in rq */
    unsigned long long latest_deadline;    /* Latest deadline in rq */
    
    /* Load tracking */
    unsigned long long total_weight;       /* Sum of all entity weights */
    unsigned long long load_avg;           /* Average load */
    
    /* Preemption management */
    thread_t curr;                         /* Currently running thread */
    thread_t next;                         /* Next thread to run */
    unsigned long long preempt_time;       /* Preemption time */
    
    /* Lock for runqueue operations */
    simple_lock_t lock;
    
    /* Statistics */
    struct {
        unsigned long long enqueue_count;
        unsigned long long dequeue_count;
        unsigned long long preempt_count;
        unsigned long long yield_count;
        unsigned long long deadline_miss_count;
    } stats;
};

/*
 * EEVDF Global State
 */
struct eevdf_state {
    unsigned long long sysctl_sched_latency;      /* Latency target */
    unsigned long long sysctl_sched_min_granularity; /* Min granularity */
    unsigned long long sysctl_sched_wakeup_granularity; /* Wakeup granularity */
    unsigned long long sysctl_sched_child_runs_first; /* Child runs first flag */
    unsigned long long sysctl_sched_features;     /* Scheduler features */
    unsigned long long sysctl_sched_tunable_scaling; /* Tunable scaling */
    
    unsigned long long total_vruntime;            /* Total system vruntime */
    unsigned long long total_deadline;            /* Total system deadline */
    unsigned int total_running;                   /* Total running tasks */
    
    simple_lock_t global_lock;
};

/* Global EEVDF state */
static struct eevdf_state eevdf_global;
static struct eevdf_rq eevdf_rq_percpu[MAX_CPUS];

/*
 * Nice to weight conversion table (Linux style)
 * Weight = 1024 / (1.25^nice)
 */
static const int eevdf_prio_to_weight[40] = {
 /* -20 */ 88761, 71755, 56483, 46273, 36291,
 /* -15 */ 29154, 23254, 18705, 14949, 11916,
 /* -10 */ 9548, 7620, 6100, 4904, 3906,
 /* -5 */ 3121, 2501, 1991, 1586, 1277,
 /* 0 */ 1024, 820, 655, 526, 423,
 /* 5 */ 335, 272, 215, 172, 137,
 /* 10 */ 110, 87, 70, 56, 45,
 /* 15 */ 36, 29, 23, 18, 15,
};

/*
 * EEVDF Helper Functions
 */

static inline unsigned long long eevdf_time_to_ns(unsigned long long time)
{
    return time * 1000000ULL;  /* Convert ms to ns */
}

static inline unsigned long long eevdf_ns_to_time(unsigned long long ns)
{
    return ns / 1000000ULL;    /* Convert ns to ms */
}

static inline unsigned long long eevdf_calc_weight(int nice)
{
    int idx = nice + 20;
    if (idx < 0) idx = 0;
    if (idx >= 40) idx = 39;
    return eevdf_prio_to_weight[idx];
}

static inline unsigned long long eevdf_calc_delta(unsigned long long delta_exec, long weight)
{
    return (delta_exec * EEVDF_WEIGHT_SCALE) / weight;
}

static inline unsigned long long eevdf_calc_vruntime_delta(unsigned long long delta, long weight)
{
    return delta * EEVDF_WEIGHT_SCALE / weight;
}

/*
 * eevdf_init_sched_entity
 *
 * Initialize EEVDF scheduling entity for a thread
 */
void eevdf_init_sched_entity(thread_t thread)
{
    struct eevdf_sched_entity *se;
    
    if (thread == THREAD_NULL)
        return;
    
    se = &thread->eevdf_se;
    
    se->vruntime = 0;
    se->min_vruntime = 0;
    se->deadline = 0;
    se->eligible_time = 0;
    se->lag = 0;
    se->sum_exec_runtime = 0;
    se->prev_sum_exec_runtime = 0;
    se->exec_start = 0;
    se->slice = EEVDF_LATENCY_NS;
    se->slice_used = 0;
    
    /* Initialize weight based on default priority */
    se->weight = eevdf_calc_weight(0);
    se->priority = 120;  /* Default Linux priority */
    se->normal_priority = 120;
    se->rt_priority = 0;
    
    /* EEVDF specific */
    se->virtual_time = 0;
    se->deadline_vruntime = 0;
    se->lag_threshold = EEVDF_LATENCY_NS / 2;
    se->timeslice = 6;  /* 6ms default */
    se->timeslice_used = 0;
    
    se->sched_flags = 0;
    se->on_rq = FALSE;
    se->delayed = FALSE;
    se->preempted = FALSE;
    
    se->nr_cpus_allowed = 1;
    se->nr_migrations = 0;
    se->last_cpu = 0;
    
    se->rb_node.rb_parent = NULL;
    se->rb_node.rb_left = NULL;
    se->rb_node.rb_right = NULL;
    se->rb_node.rb_color = RB_RED;
    se->rb_key = 0;
    
    se->sched_class = SCHED_CLASS_NORMAL;
}

/*
 * eevdf_update_curr
 *
 * Update current task's execution statistics
 */
static void eevdf_update_curr(struct eevdf_rq *rq)
{
    thread_t curr;
    struct eevdf_sched_entity *se;
    unsigned long long now, delta_exec, delta_vruntime;
    
    if (rq == NULL || rq->curr == THREAD_NULL)
        return;
    
    curr = rq->curr;
    se = &curr->eevdf_se;
    
    if (!se->on_rq)
        return;
    
    now = mach_absolute_time();
    if (se->exec_start == 0) {
        se->exec_start = now;
        return;
    }
    
    delta_exec = now - se->exec_start;
    if (delta_exec == 0)
        return;
    
    /* Update execution time */
    se->sum_exec_runtime += delta_exec;
    se->slice_used += delta_exec;
    
    /* Calculate vruntime delta */
    delta_vruntime = eevdf_calc_vruntime_delta(delta_exec, se->weight);
    se->vruntime += delta_vruntime;
    
    /* Update runqueue vruntime tracking */
    if (se->vruntime < rq->min_vruntime)
        rq->min_vruntime = se->vruntime;
    if (se->vruntime > rq->max_vruntime)
        rq->max_vruntime = se->vruntime;
    
    /* Update average vruntime */
    if (rq->nr_running > 0) {
        rq->avg_vruntime = (rq->avg_vruntime * (rq->nr_running - 1) + 
                            se->vruntime) / rq->nr_running;
    }
    
    /* Check if slice is exhausted */
    if (se->slice_used >= se->slice) {
        /* Reset for next slice */
        se->slice_used = 0;
        se->slice = eevdf_calc_next_slice(se);
        
        /* Update deadline */
        se->deadline += se->slice;
        rq->earliest_deadline = se->deadline;
        
        /* Mark for potential preemption */
        if (rq->curr == curr)
            se->preempted = TRUE;
    }
    
    se->exec_start = now;
}

/*
 * eevdf_calc_next_slice
 *
 * Calculate next time slice based on weight and latency
 */
static unsigned long long eevdf_calc_next_slice(struct eevdf_sched_entity *se)
{
    unsigned long long slice;
    
    /* Base slice calculation */
    slice = (EEVDF_LATENCY_NS * se->weight) / EEVDF_WEIGHT_SCALE;
    
    /* Apply limits */
    if (slice < EEVDF_MIN_GRANULARITY_NS)
        slice = EEVDF_MIN_GRANULARITY_NS;
    if (slice > EEVDF_MAX_GRANULARITY_NS)
        slice = EEVDF_MAX_GRANULARITY_NS;
    
    /* Adjust based on lag */
    if (se->lag > se->lag_threshold) {
        /* High lag - reduce slice */
        slice = slice * 75 / 100;
    } else if (se->lag < (se->lag_threshold / 2)) {
        /* Low lag - increase slice */
        slice = slice * 125 / 100;
    }
    
    return slice;
}

/*
 * eevdf_calc_deadline
 *
 * Calculate deadline for scheduling entity
 */
static unsigned long long eevdf_calc_deadline(struct eevdf_sched_entity *se)
{
    unsigned long long deadline;
    
    /* Deadline = current time + slice */
    deadline = mach_absolute_time() + se->slice;
    
    /* Apply real-time priority if applicable */
    if (se->rt_priority > 0) {
        unsigned long long rt_deadline = se->slice / (se->rt_priority / 10);
        if (rt_deadline < deadline)
            deadline = rt_deadline;
    }
    
    return deadline;
}

/*
 * eevdf_entity_key
 *
 * Get RB tree key for entity (vruntime)
 */
static inline unsigned long long eevdf_entity_key(struct eevdf_sched_entity *se)
{
    return se->vruntime;
}

/*
 * eevdf_rb_insert
 *
 * Insert entity into red-black tree
 */
static void eevdf_rb_insert(struct eevdf_rq *rq, struct eevdf_sched_entity *se)
{
    rb_root_t *root = &rq->tasks_timeline;
    rb_node_t **new = &(root->rb_node);
    rb_node_t *parent = NULL;
    struct eevdf_sched_entity *entry;
    unsigned long long key = eevdf_entity_key(se);
    
    /* Find insertion point */
    while (*new) {
        parent = *new;
        entry = rb_entry(parent, struct eevdf_sched_entity, rb_node);
        
        if (key < eevdf_entity_key(entry))
            new = &((*new)->rb_left);
        else
            new = &((*new)->rb_right);
    }
    
    /* Insert node */
    rb_link_node(&se->rb_node, parent, new);
    rb_insert_color(&se->rb_node, root);
    
    se->rb_key = key;
}

/*
 * eevdf_rb_remove
 *
 * Remove entity from red-black tree
 */
static void eevdf_rb_remove(struct eevdf_rq *rq, struct eevdf_sched_entity *se)
{
    rb_erase(&se->rb_node, &rq->tasks_timeline);
    se->rb_node.rb_parent = NULL;
}

/*
 * eevdf_pick_next
 *
 * Pick next entity to run (earliest vruntime)
 */
static struct eevdf_sched_entity *eevdf_pick_next(struct eevdf_rq *rq)
{
    rb_node_t *node;
    struct eevdf_sched_entity *se = NULL;
    
    if (rq->nr_running == 0)
        return NULL;
    
    /* Get leftmost node (smallest vruntime) */
    node = rb_first(&rq->tasks_timeline);
    if (node) {
        se = rb_entry(node, struct eevdf_sched_entity, rb_node);
        
        /* Check eligibility */
        if (se->eligible_time > mach_absolute_time()) {
            /* Not eligible yet, check next */
            node = rb_next(node);
            if (node)
                se = rb_entry(node, struct eevdf_sched_entity, rb_node);
        }
    }
    
    return se;
}

/*
 * eevdf_check_preempt
 *
 * Check if current task should be preempted
 */
static boolean_t eevdf_check_preempt(struct eevdf_rq *rq, struct eevdf_sched_entity *se)
{
    thread_t curr;
    struct eevdf_sched_entity *curr_se;
    unsigned long long now;
    
    if (rq->curr == THREAD_NULL)
        return FALSE;
    
    curr = rq->curr;
    curr_se = &curr->eevdf_se;
    now = mach_absolute_time();
    
    /* Real-time tasks preempt everything */
    if (se->rt_priority > 0 && curr_se->rt_priority == 0)
        return TRUE;
    
    /* Higher real-time priority preempts */
    if (se->rt_priority > curr_se->rt_priority)
        return TRUE;
    
    /* Check if current task exceeded its slice */
    if (curr_se->slice_used >= curr_se->slice)
        return TRUE;
    
    /* Check if new task has smaller vruntime */
    if (se->vruntime < curr_se->vruntime) {
        unsigned long long diff = curr_se->vruntime - se->vruntime;
        if (diff > EEVDF_PREEMPTION_THRESHOLD)
            return TRUE;
    }
    
    /* Check deadline urgency */
    if (se->deadline <= now + EEVDF_DEADLINE_MARGIN_NS) {
        if (curr_se->deadline > se->deadline)
            return TRUE;
    }
    
    return FALSE;
}

/*
 * eevdf_enqueue_task
 *
 * Enqueue task for scheduling
 */
void eevdf_enqueue_task(thread_t thread)
{
    struct eevdf_rq *rq;
    struct eevdf_sched_entity *se;
    int cpu;
    
    if (thread == THREAD_NULL)
        return;
    
    cpu = cpu_number();
    rq = &eevdf_rq_percpu[cpu];
    se = &thread->eevdf_se;
    
    simple_lock(&rq->lock);
    
    eevdf_update_curr(rq);
    
    if (!se->on_rq) {
        /* Update vruntime if task was sleeping */
        if (se->sum_exec_runtime > 0) {
            unsigned long long now = mach_absolute_time();
            unsigned long long sleep_time = now - se->exec_start;
            if (sleep_time > EEVDF_LATENCY_NS) {
                /* Decay vruntime for long sleeps */
                se->vruntime -= eevdf_calc_vruntime_delta(sleep_time, se->weight);
                if (se->vruntime < rq->min_vruntime)
                    se->vruntime = rq->min_vruntime;
            }
        }
        
        /* Set eligibility time */
        se->eligible_time = mach_absolute_time();
        
        /* Calculate deadline */
        se->deadline = eevdf_calc_deadline(se);
        
        /* Insert into red-black tree */
        eevdf_rb_insert(rq, se);
        
        se->on_rq = TRUE;
        rq->nr_running++;
        rq->total_weight += se->weight;
        
        /* Update runqueue statistics */
        rq->stats.enqueue_count++;
        
        /* Check if should preempt current task */
        if (eevdf_check_preempt(rq, se)) {
            rq->preempt_time = mach_absolute_time();
            rq->stats.preempt_count++;
            ast_on(cpu, AST_BLOCK);
        }
    }
    
    simple_unlock(&rq->lock);
}

/*
 * eevdf_dequeue_task
 *
 * Dequeue task from scheduling
 */
void eevdf_dequeue_task(thread_t thread)
{
    struct eevdf_rq *rq;
    struct eevdf_sched_entity *se;
    int cpu;
    
    if (thread == THREAD_NULL)
        return;
    
    cpu = cpu_number();
    rq = &eevdf_rq_percpu[cpu];
    se = &thread->eevdf_se;
    
    simple_lock(&rq->lock);
    
    eevdf_update_curr(rq);
    
    if (se->on_rq) {
        eevdf_rb_remove(rq, se);
        se->on_rq = FALSE;
        rq->nr_running--;
        rq->total_weight -= se->weight;
        rq->stats.dequeue_count++;
    }
    
    simple_unlock(&rq->lock);
}

/*
 * eevdf_pick_next_task
 *
 * Pick next task to run using EEVDF algorithm
 */
thread_t eevdf_pick_next_task(struct eevdf_rq *rq)
{
    struct eevdf_sched_entity *se;
    thread_t next_thread;
    
    if (rq == NULL)
        return THREAD_NULL;
    
    simple_lock(&rq->lock);
    
    eevdf_update_curr(rq);
    
    /* Pick best entity */
    se = eevdf_pick_next(rq);
    
    if (se == NULL) {
        simple_unlock(&rq->lock);
        return THREAD_NULL;
    }
    
    /* Get thread from entity */
    next_thread = container_of(se, struct thread, eevdf_se);
    
    if (next_thread != rq->curr) {
        rq->next = next_thread;
        rq->nr_switches++;
        
        /* Update last CPU */
        next_thread->eevdf_se.last_cpu = cpu_number();
    }
    
    simple_unlock(&rq->lock);
    
    return next_thread;
}

/*
 * eevdf_task_tick
 *
 * Called on every timer tick for EEVDF scheduling decisions
 */
void eevdf_task_tick(thread_t thread)
{
    struct eevdf_rq *rq;
    struct eevdf_sched_entity *se;
    int cpu;
    
    if (thread == THREAD_NULL)
        return;
    
    cpu = cpu_number();
    rq = &eevdf_rq_percpu[cpu];
    se = &thread->eevdf_se;
    
    simple_lock(&rq->lock);
    
    if (rq->curr == thread && se->on_rq) {
        eevdf_update_curr(rq);
        
        /* Check if need to reschedule */
        if (se->slice_used >= se->slice) {
            /* Slice exhausted, request reschedule */
            ast_on(cpu, AST_BLOCK);
            rq->stats.nr_forced_switches++;
        }
        
        /* Check deadline miss */
        if (se->deadline > 0 && mach_absolute_time() > se->deadline) {
            rq->stats.deadline_miss_count++;
            /* Urgent reschedule */
            ast_on(cpu, AST_BLOCK);
        }
    }
    
    simple_unlock(&rq->lock);
}

/*
 * eevdf_yield_task
 *
 * Yield current task voluntarily
 */
void eevdf_yield_task(thread_t thread)
{
    struct eevdf_rq *rq;
    struct eevdf_sched_entity *se;
    int cpu;
    
    if (thread == THREAD_NULL)
        return;
    
    cpu = cpu_number();
    rq = &eevdf_rq_percpu[cpu];
    se = &thread->eevdf_se;
    
    simple_lock(&rq->lock);
    
    if (rq->curr == thread) {
        /* Mark as yielded and request reschedule */
        se->slice_used = se->slice;  /* Force slice expiration */
        rq->stats.yield_count++;
        ast_on(cpu, AST_BLOCK);
    }
    
    simple_unlock(&rq->lock);
}

/*
 * eevdf_set_priority
 *
 * Set EEVDF priority for thread
 */
void eevdf_set_priority(thread_t thread, int nice, int rt_prio)
{
    struct eevdf_sched_entity *se;
    int old_weight;
    
    if (thread == THREAD_NULL)
        return;
    
    se = &thread->eevdf_se;
    old_weight = se->weight;
    
    /* Update nice value */
    se->weight = eevdf_calc_weight(nice);
    se->priority = 120 + nice;
    se->normal_priority = se->priority;
    
    /* Update real-time priority */
    if (rt_prio > 0 && rt_prio <= 99) {
        se->rt_priority = rt_prio;
        se->sched_class = SCHED_CLASS_RT;
    } else {
        se->rt_priority = 0;
        se->sched_class = SCHED_CLASS_NORMAL;
    }
    
    /* Adjust vruntime if weight changed significantly */
    if (se->on_rq && old_weight != se->weight) {
        unsigned long long now = mach_absolute_time();
        unsigned long long delta = now - se->exec_start;
        unsigned long long vruntime_adjust = eevdf_calc_vruntime_delta(delta, se->weight) -
                                              eevdf_calc_vruntime_delta(delta, old_weight);
        se->vruntime += vruntime_adjust;
    }
}

/*
 * eevdf_update_load_avg
 *
 * Update system load average for EEVDF
 */
static void eevdf_update_load_avg(struct eevdf_rq *rq)
{
    unsigned long long now = mach_absolute_time();
    static unsigned long long last_update = 0;
    unsigned long long delta;
    
    if (last_update == 0) {
        last_update = now;
        return;
    }
    
    delta = now - last_update;
    if (delta > 1000000000ULL) {  /* Update every second */
        /* Exponential moving average */
        rq->load_avg = (rq->load_avg * 7 + rq->total_weight) / 8;
        last_update = now;
    }
}

/*
 * eevdf_balance_runqueue
 *
 * Balance runqueues across CPUs
 */
static void eevdf_balance_runqueue(void)
{
    int cpu, target_cpu;
    struct eevdf_rq *src_rq, *dst_rq;
    unsigned long long min_load, max_load;
    unsigned long long load_diff;
    
    min_load = ~0ULL;
    max_load = 0;
    target_cpu = 0;
    
    /* Find most and least loaded CPUs */
    for (cpu = 0; cpu < smp_get_numcpus(); cpu++) {
        src_rq = &eevdf_rq_percpu[cpu];
        simple_lock(&src_rq->lock);
        
        if (src_rq->load_avg < min_load) {
            min_load = src_rq->load_avg;
            target_cpu = cpu;
        }
        if (src_rq->load_avg > max_load)
            max_load = src_rq->load_avg;
        
        simple_unlock(&src_rq->lock);
    }
    
    load_diff = max_load - min_load;
    
    /* Migrate tasks if imbalance is significant (>25%) */
    if (load_diff > (max_load / 4)) {
        /* Find source CPU with highest load */
        for (cpu = 0; cpu < smp_get_numcpus(); cpu++) {
            src_rq = &eevdf_rq_percpu[cpu];
            if (src_rq->load_avg == max_load) {
                /* Would migrate tasks here */
                break;
            }
        }
    }
}

/*
 * eevdf_init_cpu
 *
 * Initialize EEVDF for a CPU
 */
void eevdf_init_cpu(int cpu)
{
    struct eevdf_rq *rq;
    
    if (cpu >= MAX_CPUS)
        return;
    
    rq = &eevdf_rq_percpu[cpu];
    
    rq->tasks_timeline.rb_node = NULL;
    rq->tasks_deadline.rb_node = NULL;
    rq->nr_running = 0;
    rq->nr_switches = 0;
    rq->nr_forced_switches = 0;
    rq->min_vruntime = 0;
    rq->max_vruntime = 0;
    rq->avg_vruntime = 0;
    rq->earliest_deadline = 0;
    rq->latest_deadline = 0;
    rq->total_weight = 0;
    rq->load_avg = 0;
    rq->curr = THREAD_NULL;
    rq->next = THREAD_NULL;
    rq->preempt_time = 0;
    
    memset(&rq->stats, 0, sizeof(rq->stats));
    simple_lock_init(&rq->lock);
}

/*
 * eevdf_global_init
 *
 * Initialize global EEVDF scheduler state
 */
void eevdf_global_init(void)
{
    eevdf_global.sysctl_sched_latency = EEVDF_LATENCY_NS;
    eevdf_global.sysctl_sched_min_granularity = EEVDF_MIN_GRANULARITY_NS;
    eevdf_global.sysctl_sched_wakeup_granularity = EEVDF_LATENCY_NS / 2;
    eevdf_global.sysctl_sched_child_runs_first = 1;
    eevdf_global.sysctl_sched_features = 0;
    eevdf_global.sysctl_sched_tunable_scaling = 1;
    
    eevdf_global.total_vruntime = 0;
    eevdf_global.total_deadline = 0;
    eevdf_global.total_running = 0;
    
    simple_lock_init(&eevdf_global.global_lock);
    
    /* Initialize per-CPU runqueues */
    for (int i = 0; i < smp_get_numcpus(); i++) {
        eevdf_init_cpu(i);
    }
}

/*
 * eevdf_schedule
 *
 * Main EEVDF scheduling decision function
 */
thread_t eevdf_schedule(void)
{
    struct eevdf_rq *rq;
    thread_t next;
    int cpu;
    
    cpu = cpu_number();
    rq = &eevdf_rq_percpu[cpu];
    
    /* Update current task statistics */
    if (rq->curr != THREAD_NULL) {
        eevdf_update_curr(rq);
    }
    
    /* Pick next task */
    next = eevdf_pick_next_task(rq);
    
    /* Update load average */
    eevdf_update_load_avg(rq);
    
    /* Balance runqueues periodically */
    static int balance_counter = 0;
    if (++balance_counter >= 1000) {
        eevdf_balance_runqueue();
        balance_counter = 0;
    }
    
    return next;
}

/*
 * eevdf_get_debug_info
 *
 * Get EEVDF debug information
 */
void eevdf_get_debug_info(struct eevdf_debug_info *info)
{
    struct eevdf_rq *rq;
    int cpu;
    
    if (info == NULL)
        return;
    
    info->total_running = 0;
    info->total_switches = 0;
    info->total_preemptions = 0;
    info->total_deadline_misses = 0;
    info->min_vruntime = ~0ULL;
    info->max_vruntime = 0;
    
    for (cpu = 0; cpu < smp_get_numcpus(); cpu++) {
        rq = &eevdf_rq_percpu[cpu];
        simple_lock(&rq->lock);
        
        info->total_running += rq->nr_running;
        info->total_switches += rq->nr_switches;
        info->total_preemptions += rq->stats.preempt_count;
        info->total_deadline_misses += rq->stats.deadline_miss_count;
        
        if (rq->min_vruntime < info->min_vruntime)
            info->min_vruntime = rq->min_vruntime;
        if (rq->max_vruntime > info->max_vruntime)
            info->max_vruntime = rq->max_vruntime;
        
        info->avg_load += rq->load_avg;
        
        simple_unlock(&rq->lock);
    }
    
    info->avg_load /= smp_get_numcpus();
}

/*
 * Replace original thread_select with EEVDF version
 */
static thread_t thread_select_eevdf(processor_t myprocessor)
{
    thread_t thread;
    
    /* Use EEVDF to pick next thread */
    thread = eevdf_schedule();
    
    if (thread == THREAD_NULL) {
        /* No runnable thread, use idle thread */
        thread = myprocessor->idle_thread;
    }
    
    return thread;
}

/*
 * Modified thread_block with EEVDF support
 */
void thread_block_eevdf(continuation_t continuation)
{
    thread_t thread = current_thread();
    processor_t myprocessor = cpu_to_processor(cpu_number());
    thread_t new_thread;
    spl_t s;
    
    check_simple_locks();
    
    s = splsched();
    
    /* Dequeue current thread from EEVDF */
    eevdf_dequeue_task(thread);
    
    /* Update EEVDF statistics */
    eevdf_task_tick(thread);
    
    ast_off(cpu_number(), AST_BLOCK);
    
    do {
        new_thread = thread_select_eevdf(myprocessor);
    } while (!thread_invoke(thread, continuation, new_thread));
    
    splx(s);
}

/*
 * Modified thread_setrun with EEVDF support
 */
void thread_setrun_eevdf(thread_t th, boolean_t may_preempt)
{
    spl_t s;
    
    if (th == THREAD_NULL)
        return;
    
    s = splsched();
    thread_lock(th);
    
    /* Update priority if needed */
    if (th->sched_stamp != sched_tick) {
        update_priority(th);
    }
    
    /* Enqueue in EEVDF */
    eevdf_enqueue_task(th);
    
    /* Check for preemption */
    if (may_preempt && current_thread() != th) {
        struct eevdf_rq *rq = &eevdf_rq_percpu[cpu_number()];
        if (eevdf_check_preempt(rq, &th->eevdf_se)) {
            ast_on(cpu_number(), AST_BLOCK);
        }
    }
    
    thread_unlock(th);
    splx(s);
}

/*
 * EEVDF statistics export for Mach
 */
kern_return_t host_eevdf_info(host_t host, struct eevdf_global_info *info)
{
    if (host == HOST_NULL || info == NULL)
        return KERN_INVALID_HOST;
    
    info->sched_latency_ns = eevdf_global.sysctl_sched_latency;
    info->min_granularity_ns = eevdf_global.sysctl_sched_min_granularity;
    info->wakeup_granularity_ns = eevdf_global.sysctl_sched_wakeup_granularity;
    info->child_runs_first = eevdf_global.sysctl_sched_child_runs_first;
    info->features = eevdf_global.sysctl_sched_features;
    info->total_running = eevdf_global.total_running;
    
    eevdf_get_debug_info(&info->debug);
    
    return KERN_SUCCESS;
}

/*
 * EEVDF sysctl interface
 */
kern_return_t eevdf_sysctl(int name, unsigned int *oldp, unsigned int *oldlenp,
                           unsigned int *newp, unsigned int newlen)
{
    kern_return_t kr = KERN_SUCCESS;
    
    switch (name) {
        case EEVDF_SCHED_LATENCY:
            if (newp && newlen >= sizeof(unsigned int)) {
                eevdf_global.sysctl_sched_latency = *newp;
            }
            if (oldp && oldlenp && *oldlenp >= sizeof(unsigned int)) {
                *oldp = eevdf_global.sysctl_sched_latency;
            }
            break;
            
        case EEVDF_MIN_GRANULARITY:
            if (newp && newlen >= sizeof(unsigned int)) {
                eevdf_global.sysctl_sched_min_granularity = *newp;
            }
            if (oldp && oldlenp && *oldlenp >= sizeof(unsigned int)) {
                *oldp = eevdf_global.sysctl_sched_min_granularity;
            }
            break;
            
        default:
            kr = KERN_INVALID_ARGUMENT;
            break;
    }
    
    return kr;
}

/*
 * Initialize EEVDF scheduler
 */
void eevdf_scheduler_init(void)
{
    printf("Initializing EEVDF Scheduler...\n");
    
    eevdf_global_init();
    
    printf("EEVDF Scheduler initialized:\n");
    printf("  Latency: %llu ns\n", eevdf_global.sysctl_sched_latency);
    printf("  Min Granularity: %llu ns\n", eevdf_global.sysctl_sched_min_granularity);
    printf("  Wakeup Granularity: %llu ns\n", eevdf_global.sysctl_sched_wakeup_granularity);
}

/*
 * Override original scheduling functions
 */
#define thread_block thread_block_eevdf
#define thread_setrun thread_setrun_eevdf

/*
 * EEVDF debug structures
 */
struct eevdf_debug_info {
    unsigned int total_running;
    unsigned int total_switches;
    unsigned int total_preemptions;
    unsigned int total_deadline_misses;
    unsigned long long min_vruntime;
    unsigned long long max_vruntime;
    unsigned long long avg_load;
};

struct eevdf_global_info {
    unsigned long long sched_latency_ns;
    unsigned long long min_granularity_ns;
    unsigned long long wakeup_granularity_ns;
    unsigned int child_runs_first;
    unsigned long long features;
    unsigned int total_running;
    struct eevdf_debug_info debug;
};

/* EEVDF sysctl names */
#define EEVDF_SCHED_LATENCY     1
#define EEVDF_MIN_GRANULARITY   2
#define EEVDF_WAKEUP_GRANULARITY 3
#define EEVDF_CHILD_RUNS_FIRST  4
#define EEVDF_FEATURES          5

/*
 * Additional EEVDF Scheduler Functions
 * Enhanced scheduling features, NUMA awareness, and advanced algorithms
 */

/*
 * EEVDF NUMA-aware scheduling structures
 */
struct eevdf_numa_stats {
    unsigned int node_id;
    unsigned long long local_runtime;
    unsigned long long remote_runtime;
    unsigned long long migrate_count;
    unsigned long long numa_faults_local;
    unsigned long long numa_faults_remote;
    unsigned int numa_hit;
    unsigned int numa_miss;
    unsigned int numa_foreign;};

struct eevdf_numa_domain {
    unsigned int node_mask;
    unsigned int num_nodes;
    unsigned long long *node_distances;
    struct eevdf_numa_stats stats[64];
};

/*
 * EEVDF energy-aware scheduling
 */
struct eevdf_energy_model {
    unsigned long long dynamic_power;
    unsigned long long static_power;
    unsigned long long leakage_power;
    unsigned int efficiency;
    unsigned int max_freq;
    unsigned int min_freq;
    unsigned int current_freq;
};

/*
 * EEVDF group scheduling (for cgroups)
 */
struct eevdf_task_group {
    unsigned int group_id;
    unsigned long long share;
    unsigned long long usage;
    unsigned long long quota;
    unsigned long long period;
    struct eevdf_sched_entity *se;
    struct eevdf_task_group *parent;
    rb_root_t children;
    unsigned int nr_tasks;
    unsigned long long min_vruntime;
    unsigned long long max_vruntime;
};

/*
 * eevdf_update_numa_stats
 *
 * Update NUMA statistics for task migration decisions
 */
void eevdf_update_numa_stats(thread_t thread, unsigned int node_id)
{
    struct eevdf_sched_entity *se;
    struct eevdf_numa_domain *numa_domain;
    unsigned int current_node;
    
    if (thread == THREAD_NULL)
        return;
    
    se = &thread->eevdf_se;
    current_node = cpu_to_node(se->last_cpu);
    
    if (current_node != node_id) {
        se->numa_faults_remote++;
        se->numa_migrations++;
        
        /* Update NUMA domain statistics */
        numa_domain = &eevdf_numa_domains[current_node];
        numa_domain->stats[node_id].numa_foreign++;
        numa_domain->stats[current_node].numa_miss++;
        
        /* Check if should migrate based on fault ratio */
        if (se->numa_faults_remote > se->numa_faults_local * 2) {
            /* Too many remote faults, schedule migration */
            se->sched_flags |= EEVDF_FLAG_MIGRATE_NUMA;
        }
    } else {
        se->numa_faults_local++;
        numa_domain = &eevdf_numa_domains[current_node];
        numa_domain->stats[current_node].numa_hit++;
    }
}

/*
 * eevdf_calc_numa_affinity
 *
 * Calculate NUMA affinity score for task on a node
 */
static unsigned long long eevdf_calc_numa_affinity(thread_t thread, int target_node)
{
    struct eevdf_sched_entity *se;
    unsigned long long score = 0;
    int current_node;
    
    if (thread == THREAD_NULL)
        return 0;
    
    se = &thread->eevdf_se;
    current_node = cpu_to_node(se->last_cpu);
    
    /* Base score on local vs remote ratio */
    if (current_node == target_node) {
        score = 1000;  /* Prefer local node */
        if (se->numa_faults_local > 0)
            score += se->numa_faults_local / 100;
    } else {
        score = 100;
        if (se->numa_faults_remote > 0)
            score = 1000 / (se->numa_faults_remote / 100 + 1);
    }
    
    /* Adjust based on node distance */
    if (eevdf_numa_distances[current_node][target_node] > 0) {
        score = (score * 1000) / eevdf_numa_distances[current_node][target_node];
    }
    
    /* Priority boost for real-time tasks */
    if (se->rt_priority > 0)
        score *= (se->rt_priority + 10);
    
    return score;
}

/*
 * eevdf_migrate_task_numa
 *
 * Migrate task to better NUMA node
 */
kern_return_t eevdf_migrate_task_numa(thread_t thread)
{
    struct eevdf_sched_entity *se;
    int best_node = -1;
    unsigned long long best_score = 0;
    unsigned long long score;
    int i;
    
    if (thread == THREAD_NULL)
        return KERN_INVALID_ARGUMENT;
    
    se = &thread->eevdf_se;
    
    /* Find best NUMA node */
    for (i = 0; i < numa_max_nodes(); i++) {
        score = eevdf_calc_numa_affinity(thread, i);
        if (score > best_score) {
            best_score = score;
            best_node = i;
        }
    }
    
    /* Migrate if better node found */
    if (best_node >= 0 && best_node != cpu_to_node(se->last_cpu)) {
        int target_cpu = node_to_cpu(best_node, 0);
        thread_migrate_to_cpu(thread, target_cpu);
        se->sched_flags &= ~EEVDF_FLAG_MIGRATE_NUMA;
        return KERN_SUCCESS;
    }
    
    return KERN_FAILURE;
}

/*
 * eevdf_energy_aware_schedule
 *
 * Energy-aware scheduling decision
 */
static thread_t eevdf_energy_aware_schedule(struct eevdf_rq *rq)
{
    thread_t candidate, best_thread = THREAD_NULL;
    struct eevdf_sched_entity *se;
    unsigned long long energy_cost;
    unsigned long long min_energy = ~0ULL;
    rb_node_t *node;
    
    if (rq->nr_running == 0)
        return THREAD_NULL;
    
    /* Find task with minimal energy cost */
    for (node = rb_first(&rq->tasks_timeline); node; node = rb_next(node)) {
        se = rb_entry(node, struct eevdf_sched_entity, rb_node);
        candidate = container_of(se, struct thread, eevdf_se);
        
        /* Calculate estimated energy cost */
        energy_cost = eevdf_estimate_energy(candidate);
        
        /* Adjust for deadline constraints */
        if (se->deadline > 0) {
            unsigned long long now = mach_absolute_time();
            if (se->deadline <= now + EEVDF_DEADLINE_MARGIN_NS) {
                /* Urgent task, ignore energy */
                return candidate;
            }
        }
        
        if (energy_cost < min_energy) {
            min_energy = energy_cost;
            best_thread = candidate;
        }
    }
    
    return best_thread;
}

/*
 * eevdf_estimate_energy
 *
 * Estimate energy consumption for running a task
 */
static unsigned long long eevdf_estimate_energy(thread_t thread)
{
    struct eevdf_sched_entity *se;
    unsigned long long energy = 0;
    unsigned int cpu_freq;
    
    if (thread == THREAD_NULL)
        return 0;
    
    se = &thread->eevdf_se;
    cpu_freq = current_cpu_frequency();
    
    /* Dynamic power: P = C * V^2 * f */
    energy = se->sum_exec_runtime * cpu_freq * cpu_freq;
    
    /* Adjust for task priority (higher priority = more energy) */
    energy = energy * (se->priority + 100) / 100;
    
    /* NUMA penalty for remote memory access */
    if (se->numa_faults_remote > se->numa_faults_local) {
        energy = energy * 150 / 100;
    }
    
    return energy;
}

/*
 * eevdf_dynamic_freq_scaling
 *
 * Dynamic frequency scaling based on load
 */
void eevdf_dynamic_freq_scaling(int cpu)
{
    struct eevdf_rq *rq;
    unsigned int new_freq;
    unsigned long long load;
    
    if (cpu >= MAX_CPUS)
        return;
    
    rq = &eevdf_rq_percpu[cpu];
    simple_lock(&rq->lock);
    
    load = rq->load_avg;
    
    /* Calculate target frequency based on load */
    if (load > 90) {
        new_freq = eevdf_energy_model.max_freq;
    } else if (load > 70) {
        new_freq = eevdf_energy_model.max_freq * 9 / 10;
    } else if (load > 50) {
        new_freq = eevdf_energy_model.max_freq * 7 / 10;
    } else if (load > 30) {
        new_freq = eevdf_energy_model.max_freq * 5 / 10;
    } else if (load > 10) {
        new_freq = eevdf_energy_model.max_freq * 3 / 10;
    } else {
        new_freq = eevdf_energy_model.min_freq;
    }
    
    /* Apply frequency change */
    if (new_freq != eevdf_energy_model.current_freq) {
        set_cpu_frequency(cpu, new_freq);
        eevdf_energy_model.current_freq = new_freq;
    }
    
    simple_unlock(&rq->lock);
}

/*
 * eevdf_group_schedule
 *
 * Group scheduling for cgroups
 */
static thread_t eevdf_group_schedule(struct eevdf_task_group *tg)
{
    struct eevdf_sched_entity *se;
    thread_t thread = THREAD_NULL;
    rb_node_t *node;
    
    if (tg == NULL || tg->nr_tasks == 0)
        return THREAD_NULL;
    
    /* Find entity with minimum vruntime in group */
    node = rb_first(&tg->children);
    if (node) {
        se = rb_entry(node, struct eevdf_sched_entity, rb_node);
        thread = container_of(se, struct thread, eevdf_se);
    }
    
    return thread;
}

/*
 * eevdf_calculate_group_share
 *
 * Calculate fair share for task group
 */
void eevdf_calculate_group_share(struct eevdf_task_group *tg)
{
    unsigned long long total_shares = 0;
    unsigned long long total_usage = 0;
    struct rb_node *node;
    struct eevdf_task_group *child;
    
    if (tg == NULL)
        return;
    
    /* Calculate total shares and usage */
    for (node = rb_first(&tg->children); node; node = rb_next(node)) {
        child = rb_entry(node, struct eevdf_task_group, children);
        total_shares += child->share;
        total_usage += child->usage;
    }
    
    /* Distribute quota based on share */
    if (total_shares > 0 && tg->quota > 0) {
        for (node = rb_first(&tg->children); node; node = rb_next(node)) {
            child = rb_entry(node, struct eevdf_task_group, children);
            child->quota = (tg->quota * child->share) / total_shares;
        }
    }
}

/*
 * eevdf_deadline_scheduling
 *
 * Enhanced deadline scheduling with admission control
 */
kern_return_t eevdf_deadline_schedule(thread_t thread, 
                                      unsigned long long runtime,
                                      unsigned long long period,
                                      unsigned long long deadline)
{
    struct eevdf_sched_entity *se;
    unsigned long long total_utilization = 0;
    unsigned long long new_utilization;
    int cpu;
    
    if (thread == THREAD_NULL)
        return KERN_INVALID_ARGUMENT;
    
    /* Admission control: sum of utilizations <= max CPUs */
    new_utilization = (runtime * 1000) / period;
    
    for (cpu = 0; cpu < smp_get_numcpus(); cpu++) {
        total_utilization += eevdf_cpu_utilization[cpu];
    }
    
    if (total_utilization + new_utilization > smp_get_numcpus() * 1000) {
        return KERN_RESOURCE_SHORTAGE;  /* Cannot admit */
    }
    
    se = &thread->eevdf_se;
    se->deadline = deadline;
    se->sched_runtime = runtime;
    se->sched_period = period;
    se->sched_class = SCHED_CLASS_DEADLINE;
    
    /* Add to deadline tracking */
    eevdf_track_deadline(thread);
    
    return KERN_SUCCESS;
}

/*
 * eevdf_track_deadline
 *
 * Track deadline tasks for admission control
 */
static void eevdf_track_deadline(thread_t thread)
{
    struct eevdf_sched_entity *se;
    int cpu;
    
    if (thread == THREAD_NULL)
        return;
    
    se = &thread->eevdf_se;
    cpu = se->last_cpu;
    
    eevdf_cpu_utilization[cpu] += (se->sched_runtime * 1000) / se->sched_period;
}

/*
 * eevdf_bandwidth_controller
 *
 * Bandwidth control for real-time tasks
 */
struct eevdf_bandwidth_ctrl {
    unsigned long long period;
    unsigned long long runtime;
    unsigned long long deadline;
    unsigned long long used;
    unsigned long long throttled_until;
    simple_lock_t lock;
};

void eevdf_bandwidth_update(thread_t thread)
{
    struct eevdf_bandwidth_ctrl *bw;
    struct eevdf_sched_entity *se;
    unsigned long long now;
    
    if (thread == THREAD_NULL)
        return;
    
    se = &thread->eevdf_se;
    bw = &thread->eevdf_bw;
    now = mach_absolute_time();
    
    simple_lock(&bw->lock);
    
    /* Check if throttled */
    if (now < bw->throttled_until) {
        se->sched_flags |= EEVDF_FLAG_THROTTLED;
        simple_unlock(&bw->lock);
        return;
    }
    
    /* Update used bandwidth */
    bw->used += eevdf_update_curr(se);
    
    /* Check if exceeded bandwidth */
    if (bw->used > bw->runtime) {
        /* Throttle for remainder of period */
        bw->throttled_until = now + (bw->period - (now % bw->period));
        se->sched_flags |= EEVDF_FLAG_THROTTLED;
    }
    
    /* Period elapsed, reset */
    if ((now % bw->period) < eevdf_prev_period) {
        bw->used = 0;
        se->sched_flags &= ~EEVDF_FLAG_THROTTLED;
    }
    
    eevdf_prev_period = now % bw->period;
    
    simple_unlock(&bw->lock);
}

/*
 * eevdf_sched_setaffinity
 *
 * Set CPU affinity with EEVDF awareness
 */
kern_return_t eevdf_sched_setaffinity(thread_t thread, unsigned int cpus_allowed)
{
    struct eevdf_sched_entity *se;
    int old_cpu, new_cpu;
    
    if (thread == THREAD_NULL)
        return KERN_INVALID_ARGUMENT;
    
    se = &thread->eevdf_se;
    old_cpu = se->last_cpu;
    
    /* Check if current CPU is allowed */
    if ((cpus_allowed & (1 << old_cpu)) == 0) {
        /* Need to migrate */
        new_cpu = ffs(cpus_allowed) - 1;
        if (new_cpu >= 0) {
            thread_migrate_to_cpu(thread, new_cpu);
            se->nr_migrations++;
        } else {
            return KERN_INVALID_ARGUMENT;
        }
    }
    
    se->nr_cpus_allowed = popcount(cpus_allowed);
    se->sched_flags |= EEVDF_FLAG_AFFINITY_SET;
    
    return KERN_SUCCESS;
}

/*
 * eevdf_sched_getaffinity
 *
 * Get CPU affinity mask
 */
unsigned int eevdf_sched_getaffinity(thread_t thread)
{
    struct eevdf_sched_entity *se;
    unsigned int mask = 0;
    
    if (thread == THREAD_NULL)
        return 0;
    
    se = &thread->eevdf_se;
    
    /* Build affinity mask based on allowed CPUs */
    for (int i = 0; i < smp_get_numcpus(); i++) {
        if (se->nr_cpus_allowed & (1 << i))
            mask |= (1 << i);
    }
    
    return mask;
}

/*
 * eevdf_sched_yield
 *
 * Yield CPU with EEVDF accounting
 */
void eevdf_sched_yield(thread_t thread)
{
    struct eevdf_sched_entity *se;
    struct eevdf_rq *rq;
    
    if (thread == THREAD_NULL)
        return;
    
    se = &thread->eevdf_se;
    rq = &eevdf_rq_percpu[cpu_number()];
    
    simple_lock(&rq->lock);
    
    /* Mark as yield and reset slice */
    se->slice_used = se->slice;  /* Force requeue */
    se->sched_flags |= EEVDF_FLAG_YIELDED;
    
    /* Update statistics */
    rq->stats.yield_count++;
    
    simple_unlock(&rq->lock);
    
    /* Force reschedule */
    ast_on(cpu_number(), AST_BLOCK);
}

/*
 * eevdf_sched_get_priority_max
 *
 * Get maximum priority for scheduling policy
 */
int eevdf_sched_get_priority_max(int policy)
{
    switch (policy) {
        case SCHED_FIFO:
        case SCHED_RR:
            return 99;
        case SCHED_DEADLINE:
            return 99;
        case SCHED_NORMAL:
        case SCHED_BATCH:
        case SCHED_IDLE:
            return 0;
        default:
            return -1;
    }
}

/*
 * eevdf_sched_get_priority_min
 *
 * Get minimum priority for scheduling policy
 */
int eevdf_sched_get_priority_min(int policy)
{
    switch (policy) {
        case SCHED_FIFO:
        case SCHED_RR:
            return 1;
        case SCHED_DEADLINE:
            return 1;
        case SCHED_NORMAL:
        case SCHED_BATCH:
        case SCHED_IDLE:
            return 0;
        default:
            return -1;
    }
}


/*
 * eevdf_reset_statistics
 *
 * Reset EEVDF statistics
 */
void eevdf_reset_statistics(void)
{
    struct eevdf_rq *rq;
    int cpu;
    
    for (cpu = 0; cpu < smp_get_numcpus(); cpu++) {
        rq = &eevdf_rq_percpu[cpu];
        simple_lock(&rq->lock);
        
        rq->nr_switches = 0;
        memset(&rq->stats, 0, sizeof(rq->stats));
        
        simple_unlock(&rq->lock);
    }
}

/*
 * eevdf_dump_rq
 *
 * Dump runqueue contents for debugging
 */
void eevdf_dump_rq(int cpu)
{
    struct eevdf_rq *rq;
    struct eevdf_sched_entity *se;
    thread_t thread;
    rb_node_t *node;
    
    if (cpu >= MAX_CPUS)
        return;
    
    rq = &eevdf_rq_percpu[cpu];
    
    printf("\nEEVDF Runqueue CPU %d:\n", cpu);
    printf("=====================\n");
    printf("nr_running: %u\n", rq->nr_running);
    printf("min_vruntime: %llu\n", rq->min_vruntime);
    printf("max_vruntime: %llu\n", rq->max_vruntime);
    printf("avg_vruntime: %llu\n", rq->avg_vruntime);
    printf("\nTasks:\n");
    
    for (node = rb_first(&rq->tasks_timeline); node; node = rb_next(node)) {
        se = rb_entry(node, struct eevdf_sched_entity, rb_node);
        thread = container_of(se, struct thread, eevdf_se);
        
        printf("  Thread %p: vruntime=%llu deadline=%llu weight=%ld prio=%d\n",
               thread, se->vruntime, se->deadline, se->weight, se->priority);
    }
}

/*
 * eevdf_wait_task
 *
 * Put task in wait state with EEVDF accounting
 */
void eevdf_wait_task(thread_t thread, unsigned long long wait_time_ns)
{
    struct eevdf_sched_entity *se;
    
    if (thread == THREAD_NULL)
        return;
    
    se = &thread->eevdf_se;
    
    /* Account wait time in vruntime (boost sleeping tasks) */
    if (wait_time_ns > EEVDF_LATENCY_NS) {
        /* Sleeping tasks get vruntime boost */
        unsigned long long boost = eevdf_calc_vruntime_delta(wait_time_ns, se->weight);
        if (se->vruntime > boost)
            se->vruntime -= boost;
    }
    
    /* Dequeue from runqueue */
    eevdf_dequeue_task(thread);
}

/*
 * eevdf_wakeup_task
 *
 * Wake up task with EEVDF handling
 */
void eevdf_wakeup_task(thread_t thread)
{
    struct eevdf_sched_entity *se;
    struct eevdf_rq *rq;
    unsigned long long now;
    
    if (thread == THREAD_NULL)
        return;
    
    se = &thread->eevdf_se;
    now = mach_absolute_time();
    rq = &eevdf_rq_percpu[cpu_number()];
    
    simple_lock(&rq->lock);
    
    /* Update vruntime for wakeup */
    if (se->sum_exec_runtime > 0) {
        unsigned long long sleep_time = now - se->exec_start;
        if (sleep_time > EEVDF_LATENCY_NS) {
            /* Decay vruntime for long sleeps */
            unsigned long long decay = eevdf_calc_vruntime_delta(sleep_time, se->weight);
            if (se->vruntime > decay)
                se->vruntime -= decay;
        }
    }
    
    se->exec_start = now;
    se->eligible_time = now;
    
    simple_unlock(&rq->lock);
    
    /* Enqueue for scheduling */
    eevdf_enqueue_task(thread);
}

/*
 * eevdf_find_best_cpu
 *
 * Find best CPU for task based on load and affinity
 */
int eevdf_find_best_cpu(thread_t thread)
{
    struct eevdf_sched_entity *se;
    int best_cpu = -1;
    unsigned long long best_load = ~0ULL;
    unsigned long long cpu_load;
    int cpu;
    
    if (thread == THREAD_NULL)
        return -1;
    
    se = &thread->eevdf_se;
    
    for (cpu = 0; cpu < smp_get_numcpus(); cpu++) {
        /* Check affinity */
        if ((se->nr_cpus_allowed & (1 << cpu)) == 0)
            continue;
        
        /* Calculate load including NUMA factor */
        cpu_load = eevdf_rq_percpu[cpu].load_avg;
        
        /* Apply NUMA penalty */
        if (cpu_to_node(cpu) != cpu_to_node(se->last_cpu)) {
            cpu_load = cpu_load * 120 / 100;
        }
        
        if (cpu_load < best_load) {
            best_load = cpu_load;
            best_cpu = cpu;
        }
    }
    
    return best_cpu;
}

/*
 * eevdf_balance_tasks
 *
 * Balance tasks across CPUs for load distribution
 */
void eevdf_balance_tasks(void)
{
    int src_cpu, dst_cpu;
    struct eevdf_rq *src_rq, *dst_rq;
    struct eevdf_sched_entity *se;
    thread_t thread;
    unsigned long long load_diff;
    int balance_count = 0;
    
    for (src_cpu = 0; src_cpu < smp_get_numcpus(); src_cpu++) {
        src_rq = &eevdf_rq_percpu[src_cpu];
        
        if (src_rq->load_avg == 0)
            continue;
        
        for (dst_cpu = 0; dst_cpu < smp_get_numcpus(); dst_cpu++) {
            if (src_cpu == dst_cpu)
                continue;
            
            dst_rq = &eevdf_rq_percpu[dst_cpu];
            
            if (src_rq->load_avg <= dst_rq->load_avg)
                continue;
            
            load_diff = src_rq->load_avg - dst_rq->load_avg;
            
            /* Balance if load difference > 25% */
            if (load_diff > (src_rq->load_avg / 4)) {
                /* Find task to migrate */
                simple_lock(&src_rq->lock);
                
                if (src_rq->nr_running > 0) {
                    struct rb_node *node = rb_first(&src_rq->tasks_timeline);
                    if (node) {
                        se = rb_entry(node, struct eevdf_sched_entity, rb_node);
                        thread = container_of(se, struct thread, eevdf_se);
                        
                        /* Check if can migrate */
                        if (thread->eevdf_se.nr_cpus_allowed & (1 << dst_cpu)) {
                            eevdf_dequeue_task(thread);
                            thread_migrate_to_cpu(thread, dst_cpu);
                            eevdf_enqueue_task(thread);
                            balance_count++;
                        }
                    }
                }
                
                simple_unlock(&src_rq->lock);
                
                if (balance_count >= 4)
                    return;  /* Limit migrations per cycle */
            }
        }
    }
}

/*
 * eevdf_watchdog
 *
 * Watchdog to detect scheduler stalls
 */
void eevdf_watchdog(void)
{
    static unsigned long long last_timestamp = 0;
    unsigned long long now;
    struct eevdf_rq *rq;
    int cpu;
    
    now = mach_absolute_time();
    
    /* Check for scheduler stall */
    if (last_timestamp != 0 && (now - last_timestamp) > 10000000000ULL) { /* 10 seconds */
        printf("EEVDF Watchdog: Possible scheduler stall detected!\n");
        
        for (cpu = 0; cpu < smp_get_numcpus(); cpu++) {
            rq = &eevdf_rq_percpu[cpu];
            printf("CPU %d: nr_running=%u load=%llu\n", 
                   cpu, rq->nr_running, rq->load_avg);
            
            if (rq->curr != THREAD_NULL) {
                printf("  Current: %p prio=%d vruntime=%llu\n",
                       rq->curr, rq->curr->eevdf_se.priority,
                       rq->curr->eevdf_se.vruntime);
            }
        }
    }
    
    last_timestamp = now;
}

/*
 * eevdf_sysctl_register
 *
 * Register EEVDF sysctl entries
 */
void eevdf_sysctl_register(void)
{
    /* Register sysctl entries for EEVDF tuning */
    sysctl_register_int("sched_latency_ns", &eevdf_global.sysctl_sched_latency);
    sysctl_register_int("sched_min_granularity_ns", 
                        &eevdf_global.sysctl_sched_min_granularity);
    sysctl_register_int("sched_wakeup_granularity_ns",
                        &eevdf_global.sysctl_sched_wakeup_granularity);
    sysctl_register_int("sched_child_runs_first",
                        (int*)&eevdf_global.sysctl_sched_child_runs_first);
}

/*
 * eevdf_performance_monitor
 *
 * Performance monitoring for EEVDF
 */
struct eevdf_perf_data {
    unsigned long long avg_scheduling_latency;
    unsigned long long max_scheduling_latency;
    unsigned long long avg_deadline_margin;
    unsigned long long preemption_ratio;
    unsigned long long load_balance_effectiveness;
};

void eevdf_collect_perf_data(struct eevdf_perf_data *data)
{
    struct eevdf_rq *rq;
    int cpu;
    unsigned long long total_latency = 0;
    unsigned long long max_latency = 0;
    unsigned long long total_margin = 0;
    unsigned long long total_preempt = 0;
    unsigned long long total_running = 0;
    
    if (data == NULL)
        return;
    
    for (cpu = 0; cpu < smp_get_numcpus(); cpu++) {
        rq = &eevdf_rq_percpu[cpu];
        simple_lock(&rq->lock);
        
        total_latency += rq->avg_scheduling_latency;
        if (rq->max_scheduling_latency > max_latency)
            max_latency = rq->max_scheduling_latency;
        
        total_margin += rq->avg_deadline_margin;
        total_preempt += rq->stats.preempt_count;
        total_running += rq->nr_running;
        
        simple_unlock(&rq->lock);
    }
    
    data->avg_scheduling_latency = total_latency / smp_get_numcpus();
    data->max_scheduling_latency = max_latency;
    data->avg_deadline_margin = total_margin / smp_get_numcpus();
    data->preemption_ratio = total_running > 0 ? total_preempt / total_running : 0;
    data->load_balance_effectiveness = eevdf_balance_effectiveness;
}

/*
 * Constants and flags definitions
 */
#define EEVDF_FLAG_MIGRATE_NUMA      0x00000001
#define EEVDF_FLAG_THROTTLED         0x00000002
#define EEVDF_FLAG_YIELDED           0x00000004
#define EEVDF_FLAG_AFFINITY_SET      0x00000008
#define EEVDF_FLAG_ENERGY_AWARE      0x00000010

/* EEVDF global arrays */
static struct eevdf_numa_domain eevdf_numa_domains[MAX_NODES];
static unsigned long long eevdf_numa_distances[MAX_NODES][MAX_NODES];
static unsigned long long eevdf_cpu_utilization[MAX_CPUS];
static struct eevdf_energy_model eevdf_energy_model;
static unsigned long long eevdf_prev_period = 0;
static unsigned long long eevdf_balance_effectiveness = 0;

/* Helper functions declarations */
static int numa_max_nodes(void);
static int node_to_cpu(int node, int index);
static int cpu_to_node(int cpu);
static unsigned int popcount(unsigned int mask);
static void set_cpu_frequency(int cpu, unsigned int freq);
static unsigned int current_cpu_frequency(void);
static unsigned long long eevdf_update_curr(struct eevdf_sched_entity *se);

/* Maximum NUMA nodes supported */
#define MAX_NUMA_NODES 64
#define INVALID_NODE_ID 0xFFFFFFFF

/* NUMA node information structure */
struct numa_node_info {
    unsigned int node_id;
    unsigned int processor_start;
    unsigned int processor_count;
    unsigned long long base_address;
    unsigned long long size;
    unsigned int memory_controller;
    unsigned int distance_table[MAX_NUMA_NODES];
};

/* Global NUMA configuration */
static struct numa_node_info numa_nodes[MAX_NUMA_NODES];
static unsigned int numa_node_count = 0;
static unsigned int numa_initialized = FALSE;

/* CPU to NUMA node mapping */
static unsigned int cpu_to_node_map[MAX_CPUS];

/* Node to CPU list mapping */
static unsigned int node_to_cpu_list[MAX_NUMA_NODES][MAX_CPUS];
static unsigned int node_to_cpu_count[MAX_NUMA_NODES];

/* Frequency scaling structures */
struct cpu_freq_info {
    unsigned int current_freq;      /* Current frequency in KHz */
    unsigned int min_freq;          /* Minimum supported frequency */
    unsigned int max_freq;          /* Maximum supported frequency */
    unsigned int turbo_freq;        /* Turbo boost frequency */
    unsigned int latency;           /* Transition latency in microseconds */
    unsigned int voltage;           /* Current voltage in mV */
    unsigned int power;             /* Current power consumption in mW */
    unsigned int temperature;       /* Current temperature in millidegrees */
    simple_lock_t lock;
    boolean_t enabled;
};

static struct cpu_freq_info cpu_freq[MAX_CPUS];

/* EEVDF scheduler update function */
static unsigned long long eevdf_update_curr(struct eevdf_sched_entity *se)
{
    unsigned long long now, delta_exec, delta_vruntime;
    unsigned long long prev_exec_time;
    
    if (se == NULL)
        return 0;
    
    now = mach_absolute_time();
    prev_exec_time = se->exec_start;
    
    if (prev_exec_time == 0) {
        se->exec_start = now;
        return 0;
    }
    
    delta_exec = now - prev_exec_time;
    if (delta_exec == 0)
        return 0;
    
    /* Update execution time */
    se->sum_exec_runtime += delta_exec;
    se->slice_used += delta_exec;
    
    /* Calculate vruntime delta based on weight */
    delta_vruntime = eevdf_calc_vruntime_delta(delta_exec, se->weight);
    se->vruntime += delta_vruntime;
    
    /* Update exec start time for next delta */
    se->exec_start = now;
    
    /* Return the delta for bandwidth accounting */
    return delta_exec;
}

/*
 * numa_max_nodes
 *
 * Returns the maximum number of NUMA nodes in the system
 */
static int numa_max_nodes(void)
{
    if (!numa_initialized)
        return 1;  /* Default to 1 node if not initialized */
    
    return numa_node_count;
}

/*
 * numa_init
 *
 * Initialize NUMA topology from SRAT table or ACPI
 */
static void numa_init(void)
{
    unsigned int i, j;
    unsigned int cpu, node;
    processor_t processor;
    
    printf("Initializing NUMA topology...\n");
    
    /* Try to read from SRAT table */
    if (srat_table_present()) {
        numa_node_count = srat_get_node_count();
        for (i = 0; i < numa_node_count; i++) {
            numa_nodes[i].node_id = srat_get_node_id(i);
            numa_nodes[i].processor_start = srat_get_node_processor_start(i);
            numa_nodes[i].processor_count = srat_get_node_processor_count(i);
            numa_nodes[i].base_address = srat_get_node_memory_base(i);
            numa_nodes[i].size = srat_get_node_memory_size(i);
            numa_nodes[i].memory_controller = srat_get_node_mc_id(i);
            
            /* Get distance table */
            for (j = 0; j < numa_node_count; j++) {
                numa_nodes[i].distance_table[j] = srat_get_node_distance(i, j);
            }
        }
    } else {
        /* Default to single node configuration */
        numa_node_count = 1;
        numa_nodes[0].node_id = 0;
        numa_nodes[0].processor_start = 0;
        numa_nodes[0].processor_count = smp_get_numcpus();
        numa_nodes[0].base_address = 0;
        numa_nodes[0].size = vm_page_count() * PAGE_SIZE;
        numa_nodes[0].memory_controller = 0;
        
        for (j = 0; j < MAX_NUMA_NODES; j++) {
            numa_nodes[0].distance_table[j] = 10;  /* Local distance */
        }
    }
    
    /* Initialize CPU to node mapping */
    for (cpu = 0; cpu < MAX_CPUS; cpu++) {
        cpu_to_node_map[cpu] = INVALID_NODE_ID;
    }
    
    /* Build CPU to node mapping */
    for (node = 0; node < numa_node_count; node++) {
        node_to_cpu_count[node] = 0;
        
        for (cpu = 0; cpu < numa_nodes[node].processor_count; cpu++) {
            unsigned int global_cpu = numa_nodes[node].processor_start + cpu;
            if (global_cpu < MAX_CPUS) {
                cpu_to_node_map[global_cpu] = node;
                node_to_cpu_list[node][node_to_cpu_count[node]++] = global_cpu;
            }
        }
    }
    
    /* Verify all CPUs have node mapping */
    for (cpu = 0; cpu < smp_get_numcpus(); cpu++) {
        if (cpu_to_node_map[cpu] == INVALID_NODE_ID) {
            /* Assign to node 0 by default */
            cpu_to_node_map[cpu] = 0;
            node_to_cpu_list[0][node_to_cpu_count[0]++] = cpu;
        }
    }
    
    /* Print NUMA configuration */
    printf("NUMA Configuration:\n");
    printf("  Nodes: %d\n", numa_node_count);
    for (node = 0; node < numa_node_count; node++) {
        printf("  Node %d: CPUs %d-%d, Memory %lluMB\n",
               numa_nodes[node].node_id,
               numa_nodes[node].processor_start,
               numa_nodes[node].processor_start + numa_nodes[node].processor_count - 1,
               numa_nodes[node].size / (1024 * 1024));
    }
    
    numa_initialized = TRUE;
}

/*
 * node_to_cpu
 *
 * Returns the CPU number for a given node and index
 */
static int node_to_cpu(int node, int index)
{
    if (node < 0 || node >= MAX_NUMA_NODES)
        return -1;
    
    if (!numa_initialized)
        return index;  /* Fallback to linear mapping */
    
    if (index >= node_to_cpu_count[node])
        return -1;
    
    return node_to_cpu_list[node][index];
}

/*
 * cpu_to_node
 *
 * Returns the NUMA node ID for a given CPU
 */
static int cpu_to_node(int cpu)
{
    if (cpu < 0 || cpu >= MAX_CPUS)
        return 0;  /* Default to node 0 */
    
    if (!numa_initialized) {
        /* Simple linear mapping */
        return cpu / (smp_get_numcpus() / numa_node_count);
    }
    
    return cpu_to_node_map[cpu];
}

/*
 * popcount
 *
 * Count number of set bits in a mask
 */
static unsigned int popcount(unsigned int mask)
{
    unsigned int count = 0;
    
    /* Using Brian Kernighan's algorithm */
    while (mask) {
        mask &= (mask - 1);
        count++;
    }
    
    return count;
}

/*
 * set_cpu_frequency
 *
 * Set CPU frequency (platform dependent)
 */
static void set_cpu_frequency(int cpu, unsigned int freq_khz)
{
    struct cpu_freq_info *freq_info;
    unsigned long long now;
    static unsigned long long last_freq_change[MAX_CPUS];
    
    if (cpu < 0 || cpu >= MAX_CPUS)
        return;
    
    freq_info = &cpu_freq[cpu];
    
    simple_lock(&freq_info->lock);
    
    if (!freq_info->enabled) {
        simple_unlock(&freq_info->lock);
        return;
    }
    
    /* Validate frequency range */
    if (freq_khz < freq_info->min_freq)
        freq_khz = freq_info->min_freq;
    if (freq_khz > freq_info->max_freq)
        freq_khz = freq_info->max_freq;
    
    /* Rate limit frequency changes (min 10ms between changes) */
    now = mach_absolute_time();
    if (now - last_freq_change[cpu] < 10000000) {  /* 10ms in nanoseconds */
        simple_unlock(&freq_info->lock);
        return;
    }
    
    /* Platform specific frequency setting */
#if defined(__i386__) || defined(__x86_64__)
    /* Intel/AMD specific: use MSR or ACPI P-states */
    if (cpu == cpu_number()) {
        /* Set current CPU frequency using MSR */
        unsigned long long msr_val;
        
        /* Calculate ratio for target frequency */
        unsigned int ratio = (freq_khz * 100) / freq_info->max_freq;
        
        /* Read current MSR */
        rdmsrl(MSR_IA32_PERF_CTL, msr_val);
        
        /* Update frequency ratio */
        msr_val &= ~0xFFFF;
        msr_val |= (ratio & 0xFFFF);
        
        /* Write back MSR */
        wrmsrl(MSR_IA32_PERF_CTL, msr_val);
        
        /* Wait for transition */
        do {
            rdmsrl(MSR_IA32_PERF_STATUS, msr_val);
        } while ((msr_val & 0xFFFF) != (ratio & 0xFFFF));
    } else {
        /* Send IPI to other CPU to change frequency */
        smp_send_ipi(cpu, IPI_FREQ_CHANGE, freq_khz);
    }
#elif defined(__arm__) || defined(__aarch64__)
    /* ARM specific: use CPUfreq or DVFS */
    set_arm_cpu_frequency(cpu, freq_khz);
#else
    /* Generic fallback: nothing to do */
#endif
    
    /* Update frequency info */
    freq_info->current_freq = freq_khz;
    last_freq_change[cpu] = now;
    
    /* Update voltage based on frequency (simplified model) */
    freq_info->voltage = freq_info->min_voltage + 
                         ((freq_khz - freq_info->min_freq) * 
                          (freq_info->max_voltage - freq_info->min_voltage)) / 
                         (freq_info->max_freq - freq_info->min_freq);
    
    /* Update power consumption (P = C * V^2 * f) */
    freq_info->power = (freq_info->capacitance * 
                        freq_info->voltage * freq_info->voltage * 
                        freq_khz) / 1000000;
    
    simple_unlock(&freq_info->lock);
}

/*
 * current_cpu_frequency
 *
 * Get current frequency of the calling CPU
 */
static unsigned int current_cpu_frequency(void)
{
    int cpu = cpu_number();
    struct cpu_freq_info *freq_info;
    unsigned int freq;
    
    if (cpu < 0 || cpu >= MAX_CPUS)
        return 0;
    
    freq_info = &cpu_freq[cpu];
    
    simple_lock(&freq_info->lock);
    
    if (!freq_info->enabled) {
        simple_unlock(&freq_info->lock);
        return freq_info->max_freq;  /* Return max if not enabled */
    }
    
    freq = freq_info->current_freq;
    
    simple_unlock(&freq_info->lock);
    
    return freq;
}

/*
 * freq_init
 *
 * Initialize CPU frequency scaling infrastructure
 */
static void freq_init(void)
{
    int cpu;
    struct cpu_freq_info *freq_info;
    
    printf("Initializing CPU frequency scaling...\n");
    
    for (cpu = 0; cpu < smp_get_numcpus(); cpu++) {
        freq_info = &cpu_freq[cpu];
        
        simple_lock_init(&freq_info->lock);
        
        /* Get platform-specific frequency limits */
#if defined(__i386__) || defined(__x86_64__)
        unsigned long long msr_val;
        
        /* Read maximum frequency from MSR */
        rdmsrl(MSR_IA32_PERF_CAPABILITIES, msr_val);
        freq_info->max_freq = ((msr_val >> 8) & 0xFF) * 100000;  /* KHz */
        
        /* Read minimum frequency */
        rdmsrl(MSR_IA32_PERF_STATUS, msr_val);
        freq_info->min_freq = ((msr_val >> 8) & 0xFF) * 100000;
        
        /* Read turbo frequency if available */
        if (msr_val & (1ULL << 16)) {
            freq_info->turbo_freq = freq_info->max_freq * 120 / 100;
        } else {
            freq_info->turbo_freq = freq_info->max_freq;
        }
#elif defined(__arm__) || defined(__aarch64__)
        /* ARM specific frequency detection */
        freq_info->max_freq = get_arm_max_frequency(cpu);
        freq_info->min_freq = get_arm_min_frequency(cpu);
        freq_info->turbo_freq = freq_info->max_freq;
#else
        /* Default values */
        freq_info->max_freq = 2400000;  /* 2.4 GHz default */
        freq_info->min_freq = 800000;   /* 800 MHz default */
        freq_info->turbo_freq = freq_info->max_freq;
#endif
        
        freq_info->current_freq = freq_info->max_freq;
        freq_info->latency = 100;  /* 100 microseconds default */
        freq_info->min_voltage = 800;   /* 800 mV */
        freq_info->max_voltage = 1300;  /* 1300 mV */
        freq_info->voltage = freq_info->max_voltage;
        freq_info->capacitance = 100;   /* Capacitance factor */
        freq_info->enabled = TRUE;
        
        printf("  CPU %d: min=%uKHz max=%uKHz turbo=%uKHz\n",
               cpu, freq_info->min_freq, freq_info->max_freq, freq_info->turbo_freq);
    }
}

/*
 * eevdf_calc_vruntime_delta
 *
 * Calculate vruntime delta for given execution time and weight
 */
static unsigned long long eevdf_calc_vruntime_delta(unsigned long long delta, long weight)
{
    unsigned long long vruntime_delta;
    
    /* Avoid division by zero */
    if (weight <= 0)
        weight = EEVDF_WEIGHT_SCALE;
    
    /* vruntime = delta * NICE_0_LOAD / weight */
    vruntime_delta = (delta * EEVDF_WEIGHT_SCALE) / weight;
    
    return vruntime_delta;
}

/*
 * eevdf_calc_weight
 *
 * Calculate weight from nice value
 */
static long eevdf_calc_weight(int nice)
{
    static const int prio_to_weight[40] = {
        88761, 71755, 56483, 46273, 36291,
        29154, 23254, 18705, 14949, 11916,
        9548, 7620, 6100, 4904, 3906,
        3121, 2501, 1991, 1586, 1277,
        1024, 820, 655, 526, 423,
        335, 272, 215, 172, 137,
        110, 87, 70, 56, 45,
        36, 29, 23, 18, 15,
    };
    
    int idx = nice + 20;
    
    if (idx < 0)
        idx = 0;
    if (idx >= 40)
        idx = 39;
    
    return prio_to_weight[idx];
}

/*
 * srat_table_present
 *
 * Check if SRAT table is present (ACPI)
 */
static boolean_t srat_table_present(void)
{
    /* In real implementation, would check ACPI SRAT table */
    /* For now, return FALSE to use default configuration */
    return FALSE;
}

/*
 * srat_get_node_count
 *
 * Get number of NUMA nodes from SRAT
 */
static unsigned int srat_get_node_count(void)
{
    /* Would parse SRAT table */
    return 1;
}

/*
 * srat_get_node_id
 *
 * Get node ID from SRAT
 */
static unsigned int srat_get_node_id(unsigned int index)
{
    /* Would parse SRAT table */
    return index;
}

/*
 * srat_get_node_processor_start
 *
 * Get starting processor for node
 */
static unsigned int srat_get_node_processor_start(unsigned int node)
{
    /* Would parse SRAT table */
    return node * (smp_get_numcpus() / srat_get_node_count());
}

/*
 * srat_get_node_processor_count
 *
 * Get processor count for node
 */
static unsigned int srat_get_node_processor_count(unsigned int node)
{
    /* Would parse SRAT table */
    return smp_get_numcpus() / srat_get_node_count();
}

/*
 * srat_get_node_memory_base
 *
 * Get memory base address for node
 */
static unsigned long long srat_get_node_memory_base(unsigned int node)
{
    /* Would parse SRAT table */
    return node * (vm_page_count() * PAGE_SIZE / srat_get_node_count());
}

/*
 * srat_get_node_memory_size
 *
 * Get memory size for node
 */
static unsigned long long srat_get_node_memory_size(unsigned int node)
{
    /* Would parse SRAT table */
    return vm_page_count() * PAGE_SIZE / srat_get_node_count();
}

/*
 * srat_get_node_mc_id
 *
 * Get memory controller ID for node
 */
static unsigned int srat_get_node_mc_id(unsigned int node)
{
    /* Would parse SRAT table */
    return node;
}

/*
 * srat_get_node_distance
 *
 * Get distance between nodes from SLIT table
 */
static unsigned int srat_get_node_distance(unsigned int node1, unsigned int node2)
{
    /* Would parse SLIT table */
    if (node1 == node2)
        return 10;  /* Local distance */
    return 20;      /* Remote distance */
}

/*
 * smp_send_ipi
 *
 * Send IPI to another CPU (for frequency changes)
 */
static void smp_send_ipi(int cpu, int ipi_type, unsigned int data)
{
    /* In real implementation, would send IPI */
    /* For now, just call directly if CPU matches */
    if (cpu == cpu_number()) {
        /* Handle frequency change on current CPU */
        if (ipi_type == IPI_FREQ_CHANGE) {
            /* Recurse safely */
            set_cpu_frequency(cpu, data);
        }
    }
}

/*
 * get_arm_max_frequency
 *
 * Get ARM CPU maximum frequency
 */
static unsigned int get_arm_max_frequency(int cpu)
{
    /* ARM-specific implementation would read from sysfs or device tree */
    return 2000000;  /* 2 GHz default */
}

/*
 * get_arm_min_frequency
 *
 * Get ARM CPU minimum frequency
 */
static unsigned int get_arm_min_frequency(int cpu)
{
    /* ARM-specific implementation would read from sysfs or device tree */
    return 500000;  /* 500 MHz default */
}

/*
 * set_arm_cpu_frequency
 *
 * Set ARM CPU frequency
 */
static void set_arm_cpu_frequency(int cpu, unsigned int freq_khz)
{
    /* ARM-specific implementation would write to sysfs or use SCPI */
    /* For now, just update the structure */
    struct cpu_freq_info *freq_info = &cpu_freq[cpu];
    freq_info->current_freq = freq_khz;
}

/*
 * eevdf_sched_init
 *
 * Initialize EEVDF scheduler helpers
 */
void eevdf_sched_init(void)
{
    /* Initialize NUMA subsystem */
    numa_init();
    
    /* Initialize frequency scaling */
    freq_init();
    
    /* Initialize EEVDF update function */
    printf("EEVDF scheduler helpers initialized\n");
    printf("  NUMA nodes: %d\n", numa_node_count);
    printf("  CPU freq scaling: %s\n", 
           cpu_freq[0].enabled ? "enabled" : "disabled");
}

/*
 * eevdf_get_node_distance
 *
 * Get distance between two NUMA nodes
 */
unsigned int eevdf_get_node_distance(int node1, int node2)
{
    if (!numa_initialized)
        return (node1 == node2) ? 10 : 20;
    
    if (node1 < 0 || node1 >= numa_node_count ||
        node2 < 0 || node2 >= numa_node_count)
        return 20;
    
    return numa_nodes[node1].distance_table[node2];
}

/*
 * eevdf_get_node_memory_size
 *
 * Get memory size for NUMA node
 */
unsigned long long eevdf_get_node_memory_size(int node)
{
    if (!numa_initialized || node < 0 || node >= numa_node_count)
        return vm_page_count() * PAGE_SIZE;
    
    return numa_nodes[node].size;
}

/*
 * eevdf_get_cpu_temperature
 *
 * Get CPU temperature in millidegrees Celsius
 */
unsigned int eevdf_get_cpu_temperature(int cpu)
{
    struct cpu_freq_info *freq_info;
    
    if (cpu < 0 || cpu >= MAX_CPUS)
        return 0;
    
    freq_info = &cpu_freq[cpu];
    
    /* Platform-specific temperature reading */
#if defined(__i386__) || defined(__x86_64__)
    if (cpu == cpu_number()) {
        unsigned long long msr_val;
        rdmsrl(MSR_IA32_THERM_STATUS, msr_val);
        return (msr_val >> 16) & 0x7F;  /* Digital readout */
    }
#endif
    
    return freq_info->temperature;
}

/*
 * eevdf_get_cpu_power
 *
 * Get CPU power consumption in milliwatts
 */
unsigned int eevdf_get_cpu_power(int cpu)
{
    struct cpu_freq_info *freq_info;
    
    if (cpu < 0 || cpu >= MAX_CPUS)
        return 0;
    
    freq_info = &cpu_freq[cpu];
    
    simple_lock(&freq_info->lock);
    unsigned int power = freq_info->power;
    simple_unlock(&freq_info->lock);
    
    return power;
}

/*
 * MSR definitions for x86
 */
#ifdef __x86_64__
#define MSR_IA32_PERF_CTL         0x199
#define MSR_IA32_PERF_STATUS      0x198
#define MSR_IA32_PERF_CAPABILITIES 0x345
#define MSR_IA32_THERM_STATUS     0x19C
#endif

/* IPI types */
#define IPI_FREQ_CHANGE           0x01
#define IPI_TLB_SHOOTDOWN         0x02
#define IPI_RESCHEDULE            0x03

/* EEVDF weight scale */
#ifndef EEVDF_WEIGHT_SCALE
#define EEVDF_WEIGHT_SCALE 1024
#endif

/*
 * EEVDF statistics tracking
 */
void eevdf_update_scheduling_latency(int cpu, unsigned long long latency)
{
    struct eevdf_rq *rq;
    
    if (cpu < 0 || cpu >= MAX_CPUS)
        return;
    
    rq = &eevdf_rq_percpu[cpu];
    simple_lock(&rq->lock);
    
    /* Update running average */
    rq->avg_scheduling_latency = (rq->avg_scheduling_latency * 7 + latency) / 8;
    
    if (latency > rq->max_scheduling_latency)
        rq->max_scheduling_latency = latency;
    
    simple_unlock(&rq->lock);
}

void eevdf_update_deadline_margin(int cpu, unsigned long long margin)
{
    struct eevdf_rq *rq;
    
    if (cpu < 0 || cpu >= MAX_CPUS)
        return;
    
    rq = &eevdf_rq_percpu[cpu];
    simple_lock(&rq->lock);
    
    rq->avg_deadline_margin = (rq->avg_deadline_margin * 7 + margin) / 8;
    
    simple_unlock(&rq->lock);
}

void eevdf_update_balance_effectiveness(unsigned long long effectiveness)
{
    eevdf_balance_effectiveness = (eevdf_balance_effectiveness * 7 + effectiveness) / 8;
}
