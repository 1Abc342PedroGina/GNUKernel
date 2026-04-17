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
 * License:GPL-2.0-or-later
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
 *	File:	kern/thread.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young, David Golub
 *	Date:	1986
 *
 *	Thread management primitives implementation.
 */

#include <kern/printf.h>
#include <mach/message.h>
#include <mach/std_types.h>
#include <mach/policy.h>
#include <mach/thread_info.h>
#include <mach/thread_special_ports.h>
#include <mach/thread_status.h>
#include <mach/time_value.h>
#include <mach/vm_prot.h>
#include <mach/vm_inherit.h>
#include <machine/vm_param.h>
#include <kern/ast.h>
#include <kern/counters.h>
#include <kern/debug.h>
#include <kern/eventcount.h>
#include <kern/gnumach.server.h>
#include <kern/ipc_mig.h>
#include <kern/ipc_tt.h>
#include <kern/mach_debug.server.h>
#include <kern/mach_host.server.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/syscall_subr.h>
#include <kern/thread.h>
#include <kern/thread_swap.h>
#include <kern/host.h>
#include <kern/kalloc.h>
#include <kern/slab.h>
#include <kern/smp.h>
#include <kern/mach_clock.h>
#include <string.h>
#include <vm/vm_kern.h>
#include <vm/vm_user.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_port.h>
#include <ipc/mach_msg.h>
#include <ipc/mach_port.server.h>
#include <machine/spl.h>		/* for splsched */
#include <machine/pcb.h>
#include <machine/thread.h>		/* for MACHINE_STACK */

struct kmem_cache thread_cache;
struct kmem_cache thread_stack_cache;

queue_head_t		reaper_queue;
def_simple_lock_data(static,	reaper_lock)

/* private */
struct thread	thread_template;

#if	MACH_DEBUG
#define	STACK_MARKER	0xdeadbeefU
boolean_t		stack_check_usage = FALSE;
def_simple_lock_data(static,	stack_usage_lock)
vm_size_t		stack_max_usage = 0;
#endif	/* MACH_DEBUG */

/*
 *	Machine-dependent code must define:
 *		pcb_init
 *		pcb_terminate
 *		pcb_collect
 *
 *	The thread->pcb field is reserved for machine-dependent code.
 */

#ifdef	MACHINE_STACK
/*
 *	Machine-dependent code must define:
 *		stack_alloc_try
 *		stack_alloc
 *		stack_free
 *		stack_handoff
 *		stack_collect
 *	and if MACH_DEBUG:
 *		stack_statistics
 */
#else	/* MACHINE_STACK */
/*
 *	We allocate stacks from generic kernel VM.
 *	Machine-dependent code must define:
 *		stack_attach
 *		stack_detach
 *		stack_handoff
 *
 *	The stack_free_list can only be accessed at splsched,
 *	because stack_alloc_try/thread_invoke operate at splsched.
 */

def_simple_lock_data(static, stack_lock_data)/* splsched only */
#define stack_lock()	simple_lock(&stack_lock_data)
#define stack_unlock()	simple_unlock(&stack_lock_data)

vm_offset_t stack_free_list;		/* splsched only */
unsigned int stack_free_count = 0;	/* splsched only */
unsigned int stack_free_limit = 1;	/* patchable */

/*
 *	The next field is at the base of the stack,
 *	so the low end is left unsullied.
 */

#define stack_next(stack) (*((vm_offset_t *)((stack) + KERNEL_STACK_SIZE) - 1))

/*
 *	stack_alloc_try:
 *
 *	Non-blocking attempt to allocate a kernel stack.
 *	Called at splsched with the thread locked.
 */

boolean_t stack_alloc_try(
	thread_t	thread,
	void		(*resume)(thread_t))
{
	vm_offset_t stack;

	stack_lock();
	stack = stack_free_list;
	if (stack != 0) {
		stack_free_list = stack_next(stack);
		stack_free_count--;
	} else {
		stack = thread->stack_privilege;
	}
	stack_unlock();

	if (stack != 0) {
		stack_attach(thread, stack, resume);
		counter(c_stack_alloc_hits++);
		return TRUE;
	} else {
		counter(c_stack_alloc_misses++);
		return FALSE;
	}
}

/*
 *	stack_alloc:
 *
 *	Allocate a kernel stack for a thread.
 *	May block.
 */

kern_return_t stack_alloc(
	thread_t	thread,
	void		(*resume)(thread_t))
{
	vm_offset_t stack;
	spl_t s;

	/*
	 *	We first try the free list.  It is probably empty,
	 *	or stack_alloc_try would have succeeded, but possibly
	 *	a stack was freed before the swapin thread got to us.
	 */

	s = splsched();
	stack_lock();
	stack = stack_free_list;
	if (stack != 0) {
		stack_free_list = stack_next(stack);
		stack_free_count--;
	}
	stack_unlock();
	(void) splx(s);

	if (stack == 0) {
		stack = kmem_cache_alloc(&thread_stack_cache);
		assert(stack != 0);
#if	MACH_DEBUG
		stack_init(stack);
#endif	/* MACH_DEBUG */
	}

	stack_attach(thread, stack, resume);
	return KERN_SUCCESS;
}

/*
 *	stack_free:
 *
 *	Free a thread's kernel stack.
 *	Called at splsched with the thread locked.
 */

void stack_free(
	thread_t thread)
{
	vm_offset_t stack;

	stack = stack_detach(thread);

	if (stack != thread->stack_privilege) {
		stack_lock();
		stack_next(stack) = stack_free_list;
		stack_free_list = stack;
		stack_free_count += 1;
#if	MACH_COUNTERS
		if (stack_free_count > c_stack_alloc_max)
			c_stack_alloc_max = stack_free_count;
#endif	/* MACH_COUNTERS */
		stack_unlock();
	}
}

/*
 *	stack_collect:
 *
 *	Free excess kernel stacks.
 *	May block.
 */

void stack_collect(void)
{
	vm_offset_t stack;
	spl_t s;

	s = splsched();
	stack_lock();
	while (stack_free_count > stack_free_limit) {
		stack = stack_free_list;
		stack_free_list = stack_next(stack);
		stack_free_count--;
		stack_unlock();
		(void) splx(s);

#if	MACH_DEBUG
		stack_finalize(stack);
#endif	/* MACH_DEBUG */
		kmem_cache_free(&thread_stack_cache, stack);

		s = splsched();
		stack_lock();
	}
	stack_unlock();
	(void) splx(s);
}
#endif	/* MACHINE_STACK */

/*
 *	stack_privilege:
 *
 *	stack_alloc_try on this thread must always succeed.
 */

void stack_privilege(
	thread_t thread)
{
	/*
	 *	This implementation only works for the current thread.
	 */

	if (thread != current_thread())
		panic("stack_privilege");

	if (thread->stack_privilege == 0)
		thread->stack_privilege = current_stack();
}

void thread_init(void)
{
	kmem_cache_init(&thread_cache, "thread", sizeof(struct thread), 0,
			NULL, 0);
	/*
	 *	Kernel stacks should be naturally aligned,
	 *	so that it is easy to find the starting/ending
	 *	addresses of a stack given an address in the middle.
	 */
	kmem_cache_init(&thread_stack_cache, "thread_stack",
			KERNEL_STACK_SIZE, KERNEL_STACK_SIZE,
			NULL, 0);

	/*
	 *	Fill in a template thread for fast initialization.
	 *	[Fields that must be (or are typically) reset at
	 *	time of creation are so noted.]
	 */

	/* thread_template.links (none) */
	thread_template.runq = RUN_QUEUE_NULL;

	/* thread_template.task (later) */
	/* thread_template.thread_list (later) */
	/* thread_template.pset_threads (later) */

	/* thread_template.lock (later) */
	/* one ref for being alive; one for the guy who creates the thread */
	thread_template.ref_count = 2;

	thread_template.pcb = (pcb_t) 0;		/* (reset) */
	thread_template.kernel_stack = (vm_offset_t) 0;
	thread_template.stack_privilege = (vm_offset_t) 0;

	thread_template.wait_event = 0;
	/* thread_template.suspend_count (later) */
	thread_template.wait_result = KERN_SUCCESS;
	thread_template.wake_active = FALSE;
	thread_template.state = TH_SUSP | TH_SWAPPED;
	thread_template.swap_func = thread_bootstrap_return;

/*	thread_template.priority (later) */
	thread_template.max_priority = BASEPRI_USER;
/*	thread_template.sched_pri (later - compute_priority) */
#if	MACH_FIXPRI
	thread_template.sched_data = 0;
	thread_template.policy = POLICY_TIMESHARE;
#endif	/* MACH_FIXPRI */
	thread_template.depress_priority = -1;
	thread_template.cpu_usage = 0;
	thread_template.sched_usage = 0;
	/* thread_template.sched_stamp (later) */

	thread_template.recover = (vm_offset_t) 0;
	thread_template.vm_privilege = 0;

	thread_template.user_stop_count = 1;

	/* thread_template.<IPC structures> (later) */

	timer_init(&(thread_template.user_timer));
	timer_init(&(thread_template.system_timer));
	thread_template.user_timer_save.low = 0;
	thread_template.user_timer_save.high = 0;
	thread_template.system_timer_save.low = 0;
	thread_template.system_timer_save.high = 0;
	thread_template.cpu_delta = 0;
	thread_template.sched_delta = 0;

	thread_template.active = FALSE; /* reset */
	thread_template.ast = AST_ZILCH;

	/* thread_template.processor_set (later) */
	thread_template.bound_processor = PROCESSOR_NULL;
#if	MACH_HOST
	thread_template.may_assign = TRUE;
	thread_template.assign_active = FALSE;
#endif	/* MACH_HOST */

#if	NCPUS > 1
	/* thread_template.last_processor  (later) */
#endif	/* NCPUS > 1 */

	/*
	 *	Initialize other data structures used in
	 *	this module.
	 */

	queue_init(&reaper_queue);
	simple_lock_init(&reaper_lock);

#ifndef	MACHINE_STACK
	simple_lock_init(&stack_lock_data);
#endif	/* MACHINE_STACK */

#if	MACH_DEBUG
	simple_lock_init(&stack_usage_lock);
#endif	/* MACH_DEBUG */

	/*
	 *	Initialize any machine-dependent
	 *	per-thread structures necessary.
	 */

	pcb_module_init();
}

kern_return_t thread_create(
	task_t	parent_task,
	thread_t	*child_thread)		/* OUT */
{
	thread_t	new_thread;
	processor_set_t	pset;

	if (parent_task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	/*
	 *	Allocate a thread and initialize static fields
	 */

	new_thread = (thread_t) kmem_cache_alloc(&thread_cache);

	if (new_thread == THREAD_NULL)
		return KERN_RESOURCE_SHORTAGE;

	*new_thread = thread_template;

	record_time_stamp (&new_thread->creation_time);

	/*
	 *	Initialize runtime-dependent fields
	 */

	new_thread->task = parent_task;
	if (parent_task && current_thread() && current_task() != kernel_task &&
		parent_task == current_task() && current_thread()->vm_privilege)
		new_thread->vm_privilege = 1;
	simple_lock_init(&new_thread->lock);
	new_thread->sched_stamp = sched_tick;
	thread_timeout_setup(new_thread);

	/*
	 *	Create a pcb.  The kernel stack is created later,
	 *	when the thread is swapped-in.
	 */
	pcb_init(parent_task, new_thread);

	ipc_thread_init(new_thread);

	/*
	 *	Find the processor set for the parent task.
	 */
	task_lock(parent_task);
	pset = parent_task->processor_set;
	pset_reference(pset);
	task_unlock(parent_task);

	/*
	 *	This thread will mosty probably start working, assume it
	 *	will take its share of CPU, to avoid having to find it out
	 *	slowly.  Decaying will however fix that quickly if it actually
	 *	does not work
	 */
	new_thread->cpu_usage = TIMER_RATE * SCHED_SCALE /
				(pset->load_average >= SCHED_SCALE ?
				  pset->load_average : SCHED_SCALE);
	new_thread->sched_usage = TIMER_RATE * SCHED_SCALE;

	/*
	 *	Lock both the processor set and the task,
	 *	so that the thread can be added to both
	 *	simultaneously.  Processor set must be
	 *	locked first.
	 */

    Restart:
	pset_lock(pset);
	task_lock(parent_task);

	/*
	 *	If the task has changed processor sets,
	 *	catch up (involves lots of lock juggling).
	 */
	{
	    processor_set_t	cur_pset;

	    cur_pset = parent_task->processor_set;
	    if (!cur_pset->active)
		cur_pset = &default_pset;

	    if (cur_pset != pset) {
		pset_reference(cur_pset);
		task_unlock(parent_task);
		pset_unlock(pset);
		pset_deallocate(pset);
		pset = cur_pset;
		goto Restart;
	    }
	}

	/*
	 *	Set the thread`s priority from the pset and task.
	 */

	new_thread->priority = parent_task->priority;
	if (pset->max_priority > new_thread->max_priority)
		new_thread->max_priority = pset->max_priority;
	if (new_thread->max_priority > new_thread->priority)
		new_thread->priority = new_thread->max_priority;
	/*
	 *	Don't need to lock thread here because it can't
	 *	possibly execute and no one else knows about it.
	 */
	compute_priority(new_thread, TRUE);

	/*
	 *	Thread is suspended if the task is.  Add 1 to
	 *	suspend count since thread is created in suspended
	 *	state.
	 */
	new_thread->suspend_count = parent_task->suspend_count + 1;

	/*
	 *	Add the thread to the processor set.
	 *	If the pset is empty, suspend the thread again.
	 */

	pset_add_thread(pset, new_thread);
	if (pset->empty)
		new_thread->suspend_count++;

#if	HW_FOOTPRINT
	/*
	 *	Need to set last_processor, idle processor would be best, but
	 *	that requires extra locking nonsense.  Go for tail of
	 *	processors queue to avoid master.
	 */
	if (!pset->empty) {
		new_thread->last_processor = 
			(processor_t)queue_first(&pset->processors);
	}
	else {
		/*
		 *	Thread created in empty processor set.  Pick
		 *	master processor as an acceptable legal value.
		 */
		new_thread->last_processor = master_processor;
	}
#else	/* HW_FOOTPRINT */
	/*
	 *	Don't need to initialize because the context switch
	 *	code will set it before it can be used.
	 */
#endif	/* HW_FOOTPRINT */

#if	MACH_PCSAMPLE
	new_thread->pc_sample.seqno = 0;
	new_thread->pc_sample.sampletypes = 0;
#endif	/* MACH_PCSAMPLE */

	new_thread->pc_sample.buffer = 0;

	/* Inherit the task name as the thread name. */
	memcpy (new_thread->name, parent_task->name, THREAD_NAME_SIZE);

	/*
	 *	Add the thread to the task`s list of threads.
	 *	The new thread holds another reference to the task.
	 */

	parent_task->ref_count++;

	parent_task->thread_count++;
	queue_enter(&parent_task->thread_list, new_thread, thread_t,
					thread_list);

	/*
	 *	Finally, mark the thread active.
	 */

	new_thread->active = TRUE;

	if (!parent_task->active) {
		task_unlock(parent_task);
		pset_unlock(pset);
		(void) thread_terminate(new_thread);
		/* release ref we would have given our caller */
		thread_deallocate(new_thread);
		return KERN_FAILURE;
	}
	task_unlock(parent_task);
	pset_unlock(pset);

	ipc_thread_enable(new_thread);

	*child_thread = new_thread;
	return KERN_SUCCESS;
}

unsigned int thread_deallocate_stack = 0;

void thread_deallocate(
	thread_t	thread)
{
	spl_t		s;
	task_t		task;
	processor_set_t	pset;

	time_value64_t	user_time, system_time;

	if (thread == THREAD_NULL)
		return;

	/*
	 *	First, check for new count > 0 (the common case).
	 *	Only the thread needs to be locked.
	 */
	s = splsched();
	thread_lock(thread);
	if (--thread->ref_count > 0) {
		thread_unlock(thread);
		(void) splx(s);
		return;
	}

	/*
	 *	Count is zero.  However, the task's and processor set's
	 *	thread lists have implicit references to
	 *	the thread, and may make new ones.  Their locks also
	 *	dominate the thread lock.  To check for this, we
	 *	temporarily restore the one thread reference, unlock
	 *	the thread, and then lock the other structures in
	 *	the proper order.
	 */
	thread->ref_count = 1;
	thread_unlock(thread);
	(void) splx(s);

	pset = thread->processor_set;
	pset_lock(pset);

#if	MACH_HOST
	/*
	 *	The thread might have moved.
	 */
	while (pset != thread->processor_set) {
	    pset_unlock(pset);
	    pset = thread->processor_set;
	    pset_lock(pset);
	}
#endif	/* MACH_HOST */

	task = thread->task;
	task_lock(task);

	s = splsched();
	thread_lock(thread);

	if (--thread->ref_count > 0) {
		/*
		 *	Task or processor_set made extra reference.
		 */
		thread_unlock(thread);
		(void) splx(s);
		task_unlock(task);
		pset_unlock(pset);
		return;
	}

	/*
	 *	Thread has no references - we can remove it.
	 */

	/*
	 *	Remove pending timeouts.
	 */
	reset_timeout_check(&thread->timer);

	reset_timeout_check(&thread->depress_timer);
	thread->depress_priority = -1;

	/*
	 *	Accumulate times for dead threads in task.
	 */
	thread_read_times(thread, &user_time, &system_time);
	time_value64_add(&task->total_user_time, &user_time);
	time_value64_add(&task->total_system_time, &system_time);

	/*
	 *	Remove thread from task list and processor_set threads list.
	 */
	task->thread_count--;
	queue_remove(&task->thread_list, thread, thread_t, thread_list);

	pset_remove_thread(pset, thread);

	thread_unlock(thread);		/* no more references - safe */
	(void) splx(s);
	task_unlock(task);
	pset_unlock(pset);
	pset_deallocate(pset);

	/*
	 *	A couple of quick sanity checks
	 */

	if (thread == current_thread()) {
	    panic("thread deallocating itself");
	}
	if ((thread->state & ~(TH_RUN | TH_HALTED | TH_SWAPPED)) != TH_SUSP)
		panic("unstopped thread destroyed!");

	/*
	 *	Deallocate the task reference, since we know the thread
	 *	is not running.
	 */
	task_deallocate(thread->task);			/* may block */

	/*
	 *	Clean up any machine-dependent resources.
	 */
	if ((thread->state & TH_SWAPPED) == 0) {
		splsched();
		stack_free(thread);
		(void) splx(s);
		thread_deallocate_stack++;
	}
	/*
	 * Rattle the event count machinery (gag)
	 */
	evc_notify_abort(thread);

	pcb_terminate(thread);
	kmem_cache_free(&thread_cache, (vm_offset_t) thread);
}

void thread_reference(
	thread_t	thread)
{
	spl_t		s;

	if (thread == THREAD_NULL)
		return;

	s = splsched();
	thread_lock(thread);
	thread->ref_count++;
	thread_unlock(thread);
	(void) splx(s);
}

/*
 *	thread_terminate:
 *
 *	Permanently stop execution of the specified thread.
 *
 *	A thread to be terminated must be allowed to clean up any state
 *	that it has before it exits.  The thread is broken out of any
 *	wait condition that it is in, and signalled to exit.  It then
 *	cleans up its state and calls thread_halt_self on its way out of
 *	the kernel.  The caller waits for the thread to halt, terminates
 *	its IPC state, and then deallocates it.
 *
 *	If the caller is the current thread, it must still exit the kernel
 *	to clean up any state (thread and port references, messages, etc).
 *	When it exits the kernel, it then terminates its IPC state and
 *	queues itself for the reaper thread, which will wait for the thread
 *	to stop and then deallocate it.  (A thread cannot deallocate itself,
 *	since it needs a kernel stack to execute.)
 */
kern_return_t thread_terminate(
	thread_t	thread)
{
	thread_t		cur_thread = current_thread();
	task_t			cur_task;
	spl_t			s;

	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;

	/*
	 *	Break IPC control over the thread.
	 */
	ipc_thread_disable(thread);

	if (thread == cur_thread) {

	    /*
	     *	Current thread will queue itself for reaper when
	     *	exiting kernel.
	     */
	    s = splsched();
	    thread_lock(thread);
	    if (thread->active) {
		    thread->active = FALSE;
		    thread_ast_set(thread, AST_TERMINATE);
	    }
	    thread_unlock(thread);
	    ast_on(cpu_number(), AST_TERMINATE);
	    splx(s);
	    return KERN_SUCCESS;
	}

	/*
	 *	Lock both threads and the current task
	 *	to check termination races and prevent deadlocks.
	 */
	cur_task = current_task();
	task_lock(cur_task);
	s = splsched();
	if ((vm_offset_t)thread < (vm_offset_t)cur_thread) {
		thread_lock(thread);
		thread_lock(cur_thread);
	}
	else {
		thread_lock(cur_thread);
		thread_lock(thread);
	}

	/*
	 *	If the current thread is being terminated, help out.
	 */
	if ((!cur_task->active) || (!cur_thread->active)) {
		thread_unlock(cur_thread);
		thread_unlock(thread);
		(void) splx(s);
		task_unlock(cur_task);
		thread_terminate(cur_thread);
		return KERN_FAILURE;
	}
    
	thread_unlock(cur_thread);
	task_unlock(cur_task);

	/*
	 *	Terminate victim thread.
	 */
	if (!thread->active) {
		/*
		 *	Someone else got there first.
		 */
		thread_unlock(thread);
		(void) splx(s);
		return KERN_FAILURE;
	}

	thread->active = FALSE;

	thread_unlock(thread);
	(void) splx(s);

#if	MACH_HOST
	/*
	 *	Reassign thread to default pset if needed.
	 */
	thread_freeze(thread);
	if (thread->processor_set != &default_pset)
		thread_doassign(thread, &default_pset, FALSE);
#endif	/* MACH_HOST */

	/*
	 *	Halt the victim at the clean point.
	 */
	(void) thread_halt(thread, TRUE);
#if	MACH_HOST
	thread_unfreeze(thread);
#endif	/* MACH_HOST */
	/*
	 *	Shut down the victims IPC and deallocate its
	 *	reference to itself.
	 */
	ipc_thread_terminate(thread);
	thread_deallocate(thread);
	return KERN_SUCCESS;
}

kern_return_t thread_terminate_release(
	thread_t thread,
	task_t task,
	mach_port_name_t thread_name,
	mach_port_name_t reply_port,
	vm_offset_t address,
	vm_size_t size)
{
	if (task == NULL)
		return KERN_INVALID_ARGUMENT;

	if (thread == NULL)
		return KERN_INVALID_ARGUMENT;

	mach_port_deallocate(task->itk_space, thread_name);

	if (reply_port != MACH_PORT_NULL)
		mach_port_destroy(task->itk_space, reply_port);

	if ((address != 0) || (size != 0))
		vm_deallocate(task->map, address, size);

	return thread_terminate(thread);
}

/*
 *	thread_force_terminate:
 *
 *	Version of thread_terminate called by task_terminate.  thread is
 *	not the current thread.  task_terminate is the dominant operation,
 *	so we can force this thread to stop.
 */
void
thread_force_terminate(
	thread_t	thread)
{
	boolean_t	deallocate_here;
	spl_t s;

	ipc_thread_disable(thread);

#if	MACH_HOST
	/*
	 *	Reassign thread to default pset if needed.
	 */
	thread_freeze(thread);
	if (thread->processor_set != &default_pset)
		thread_doassign(thread, &default_pset, FALSE);
#endif	/* MACH_HOST */

	s = splsched();
	thread_lock(thread);
	deallocate_here = thread->active;
	thread->active = FALSE;
	thread_unlock(thread);
	(void) splx(s);

	(void) thread_halt(thread, TRUE);
	ipc_thread_terminate(thread);

#if	MACH_HOST
	thread_unfreeze(thread);
#endif	/* MACH_HOST */

	if (deallocate_here)
		thread_deallocate(thread);
}


/*
 *	Halt a thread at a clean point, leaving it suspended.
 *
 *	must_halt indicates whether thread must halt.
 *
 */
kern_return_t thread_halt(
	thread_t	thread,
	boolean_t		must_halt)
{
	thread_t	cur_thread = current_thread();
	kern_return_t	ret;
	spl_t	s;

	if (thread == cur_thread)
		panic("thread_halt: trying to halt current thread.");
	/*
	 *	If must_halt is FALSE, then a check must be made for
	 *	a cycle of halt operations.
	 */
	if (!must_halt) {
		/*
		 *	Grab both thread locks.
		 */
		s = splsched();
		if ((vm_offset_t)thread < (vm_offset_t)cur_thread) {
			thread_lock(thread);
			thread_lock(cur_thread);
		}
		else {
			thread_lock(cur_thread);
			thread_lock(thread);
		}

		/*
		 *	If target thread is already halted, grab a hold
		 *	on it and return.
		 */
		if (thread->state & TH_HALTED) {
			thread->suspend_count++;
			thread_unlock(cur_thread);
			thread_unlock(thread);
			(void) splx(s);
			return KERN_SUCCESS;
		}

		/*
		 *	If someone is trying to halt us, we have a potential
		 *	halt cycle.  Break the cycle by interrupting anyone
		 *	who is trying to halt us, and causing this operation
		 *	to fail; retry logic will only retry operations
		 *	that cannot deadlock.  (If must_halt is TRUE, this
		 *	operation can never cause a deadlock.)
		 */
		if (cur_thread->ast & AST_HALT) {
			thread_wakeup_with_result(TH_EV_WAKE_ACTIVE(cur_thread),
				THREAD_INTERRUPTED);
			thread_unlock(thread);
			thread_unlock(cur_thread);
			(void) splx(s);
			return KERN_FAILURE;
		}

		thread_unlock(cur_thread);
	
	}
	else {
		/*
		 *	Lock thread and check whether it is already halted.
		 */
		s = splsched();
		thread_lock(thread);
		if (thread->state & TH_HALTED) {
			thread->suspend_count++;
			thread_unlock(thread);
			(void) splx(s);
			return KERN_SUCCESS;
		}
	}

	/*
	 *	Suspend thread - inline version of thread_hold() because
	 *	thread is already locked.
	 */
	thread->suspend_count++;
	thread->state |= TH_SUSP;

	/*
	 *	If someone else is halting it, wait for that to complete.
	 *	Fail if wait interrupted and must_halt is false.
	 */
	while ((thread->ast & AST_HALT) && (!(thread->state & TH_HALTED))) {
		thread->wake_active = TRUE;
		thread_sleep(TH_EV_WAKE_ACTIVE(thread),
			simple_lock_addr(thread->lock), TRUE);

		if (thread->state & TH_HALTED) {
			(void) splx(s);
			return KERN_SUCCESS;
		}
		if ((current_thread()->wait_result != THREAD_AWAKENED)
		    && !(must_halt)) {
			(void) splx(s);
			thread_release(thread);
			return KERN_FAILURE;
		}
		thread_lock(thread);
	}

	/*
	 *	Otherwise, have to do it ourselves.
	 */
		
	thread_ast_set(thread, AST_HALT);

	while (TRUE) {
	  	/*
		 *	Wait for thread to stop.
		 */
		thread_unlock(thread);
		(void) splx(s);

		ret = thread_dowait(thread, must_halt);

		/*
		 *	If the dowait failed, so do we.  Drop AST_HALT, and
		 *	wake up anyone else who might be waiting for it.
		 */
		if (ret != KERN_SUCCESS) {
			s = splsched();
			thread_lock(thread);
			thread_ast_clear(thread, AST_HALT);
			thread_wakeup_with_result(TH_EV_WAKE_ACTIVE(thread),
				THREAD_INTERRUPTED);
			thread_unlock(thread);
			(void) splx(s);

			thread_release(thread);
			return ret;
		}

		/*
		 *	Clear any interruptible wait.
		 */
		clear_wait(thread, THREAD_INTERRUPTED, TRUE);

		/*
		 *	If the thread's at a clean point, we're done.
		 *	Don't need a lock because it really is stopped.
		 */
		if (thread->state & TH_HALTED)
			return KERN_SUCCESS;

		/*
		 *	If the thread is at a nice continuation,
		 *	or a continuation with a cleanup routine,
		 *	call the cleanup routine.
		 */
		if ((((thread->swap_func == mach_msg_continue) ||
		      (thread->swap_func == mach_msg_receive_continue)) &&
		     mach_msg_interrupt(thread)) ||
		    (thread->swap_func == thread_exception_return) ||
		    (thread->swap_func == thread_bootstrap_return)) {
			s = splsched();
			thread_lock(thread);
			thread->state |= TH_HALTED;
			thread_ast_clear(thread, AST_HALT);
			thread_unlock(thread);
			splx(s);

			return KERN_SUCCESS;
		}

		/*
		 *	Force the thread to stop at a clean
		 *	point, and arrange to wait for it.
		 *
		 *	Set it running, so it can notice.  Override
		 *	the suspend count.  We know that the thread
		 *	is suspended and not waiting.
		 *
		 *	Since the thread may hit an interruptible wait
		 *	before it reaches a clean point, we must force it
		 *	to wake us up when it does so.  This involves some
		 *	trickery:
		 *	  We mark the thread SUSPENDED so that thread_block
		 *	will suspend it and wake us up.
		 *	  We mark the thread RUNNING so that it will run.
		 *	  We mark the thread UN-INTERRUPTIBLE (!) so that
		 *	some other thread trying to halt or suspend it won't
		 *	take it off the run queue before it runs.  Since
		 *	dispatching a thread (the tail of thread_invoke) marks
		 *	the thread interruptible, it will stop at the next
		 *	context switch or interruptible wait.
		 */

		s = splsched();
		thread_lock(thread);
		if ((thread->state & TH_SCHED_STATE) != TH_SUSP)
			panic("thread_halt");
		thread->state |= TH_RUN | TH_UNINT;
		thread_setrun(thread, FALSE);

		/*
		 *	Continue loop and wait for thread to stop.
		 */
	}
}

static void __attribute__((noreturn)) walking_zombie(void)
{
	panic("the zombie walks!");
}

/*
 *	Thread calls this routine on exit from the kernel when it
 *	notices a halt request.
 */
void	thread_halt_self(continuation_t continuation)
{
	thread_t	thread = current_thread();
	spl_t	s;

	if (thread->ast & AST_TERMINATE) {
		/*
		 *	Thread is terminating itself.  Shut
		 *	down IPC, then queue it up for the
		 *	reaper thread.
		 */
		ipc_thread_terminate(thread);

		thread_hold(thread);

		s = splsched();
		simple_lock(&reaper_lock);
		enqueue_tail(&reaper_queue, &(thread->links));
		simple_unlock(&reaper_lock);

		thread_lock(thread);
		thread->state |= TH_HALTED;
		thread_unlock(thread);
		(void) splx(s);

		thread_wakeup((event_t)&reaper_queue);
		counter(c_thread_halt_self_block++);
		thread_block(walking_zombie);
		/*NOTREACHED*/
	} else {
		/*
		 *	Thread was asked to halt - show that it
		 *	has done so.
		 */
		s = splsched();
		thread_lock(thread);
		thread->state |= TH_HALTED;
		thread_ast_clear(thread, AST_HALT);
		thread_unlock(thread);
		splx(s);
		counter(c_thread_halt_self_block++);
		thread_block(continuation);
		/*
		 *	thread_release resets TH_HALTED.
		 */
	}
}

/*
 *	thread_hold:
 *
 *	Suspend execution of the specified thread.
 *	This is a recursive-style suspension of the thread, a count of
 *	suspends is maintained.
 */
void thread_hold(
	thread_t	thread)
{
	spl_t			s;

	s = splsched();
	thread_lock(thread);
	thread->suspend_count++;
	thread->state |= TH_SUSP;
	thread_unlock(thread);
	(void) splx(s);
}

/*
 *	thread_dowait:
 *
 *	Wait for a thread to actually enter stopped state.
 *
 *	must_halt argument indicates if this may fail on interruption.
 *	This is FALSE only if called from thread_abort via thread_halt.
 */
kern_return_t
thread_dowait(
	thread_t		thread,
	boolean_t		must_halt)
{
	boolean_t		need_wakeup;
	kern_return_t		ret = KERN_SUCCESS;
	spl_t			s;

	if (thread == current_thread())
		panic("thread_dowait");

	/*
	 *	If a thread is not interruptible, it may not be suspended
	 *	until it becomes interruptible.  In this case, we wait for
	 *	the thread to stop itself, and indicate that we are waiting
	 *	for it to stop so that it can wake us up when it does stop.
	 *
	 *	If the thread is interruptible, we may be able to suspend
	 *	it immediately.  There are several cases:
	 *
	 *	1) The thread is already stopped (trivial)
	 *	2) The thread is runnable (marked RUN and on a run queue).
	 *	   We pull it off the run queue and mark it stopped.
	 *	3) The thread is running.  We wait for it to stop.
	 */

	need_wakeup = FALSE;
	s = splsched();
	thread_lock(thread);

	for (;;) {
	    switch (thread->state & TH_SCHED_STATE) {
		case			TH_SUSP:
		case	      TH_WAIT | TH_SUSP:
		    /*
		     *	Thread is already suspended, or sleeping in an
		     *	interruptible wait.  We win!
		     */
		    break;

		case TH_RUN	      | TH_SUSP:
		    /*
		     *	The thread is interruptible.  If we can pull
		     *	it off a runq, stop it here.
		     */
		    if (rem_runq(thread) != RUN_QUEUE_NULL) {
			thread->state &= ~TH_RUN;
			need_wakeup = thread->wake_active;
			thread->wake_active = FALSE;
			break;
		    }
#if	NCPUS > 1
		    /*
		     *	The thread must be running, so make its
		     *	processor execute ast_check().  This
		     *	should cause the thread to take an ast and
		     *	context switch to suspend for us.
		     */
		    cause_ast_check(thread->last_processor);
#endif	/* NCPUS > 1 */

		    /*
		     *	Fall through to wait for thread to stop.
		     */

		case TH_RUN	      | TH_SUSP | TH_UNINT:
		case TH_RUN | TH_WAIT | TH_SUSP:
		case TH_RUN | TH_WAIT | TH_SUSP | TH_UNINT:
		case	      TH_WAIT | TH_SUSP | TH_UNINT:
		    /*
		     *	Wait for the thread to stop, or sleep interruptibly
		     *	(thread_block will stop it in the latter case).
		     *	Check for failure if interrupted.
		     */
		    thread->wake_active = TRUE;
		    thread_sleep(TH_EV_WAKE_ACTIVE(thread),
				simple_lock_addr(thread->lock), TRUE);
		    thread_lock(thread);
		    if ((current_thread()->wait_result != THREAD_AWAKENED) &&
			    !must_halt) {
			ret = KERN_FAILURE;
			break;
		    }

		    /*
		     *	Repeat loop to check thread`s state.
		     */
		    continue;
	    }
	    /*
	     *	Thread is stopped at this point.
	     */
	    break;
	}

	thread_unlock(thread);
	(void) splx(s);

	if (need_wakeup)
	    thread_wakeup(TH_EV_WAKE_ACTIVE(thread));

	return ret;
}

void thread_release(
	thread_t	thread)
{
	spl_t			s;

	s = splsched();
	thread_lock(thread);
	if (--thread->suspend_count == 0) {
		thread->state &= ~(TH_SUSP | TH_HALTED);
		if ((thread->state & (TH_WAIT | TH_RUN)) == 0) {
			/* was only suspended */
			thread->state |= TH_RUN;
			thread_setrun(thread, TRUE);
		}
	}
	thread_unlock(thread);
	(void) splx(s);
}

kern_return_t thread_suspend(
	thread_t	thread)
{
	boolean_t		hold;
	spl_t			spl;

	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;

	hold = FALSE;
	spl = splsched();
	thread_lock(thread);
	/* Wait for thread to get interruptible */
	while (thread->state & TH_UNINT) {
		assert_wait(TH_EV_STATE(thread), TRUE);
		thread_unlock(thread);
		thread_block(thread_no_continuation);
		thread_lock(thread);
	}
	if (thread->user_stop_count++ == 0) {
		hold = TRUE;
		thread->suspend_count++;
		thread->state |= TH_SUSP;
	}
	thread_unlock(thread);
	(void) splx(spl);

	/*
	 *	Now  wait for the thread if necessary.
	 */
	if (hold) {
		if (thread == current_thread()) {
			/*
			 *	We want to call thread_block on our way out,
			 *	to stop running.
			 */
			spl = splsched();
			ast_on(cpu_number(), AST_BLOCK);
			(void) splx(spl);
		} else
			(void) thread_dowait(thread, TRUE);
	}
	return KERN_SUCCESS;
}


kern_return_t thread_resume(
	thread_t	thread)
{
	kern_return_t		ret;
	spl_t			s;

	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;

	ret = KERN_SUCCESS;

	s = splsched();
	thread_lock(thread);
	if (thread->user_stop_count > 0) {
	    if (--thread->user_stop_count == 0) {
		if (--thread->suspend_count == 0) {
		    thread->state &= ~(TH_SUSP | TH_HALTED);
		    if ((thread->state & (TH_WAIT | TH_RUN)) == 0) {
			    /* was only suspended */
			    thread->state |= TH_RUN;
			    thread_setrun(thread, TRUE);
		    }
		}
	    }
	}
	else {
		ret = KERN_FAILURE;
	}

	thread_unlock(thread);
	(void) splx(s);

	return ret;
}

/*
 *	Return thread's machine-dependent state.
 */
kern_return_t thread_get_state(
	thread_t		thread,
	int			flavor,
	thread_state_t		old_state,	/* pointer to OUT array */
	natural_t		*old_state_count)	/*IN/OUT*/
{
	kern_return_t		ret;

#if defined(__i386__) || defined(__x86_64__)
	if (flavor == i386_DEBUG_STATE && thread == current_thread())
		/* This state can be obtained directly for the curren thread.  */
		return thread_getstatus(thread, flavor, old_state, old_state_count);
#endif

	if (thread == THREAD_NULL || thread == current_thread())
		return KERN_INVALID_ARGUMENT;

	thread_hold(thread);
	(void) thread_dowait(thread, TRUE);

	ret = thread_getstatus(thread, flavor, old_state, old_state_count);

	thread_release(thread);
	return ret;
}

/*
 *	Change thread's machine-dependent state.
 */
kern_return_t thread_set_state(
	thread_t		thread,
	int			flavor,
	thread_state_t		new_state,
	natural_t		new_state_count)
{
	kern_return_t		ret;

#if defined(__i386__) || defined(__x86_64__)
	if (flavor == i386_DEBUG_STATE && thread == current_thread())
		/* This state can be set directly for the curren thread.  */
		return thread_setstatus(thread, flavor, new_state, new_state_count);
	if (flavor == i386_FSGS_BASE_STATE && thread == current_thread())
		/* This state can be set directly for the curren thread.  */
		return thread_setstatus(thread, flavor, new_state, new_state_count);
#endif

	if (thread == THREAD_NULL || thread == current_thread())
		return KERN_INVALID_ARGUMENT;

	thread_hold(thread);
	(void) thread_dowait(thread, TRUE);

	ret = thread_setstatus(thread, flavor, new_state, new_state_count);

	thread_release(thread);
	return ret;
}

kern_return_t thread_info(
	thread_t		thread,
	int			flavor,
	thread_info_t		thread_info_out,    /* pointer to OUT array */
	natural_t		*thread_info_count) /*IN/OUT*/
{
	int			state, flags;
	spl_t			s;

	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;

	if (flavor == THREAD_BASIC_INFO) {
	    thread_basic_info_t	basic_info;

	    /* Allow *thread_info_count to be smaller than the provided amount
	     * that does not contain the new time_value64_t fields as some
	     * callers might not know about them yet. */

	    if (*thread_info_count <
			    THREAD_BASIC_INFO_COUNT - 3 * sizeof(time_value64_t)/sizeof(natural_t))
		return KERN_INVALID_ARGUMENT;

	    basic_info = (thread_basic_info_t) thread_info_out;

	    s = splsched();
	    thread_lock(thread);

	    /*
	     *	Update lazy-evaluated scheduler info because someone wants it.
	     */
	    if ((thread->state & TH_RUN) == 0 &&
		thread->sched_stamp != sched_tick)
		    update_priority(thread);

	    /* fill in info */

	    time_value64_t user_time, system_time;
	    thread_read_times(thread, &user_time, &system_time);
	    TIME_VALUE64_TO_TIME_VALUE(&user_time, &basic_info->user_time);
	    TIME_VALUE64_TO_TIME_VALUE(&system_time, &basic_info->system_time);

	    basic_info->base_priority	= thread->priority;
	    basic_info->cur_priority	= thread->sched_pri;
	    time_value64_t creation_time;
	    read_time_stamp(&thread->creation_time, &creation_time);
	    TIME_VALUE64_TO_TIME_VALUE(&creation_time, &basic_info->creation_time);

	    if (*thread_info_count == THREAD_BASIC_INFO_COUNT) {
		/* Copy new time_value64_t fields */
		basic_info->user_time64 = user_time;
		basic_info->system_time64 = user_time;
		basic_info->creation_time64 = creation_time;
	    }

	    /*
	     *	To calculate cpu_usage, first correct for timer rate,
	     *	then for 5/8 ageing.  The correction factor [3/5] is
	     *	(1/(5/8) - 1).
	     */
	    basic_info->cpu_usage = thread->cpu_usage /
					(TIMER_RATE/TH_USAGE_SCALE);
	    basic_info->cpu_usage = (basic_info->cpu_usage * 3) / 5;

	    flags = 0;
	    if (thread->state & TH_SWAPPED)
		flags |= TH_FLAGS_SWAPPED;
	    if (thread->state & TH_IDLE)
		flags |= TH_FLAGS_IDLE;

	    if (thread->state & TH_HALTED)
		state = TH_STATE_HALTED;
	    else
	    if (thread->state & TH_RUN)
		state = TH_STATE_RUNNING;
	    else
	    if (thread->state & TH_UNINT)
		state = TH_STATE_UNINTERRUPTIBLE;
	    else
	    if (thread->state & TH_SUSP)
		state = TH_STATE_STOPPED;
	    else
	    if (thread->state & TH_WAIT)
		state = TH_STATE_WAITING;
	    else
		state = 0;		/* ? */

	    basic_info->run_state = state;
	    basic_info->flags = flags;
	    basic_info->suspend_count = thread->user_stop_count;
	    if (state == TH_STATE_RUNNING)
		basic_info->sleep_time = 0;
	    else
		basic_info->sleep_time = sched_tick - thread->sched_stamp;

	    thread_unlock(thread);
	    splx(s);

	    if (*thread_info_count > THREAD_BASIC_INFO_COUNT)
	      *thread_info_count = THREAD_BASIC_INFO_COUNT;
	    return KERN_SUCCESS;
	}
	else if (flavor == THREAD_SCHED_INFO) {
	    thread_sched_info_t	sched_info;

	    /* Allow *thread_info_count to be one smaller than the
	       usual amount, because last_processor is a
	       new member that some callers might not know about. */
	    if (*thread_info_count < THREAD_SCHED_INFO_COUNT -1)
		    return KERN_INVALID_ARGUMENT;

	    sched_info = (thread_sched_info_t) thread_info_out;

	    s = splsched();
	    thread_lock(thread);

#if	MACH_FIXPRI
	    sched_info->policy = thread->policy;
	    if (thread->policy == POLICY_FIXEDPRI)
		sched_info->data = (thread->sched_data * tick)/1000;
	    else
		sched_info->data = 0;

#else	/* MACH_FIXPRI */
	    sched_info->policy = POLICY_TIMESHARE;
	    sched_info->data = 0;
#endif	/* MACH_FIXPRI */

	    sched_info->base_priority = thread->priority;
	    sched_info->max_priority = thread->max_priority;
	    sched_info->cur_priority = thread->sched_pri;

	    sched_info->depressed = (thread->depress_priority >= 0);
	    sched_info->depress_priority = thread->depress_priority;

#if NCPUS > 1
	    if (thread->last_processor)
		sched_info->last_processor = thread->last_processor->slot_num;
	    else
#endif
		sched_info->last_processor = 0;

	    thread_unlock(thread);
	    splx(s);

	    *thread_info_count = THREAD_SCHED_INFO_COUNT;
	    return KERN_SUCCESS;
	}

	return KERN_INVALID_ARGUMENT;
}

kern_return_t	thread_abort(
	thread_t	thread)
{
	if (thread == THREAD_NULL || thread == current_thread()) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *
	 *	clear it of an event wait
	 */

	evc_notify_abort(thread);

	/*
	 *	Try to force the thread to a clean point
	 *	If the halt operation fails return KERN_ABORTED.
	 *	ipc code will convert this to an ipc interrupted error code.
	 */
	if (thread_halt(thread, FALSE) != KERN_SUCCESS)
		return KERN_ABORTED;

	/*
	 *	If the thread was in an exception, abort that too.
	 */
	mach_msg_abort_rpc(thread);

	/*
	 *	Then set it going again.
	 */
	thread_release(thread);

	/*
	 *	Also abort any depression.
	 */
	if (thread->depress_priority != -1)
		thread_depress_abort(thread);

	return KERN_SUCCESS;
}

/*
 *	thread_start:
 *
 *	Start a thread at the specified routine.
 *	The thread must	be in a swapped state.
 */

void
thread_start(
	thread_t	thread,
	continuation_t	start)
{
	thread->swap_func = start;
}

/*
 *	kernel_thread:
 *
 *	Start up a kernel thread in the specified task.
 */

thread_t kernel_thread(
	task_t		task,
	const char *	name,
	continuation_t	start,
	void *		arg)
{
	kern_return_t	kr;
	thread_t	thread;

	kr = thread_create(task, &thread);
	if (kr != KERN_SUCCESS)
		return THREAD_NULL;

	/* release "extra" ref that thread_create gave us */
	thread_deallocate(thread);
	thread_start(thread, start);
	thread->ith_other = arg;

	/*
	 *	We ensure that the kernel thread starts with a stack.
	 *	The swapin mechanism might not be operational yet.
	 */
	thread_doswapin(thread);
	thread->max_priority = BASEPRI_SYSTEM;
	thread->priority = BASEPRI_SYSTEM;
	thread->sched_pri = BASEPRI_SYSTEM;
	(void) thread_resume(thread);
	return thread;
}

/*
 *	reaper_thread:
 *
 *	This kernel thread runs forever looking for threads to destroy
 *	(when they request that they be destroyed, of course).
 */
static void __attribute__((noreturn)) reaper_thread_continue(void)
{
	for (;;) {
		thread_t thread;
		spl_t s;

		s = splsched();
		simple_lock(&reaper_lock);

		while ((thread = (thread_t) dequeue_head(&reaper_queue))
							!= THREAD_NULL) {
			simple_unlock(&reaper_lock);
			(void) splx(s);

			(void) thread_dowait(thread, TRUE);	/* may block */
			thread_deallocate(thread);		/* may block */

			s = splsched();
			simple_lock(&reaper_lock);
		}

		assert_wait((event_t) &reaper_queue, FALSE);
		simple_unlock(&reaper_lock);
		(void) splx(s);
		counter(c_reaper_thread_block++);
		thread_block(reaper_thread_continue);
	}
}

void reaper_thread(void)
{
	reaper_thread_continue();
	/*NOTREACHED*/
}

#if	MACH_HOST
/*
 *	thread_assign:
 *
 *	Change processor set assignment.
 *	Caller must hold an extra reference to the thread (if this is
 *	called directly from the ipc interface, this is an operation
 *	in progress reference).  Caller must hold no locks -- this may block.
 */

kern_return_t
thread_assign(thread_t thread,
	      processor_set_t new_pset)
{
	if (thread == THREAD_NULL || new_pset == PROCESSOR_SET_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	thread_freeze(thread);
	thread_doassign(thread, new_pset, TRUE);

	return KERN_SUCCESS;
}

/*
 *	thread_freeze:
 *
 *	Freeze thread's assignment.  Prelude to assigning thread.
 *	Only one freeze may be held per thread.  
 */
void
thread_freeze(thread_t thread)
{
	spl_t	s;
	/*
	 *	Freeze the assignment, deferring to a prior freeze.
	 */
	s = splsched();
	thread_lock(thread);
	while (thread->may_assign == FALSE) {
		thread->assign_active = TRUE;
		thread_sleep((event_t) &thread->assign_active,
			simple_lock_addr(thread->lock), FALSE);
		thread_lock(thread);
	}
	thread->may_assign = FALSE;
	thread_unlock(thread);
	(void) splx(s);
}

/*
 *	thread_unfreeze: release freeze on thread's assignment.
 */
void
thread_unfreeze(
	thread_t	thread)
{
	spl_t 	s;

	s = splsched();
	thread_lock(thread);
	thread->may_assign = TRUE;
	if (thread->assign_active) {
		thread->assign_active = FALSE;
		thread_wakeup((event_t)&thread->assign_active);
	}
	thread_unlock(thread);
	splx(s);
}

/*
 *	thread_doassign:
 *
 *	Actually do thread assignment.  thread_will_assign must have been
 *	called on the thread.  release_freeze argument indicates whether
 *	to release freeze on thread.
 */

void
thread_doassign(
	thread_t			thread,
	processor_set_t			new_pset,
	boolean_t			release_freeze)
{
	processor_set_t			pset;
	boolean_t			old_empty, new_empty;
	boolean_t			recompute_pri = FALSE;
	spl_t				s;
	
	/*
	 *	Check for silly no-op.
	 */
	pset = thread->processor_set;
	if (pset == new_pset) {
		if (release_freeze)
			thread_unfreeze(thread);
		return;
	}
	/*
	 *	Suspend the thread and stop it if it's not the current thread.
	 */
	thread_hold(thread);
	if (thread != current_thread())
		(void) thread_dowait(thread, TRUE);

	/*
	 *	Lock both psets now, use ordering to avoid deadlocks.
	 */
Restart:
	if ((vm_offset_t)pset < (vm_offset_t)new_pset) {
	    pset_lock(pset);
	    pset_lock(new_pset);
	}
	else {
	    pset_lock(new_pset);
	    pset_lock(pset);
	}

	/*
	 *	Check if new_pset is ok to assign to.  If not, reassign
	 *	to default_pset.
	 */
	if (!new_pset->active) {
	    pset_unlock(pset);
	    pset_unlock(new_pset);
	    new_pset = &default_pset;
	    goto Restart;
	}

	pset_reference(new_pset);

	/*
	 *	Grab the thread lock and move the thread.
	 *	Then drop the lock on the old pset and the thread's
	 *	reference to it.
	 */
	s = splsched();
	thread_lock(thread);

	thread_change_psets(thread, pset, new_pset);

	old_empty = pset->empty;
	new_empty = new_pset->empty;

	pset_unlock(pset);

	/*
	 *	Reset policy and priorities if needed.
	 */
#if	MACH_FIXPRI
	if ((thread->policy & new_pset->policies) == 0) {
	    thread->policy = POLICY_TIMESHARE;
	    recompute_pri = TRUE;
	}
#endif	/* MACH_FIXPRI */

	if (thread->max_priority < new_pset->max_priority) {
	    thread->max_priority = new_pset->max_priority;
	    if (thread->priority < thread->max_priority) {
		thread->priority = thread->max_priority;
		recompute_pri = TRUE;
	    }
	    else {
		if ((thread->depress_priority >= 0) &&
		    (thread->depress_priority < thread->max_priority)) {
			thread->depress_priority = thread->max_priority;
		}
	    }
	}

	pset_unlock(new_pset);

	if (recompute_pri)
		compute_priority(thread, TRUE);

	if (release_freeze) {
		thread->may_assign = TRUE;
		if (thread->assign_active) {
			thread->assign_active = FALSE;
			thread_wakeup((event_t)&thread->assign_active);
		}
	}

	thread_unlock(thread);
	splx(s);

	pset_deallocate(pset);

	/*
	 *	Figure out hold status of thread.  Threads assigned to empty
	 *	psets must be held.  Therefore:
	 *		If old pset was empty release its hold.
	 *		Release our hold from above unless new pset is empty.
	 */

	if (old_empty)
		thread_release(thread);
	if (!new_empty)
		thread_release(thread);

	/*
	 *	If current_thread is assigned, context switch to force
	 *	assignment to happen.  This also causes hold to take
	 *	effect if the new pset is empty.
	 */
	if (thread == current_thread()) {
		s = splsched();
		ast_on(cpu_number(), AST_BLOCK);
		(void) splx(s);
	}
}
#else	/* MACH_HOST */
kern_return_t
thread_assign(
	thread_t	thread,
	processor_set_t	new_pset)
{
	return KERN_FAILURE;
}
#endif	/* MACH_HOST */

/*
 *	thread_assign_default:
 *
 *	Special version of thread_assign for assigning threads to default
 *	processor set.
 */
kern_return_t
thread_assign_default(
	thread_t	thread)
{
	return thread_assign(thread, &default_pset);
}

/*
 *	thread_get_assignment
 *
 *	Return current assignment for this thread.
 */	    
kern_return_t thread_get_assignment(
	thread_t	thread,
	processor_set_t	*pset)
{
	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;

	*pset = thread->processor_set;
	pset_reference(*pset);
	return KERN_SUCCESS;
}

/*
 *	thread_priority:
 *
 *	Set priority (and possibly max priority) for thread.
 */
kern_return_t
thread_priority(
	thread_t	thread,
	int		priority,
	boolean_t	set_max)
{
    spl_t		s;
    kern_return_t	ret = KERN_SUCCESS;

    if ((thread == THREAD_NULL) || invalid_pri(priority))
	return KERN_INVALID_ARGUMENT;

    s = splsched();
    thread_lock(thread);

    /*
     *	Check for violation of max priority
     */
    if (priority < thread->max_priority)
	ret = KERN_FAILURE;
    else {
	/*
	 *	Set priorities.  If a depression is in progress,
	 *	change the priority to restore.
	 */
	if (thread->depress_priority >= 0)
	    thread->depress_priority = priority;

	else {
	    thread->priority = priority;
	    compute_priority(thread, TRUE);
	}

	if (set_max)
	    thread->max_priority = priority;
    }
    thread_unlock(thread);
    (void) splx(s);

    return ret;
}

/*
 *	thread_set_own_priority:
 *
 *	Internal use only; sets the priority of the calling thread.
 *	Will adjust max_priority if necessary.
 */
void
thread_set_own_priority(
	int	priority)
{
    spl_t	s;
    thread_t	thread = current_thread();

    s = splsched();
    thread_lock(thread);

    if (priority < thread->max_priority)
	thread->max_priority = priority;
    thread->priority = priority;
    compute_priority(thread, TRUE);

    thread_unlock(thread);
    (void) splx(s);
}

/*
 *	thread_max_priority:
 *
 *	Reset the max priority for a thread.
 */
kern_return_t
thread_max_priority(
	thread_t	thread,
	processor_set_t	pset,
	int		max_priority)
{
    spl_t		s;
    kern_return_t	ret = KERN_SUCCESS;

    if ((thread == THREAD_NULL) || (pset == PROCESSOR_SET_NULL) ||
	invalid_pri(max_priority))
	    return KERN_INVALID_ARGUMENT;

    s = splsched();
    thread_lock(thread);

#if	MACH_HOST
    /*
     *	Check for wrong processor set.
     */
    if (pset != thread->processor_set)
	ret = KERN_FAILURE;

    else {
#endif	/* MACH_HOST */
	thread->max_priority = max_priority;

	/*
	 *	Reset priority if it violates new max priority
	 */
	if (max_priority > thread->priority) {
	    thread->priority = max_priority;

	    compute_priority(thread, TRUE);
	}
	else {
	    if (thread->depress_priority >= 0 &&
		max_priority > thread->depress_priority)
		    thread->depress_priority = max_priority;
	    }
#if	MACH_HOST
    }
#endif	/* MACH_HOST */

    thread_unlock(thread);
    (void) splx(s);

    return ret;
}

/*
 *	thread_policy:
 *
 *	Set scheduling policy for thread.
 */
kern_return_t
thread_policy(
	thread_t	thread,
	int		policy,
	int		data)
{
#if	MACH_FIXPRI
	kern_return_t	ret = KERN_SUCCESS;
	int		temp;
	spl_t		s;
#endif	/* MACH_FIXPRI */

	if ((thread == THREAD_NULL) || invalid_policy(policy))
		return KERN_INVALID_ARGUMENT;

#if	MACH_FIXPRI
	s = splsched();
	thread_lock(thread);

	/*
	 *	Check if changing policy.
	 */
	if (policy == thread->policy) {
	    /*
	     *	Just changing data.  This is meaningless for
	     *	timesharing, quantum for fixed priority (but
	     *	has no effect until current quantum runs out).
	     */
	    if (policy == POLICY_FIXEDPRI) {
		temp = data * 1000;
		if (temp % tick)
			temp += tick;
		thread->sched_data = temp/tick;
	    }
	}
	else {
	    /*
	     *	Changing policy.  Check if new policy is allowed.
	     */
	    if ((thread->processor_set->policies & policy) == 0)
		    ret = KERN_FAILURE;
	    else {
		/*
		 *	Changing policy.  Save data and calculate new
		 *	priority.
		 */
		thread->policy = policy;
		if (policy == POLICY_FIXEDPRI) {
			temp = data * 1000;
			if (temp % tick)
				temp += tick;
			thread->sched_data = temp/tick;
		}
		compute_priority(thread, TRUE);
	    }
	}
	thread_unlock(thread);
	(void) splx(s);

	return ret;
#else	/* MACH_FIXPRI */
	if (policy == POLICY_TIMESHARE)
		return KERN_SUCCESS;
	else
		return KERN_FAILURE;
#endif	/* MACH_FIXPRI */
}

/*
 *	thread_wire:
 *
 *	Specify that the target thread must always be able
 *	to run and to allocate memory.
 */
kern_return_t
thread_wire(
	host_t		host,
	thread_t	thread,
	boolean_t	wired)
{
	spl_t		s;

	if (host == HOST_NULL)
	    return KERN_INVALID_ARGUMENT;

	if (thread == THREAD_NULL)
	    return KERN_INVALID_ARGUMENT;

	/*
	 * This implementation only works for the current thread.
	 * See stack_privilege.
	 */
	if (thread != current_thread())
	    return KERN_INVALID_ARGUMENT;

	s = splsched();
	thread_lock(thread);

	if (wired) {
	    thread->vm_privilege = 1;
	    stack_privilege(thread);
	}
	else {
	    thread->vm_privilege = 0;
/*XXX	    stack_unprivilege(thread); */
	    thread->stack_privilege = 0;
	}

	thread_unlock(thread);
	splx(s);

	return KERN_SUCCESS;
}

/*
 *	thread_collect_scan:
 *
 *	Attempt to free resources owned by threads.
 *	pcb_collect doesn't do anything yet.
 */

static void thread_collect_scan(void)
{
	thread_t	thread, prev_thread;
	processor_set_t		pset, prev_pset;

	prev_thread = THREAD_NULL;
	prev_pset = PROCESSOR_SET_NULL;

	simple_lock(&all_psets_lock);
	queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
		pset_lock(pset);
		queue_iterate(&pset->threads, thread, thread_t, pset_threads) {
			spl_t	s = splsched();
			thread_lock(thread);

			/*
			 *	Only collect threads which are
			 *	not runnable and are swapped.
			 */

			if ((thread->state & (TH_RUN|TH_SWAPPED))
							== TH_SWAPPED) {
				thread->ref_count++;
				thread_unlock(thread);
				(void) splx(s);
				pset->ref_count++;
				pset_unlock(pset);
				simple_unlock(&all_psets_lock);

				pcb_collect(thread);

				if (prev_thread != THREAD_NULL)
					thread_deallocate(prev_thread);
				prev_thread = thread;

				if (prev_pset != PROCESSOR_SET_NULL)
					pset_deallocate(prev_pset);
				prev_pset = pset;

				simple_lock(&all_psets_lock);
				pset_lock(pset);
			} else {
				thread_unlock(thread);
				(void) splx(s);
			}
		}
		pset_unlock(pset);
	}
	simple_unlock(&all_psets_lock);

	if (prev_thread != THREAD_NULL)
		thread_deallocate(prev_thread);
	if (prev_pset != PROCESSOR_SET_NULL)
		pset_deallocate(prev_pset);
}

boolean_t thread_collect_allowed = TRUE;
unsigned thread_collect_last_tick = 0;
unsigned thread_collect_max_rate = 0;		/* in ticks */

/*
 *	consider_thread_collect:
 *
 *	Called by the pageout daemon when the system needs more free pages.
 */

void consider_thread_collect(void)
{
	/*
	 *	By default, don't attempt thread collection more frequently
	 *	than once a second.
	 */

	if (thread_collect_max_rate == 0)
		thread_collect_max_rate = hz;

	if (thread_collect_allowed &&
	    (sched_tick >
	     (thread_collect_last_tick +
	      thread_collect_max_rate / (hz / 1)))) {
		thread_collect_last_tick = sched_tick;
		thread_collect_scan();
	}
}

#if	MACH_DEBUG

static vm_size_t stack_usage(vm_offset_t stack)
{
	unsigned i;

	for (i = 0; i < KERNEL_STACK_SIZE/sizeof(unsigned int); i++)
	    if (((unsigned int *)stack)[i] != STACK_MARKER)
		break;

	return KERNEL_STACK_SIZE - i * sizeof(unsigned int);
}

/*
 *	Machine-dependent code should call stack_init
 *	before doing its own initialization of the stack.
 */

void stack_init(
	vm_offset_t stack)
{
	if (stack_check_usage) {
	    unsigned i;

	    for (i = 0; i < KERNEL_STACK_SIZE/sizeof(unsigned int); i++)
		((unsigned int *)stack)[i] = STACK_MARKER;
	}
}

/*
 *	Machine-dependent code should call stack_finalize
 *	before releasing the stack memory.
 */

void stack_finalize(
	vm_offset_t stack)
{
	if (stack_check_usage) {
	    vm_size_t used = stack_usage(stack);

	    simple_lock(&stack_usage_lock);
	    if (used > stack_max_usage)
		stack_max_usage = used;
	    simple_unlock(&stack_usage_lock);
	}
}

#ifndef	MACHINE_STACK
/*
 *	stack_statistics:
 *
 *	Return statistics on cached kernel stacks.
 *	*maxusagep must be initialized by the caller.
 */

static void stack_statistics(
	natural_t *totalp,
	vm_size_t *maxusagep)
{
	spl_t	s;

	s = splsched();
	stack_lock();
	if (stack_check_usage) {
		vm_offset_t stack;

		/*
		 *	This is pretty expensive to do at splsched,
		 *	but it only happens when someone makes
		 *	a debugging call, so it should be OK.
		 */

		for (stack = stack_free_list; stack != 0;
		     stack = stack_next(stack)) {
			vm_size_t usage = stack_usage(stack);

			if (usage > *maxusagep)
				*maxusagep = usage;
		}
	}

	*totalp = stack_free_count;
	stack_unlock();
	(void) splx(s);
}
#endif	/* MACHINE_STACK */

kern_return_t host_stack_usage(
	host_t		host,
	vm_size_t	*reservedp,
	unsigned int	*totalp,
	vm_size_t	*spacep,
	vm_size_t	*residentp,
	vm_size_t	*maxusagep,
	vm_offset_t	*maxstackp)
{
	natural_t total;
	vm_size_t maxusage;

	if (host == HOST_NULL)
		return KERN_INVALID_HOST;

	simple_lock(&stack_usage_lock);
	maxusage = stack_max_usage;
	simple_unlock(&stack_usage_lock);

	stack_statistics(&total, &maxusage);

	*reservedp = 0;
	*totalp = total;
	*spacep = *residentp = total * round_page(KERNEL_STACK_SIZE);
	*maxusagep = maxusage;
	*maxstackp = 0;
	return KERN_SUCCESS;
}

kern_return_t processor_set_stack_usage(
	processor_set_t	pset,
	unsigned int	*totalp,
	vm_size_t	*spacep,
	vm_size_t	*residentp,
	vm_size_t	*maxusagep,
	vm_offset_t	*maxstackp)
{
	unsigned int total;
	vm_size_t maxusage;
	vm_offset_t maxstack;

	thread_t *threads;
	thread_t tmp_thread;

	unsigned int actual;	/* this many things */
	unsigned int i;

	vm_size_t size, size_needed;
	vm_offset_t addr;

	if (pset == PROCESSOR_SET_NULL)
		return KERN_INVALID_ARGUMENT;

	size = 0; addr = 0;

	for (;;) {
		pset_lock(pset);
		if (!pset->active) {
			pset_unlock(pset);
			return KERN_INVALID_ARGUMENT;
		}

		actual = pset->thread_count;

		/* do we have the memory we need? */

		size_needed = actual * sizeof(thread_t);
		if (size_needed <= size)
			break;

		/* unlock the pset and allocate more memory */
		pset_unlock(pset);

		if (size != 0)
			kfree(addr, size);

		assert(size_needed > 0);
		size = size_needed;

		addr = kalloc(size);
		if (addr == 0)
			return KERN_RESOURCE_SHORTAGE;
	}

	/* OK, have memory and the processor_set is locked & active */

	threads = (thread_t *) addr;
	for (i = 0, tmp_thread = (thread_t) queue_first(&pset->threads);
	     i < actual;
	     i++,
	     tmp_thread = (thread_t) queue_next(&tmp_thread->pset_threads)) {
		thread_reference(tmp_thread);
		threads[i] = tmp_thread;
	}
	assert(queue_end(&pset->threads, (queue_entry_t) tmp_thread));

	/* can unlock processor set now that we have the thread refs */
	pset_unlock(pset);

	/* calculate maxusage and free thread references */

	total = 0;
	maxusage = 0;
	maxstack = 0;
	for (i = 0; i < actual; i++) {
		thread_t thread = threads[i];
		vm_offset_t stack = 0;

		/*
		 *	thread->kernel_stack is only accurate if the
		 *	thread isn't swapped and is not executing.
		 *
		 *	Of course, we don't have the appropriate locks
		 *	for these shenanigans.
		 */

		if ((thread->state & TH_SWAPPED) == 0) {
			int cpu;

			stack = thread->kernel_stack;

			for (cpu = 0; cpu < smp_get_numcpus(); cpu++)
				if (percpu_array[cpu].active_thread == thread) {
					stack = percpu_array[cpu].active_stack;
					break;
				}
		}

		if (stack != 0) {
			total++;

			if (stack_check_usage) {
				vm_size_t usage = stack_usage(stack);

				if (usage > maxusage) {
					maxusage = usage;
					maxstack = (vm_offset_t) thread;
				}
			}
		}

		thread_deallocate(thread);
	}

	if (size != 0)
		kfree(addr, size);

	*totalp = total;
	*residentp = *spacep = total * round_page(KERNEL_STACK_SIZE);
	*maxusagep = maxusage;
	*maxstackp = maxstack;
	return KERN_SUCCESS;
}

/*
 *	Useful in the debugger:
 */
void
thread_stats(void)
{
	thread_t thread;
	int total = 0, rpcreply = 0;

	queue_iterate(&default_pset.threads, thread, thread_t, pset_threads) {
		total++;
		if (thread->ith_rpc_reply != IP_NULL)
			rpcreply++;
	}

	printf("%d total threads.\n", total);
	printf("%d using rpc_reply.\n", rpcreply);
}
#endif	/* MACH_DEBUG */

/*
 *	thread_set_name
 *
 *	Set the name of thread THREAD to NAME.
 */
kern_return_t
thread_set_name(
	thread_t	thread,
	const_kernel_debug_name_t	name)
{
	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;

	strncpy(thread->name, name, sizeof thread->name - 1);
	thread->name[sizeof thread->name - 1] = '\0';
	return KERN_SUCCESS;
}

/*
 *  thread_get_name
 *
 *  Return the name of the thread THREAD.
 *  Will use the name of the thread as set by thread_set_name.
 *  If thread_set_name was not used, this will return the name of the task
 *  copied when the thread was created.
 */
kern_return_t
thread_get_name(
		thread_t	thread,
		kernel_debug_name_t	name)
{
	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;

	strncpy(name, thread->name, sizeof thread->name);

	return KERN_SUCCESS;
}

/*
 * thread_get_unique_id
 *
 * Get unique identifier for thread.
 */
unsigned int thread_get_unique_id(thread_t thread)
{
    static unsigned int next_thread_id = 1;
    static simple_lock_t thread_id_lock;
    static boolean_t initialized = FALSE;
    
    if (!initialized) {
        simple_lock_init(&thread_id_lock);
        initialized = TRUE;
    }
    
    if (thread == THREAD_NULL)
        return 0;
    
    if (thread->thread_id == 0) {
        simple_lock(&thread_id_lock);
        thread->thread_id = next_thread_id++;
        simple_unlock(&thread_id_lock);
    }
    
    return thread->thread_id;
}

/*
 * thread_get_cpu_usage_percent
 *
 * Calculate CPU usage percentage for thread.
 */
unsigned int thread_get_cpu_usage_percent(thread_t thread)
{
    struct time_value64 now, diff;
    unsigned long long total_time_ns, cpu_time_ns;
    unsigned int percent;
    
    if (thread == THREAD_NULL)
        return 0;
    
    read_time_stamp(current_time(), &now);
    diff = time_value64_subtract(now, thread->creation_time);
    total_time_ns = time_value64_to_nanoseconds(diff);
    
    cpu_time_ns = time_value64_to_nanoseconds(thread->user_time) +
                  time_value64_to_nanoseconds(thread->system_time);
    
    if (total_time_ns > 0) {
        percent = (unsigned int)((cpu_time_ns * 1000ULL) / total_time_ns);
        if (percent > 1000) percent = 1000;
    } else {
        percent = 0;
    }
    
    return percent;
}

/*
 * thread_set_numa_preference
 *
 * Set NUMA node preference for thread.
 */
kern_return_t thread_set_numa_preference(
    thread_t        thread,
    unsigned int    preferred_node,
    unsigned int    node_mask)
{
    if (thread == THREAD_NULL)
        return KERN_INVALID_ARGUMENT;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    thread->numa_preferred_node = preferred_node;
    thread->numa_mask = node_mask;
    
    thread_unlock(thread);
    splx(s);
    
    return KERN_SUCCESS;
}

/*
 * thread_get_numa_stats
 *
 * Get NUMA statistics for thread.
 */
void thread_get_numa_stats(
    thread_t        thread,
    unsigned int    *preferred_node,
    unsigned int    *current_node,
    unsigned int    *node_mask)
{
    if (thread == THREAD_NULL)
        return;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    if (preferred_node != NULL)
        *preferred_node = thread->numa_preferred_node;
    if (current_node != NULL)
        *current_node = thread->cpu_id / MAX_CPUS_PER_NODE;
    if (node_mask != NULL)
        *node_mask = thread->numa_mask;
    
    thread_unlock(thread);
    splx(s);
}

/*
 * thread_set_cgroup_params
 *
 * Set cgroup parameters for thread.
 */
kern_return_t thread_set_cgroup_params(
    thread_t        thread,
    unsigned int    cgroup_id,
    unsigned int    cpu_share,
    unsigned int    mem_limit,
    unsigned int    io_weight)
{
    if (thread == THREAD_NULL)
        return KERN_INVALID_ARGUMENT;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    thread->cgroup_id = cgroup_id;
    thread->cgroup_cpu_share = cpu_share;
    thread->cgroup_mem_limit = mem_limit;
    thread->cgroup_io_weight = io_weight;
    
    thread_unlock(thread);
    splx(s);
    
    return KERN_SUCCESS;
}

/*
 * thread_update_cgroup_stats
 *
 * Update cgroup statistics for thread.
 */
void thread_update_cgroup_stats(
    thread_t        thread,
    unsigned int    cpu_usage,
    unsigned int    mem_usage)
{
    if (thread == THREAD_NULL)
        return;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    thread->cpu_usage_percent = cpu_usage;
    thread->mem_usage_percent = mem_usage;
    
    thread_unlock(thread);
    splx(s);
}

/*
 * thread_set_seccomp_filter
 *
 * Set seccomp filter for thread security.
 */
kern_return_t thread_set_seccomp_filter(
    thread_t        thread,
    unsigned int    mode,
    void            *filter)
{
    if (thread == THREAD_NULL)
        return KERN_INVALID_ARGUMENT;
    
    if (mode > 2) /* 0=disabled, 1=strict, 2=filter */
        return KERN_INVALID_ARGUMENT;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    thread->seccomp_mode = mode;
    thread->seccomp_filter = filter;
    
    thread_unlock(thread);
    splx(s);
    
    return KERN_SUCCESS;
}

/*
 * thread_check_seccomp
 *
 * Check if syscall is allowed by seccomp filter.
 */
boolean_t thread_check_seccomp(thread_t thread, unsigned int syscall_nr)
{
    boolean_t allowed = TRUE;
    
    if (thread == THREAD_NULL)
        return TRUE;
    
    if (thread->seccomp_mode == 0)
        return TRUE;
    
    if (thread->seccomp_mode == 1) {
        /* Strict mode: only read, write, exit, sigreturn */
        allowed = (syscall_nr == SYS_read || syscall_nr == SYS_write ||
                   syscall_nr == SYS_exit || syscall_nr == SYS_rt_sigreturn);
    }
    /* Filter mode would check the BPF filter */
    
    return allowed;
}

/*
 * thread_set_capabilities
 *
 * Set Linux capabilities for thread.
 */
kern_return_t thread_set_capabilities(
    thread_t        thread,
    unsigned int    cap_inheritable,
    unsigned int    cap_permitted,
    unsigned int    cap_effective,
    unsigned int    cap_bounding)
{
    if (thread == THREAD_NULL)
        return KERN_INVALID_ARGUMENT;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    thread->capabilities[0] = cap_inheritable;
    thread->capabilities[1] = cap_permitted;
    thread->capabilities[2] = cap_effective;
    thread->capabilities[3] = cap_bounding;
    
    thread_unlock(thread);
    splx(s);
    
    return KERN_SUCCESS;
}

/*
 * thread_has_capability
 *
 * Check if thread has specific capability.
 */
boolean_t thread_has_capability(thread_t thread, unsigned int cap)
{
    boolean_t has_cap;
    
    if (thread == THREAD_NULL)
        return FALSE;
    
    spl_t s = splsched();
    thread_lock(thread);
    has_cap = (thread->capabilities[2] & (1 << cap)) != 0;
    thread_unlock(thread);
    splx(s);
    
    return has_cap;
}

/*
 * thread_set_io_stats
 *
 * Update I/O statistics for thread.
 */
void thread_set_io_stats(
    thread_t            thread,
    unsigned long long  read_bytes,
    unsigned long long  write_bytes,
    unsigned int        read_ops,
    unsigned int        write_ops)
{
    if (thread == THREAD_NULL)
        return;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    thread->io_read_bytes += read_bytes;
    thread->io_write_bytes += write_bytes;
    thread->io_read_ops += read_ops;
    thread->io_write_ops += write_ops;
    
    thread_unlock(thread);
    splx(s);
}

/*
 * thread_get_io_stats
 *
 * Get I/O statistics for thread.
 */
void thread_get_io_stats(
    thread_t            thread,
    unsigned long long  *read_bytes,
    unsigned long long  *write_bytes,
    unsigned int        *read_ops,
    unsigned int        *write_ops)
{
    if (thread == THREAD_NULL)
        return;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    if (read_bytes != NULL)
        *read_bytes = thread->io_read_bytes;
    if (write_bytes != NULL)
        *write_bytes = thread->io_write_bytes;
    if (read_ops != NULL)
        *read_ops = thread->io_read_ops;
    if (write_ops != NULL)
        *write_ops = thread->io_write_ops;
    
    thread_unlock(thread);
    splx(s);
}

/*
 * thread_set_scheduling_parameters
 *
 * Set real-time scheduling parameters.
 */
kern_return_t thread_set_scheduling_parameters(
    thread_t        thread,
    unsigned int    policy,
    unsigned int    priority,
    unsigned int    runtime_ns,
    unsigned int    period_ns,
    unsigned int    deadline_ns)
{
    if (thread == THREAD_NULL)
        return KERN_INVALID_ARGUMENT;
    
    if (priority > 99)
        return KERN_INVALID_ARGUMENT;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    thread->sched_policy = policy;
    thread->sched_priority = priority;
    thread->sched_runtime_ns = runtime_ns;
    thread->sched_period_ns = period_ns;
    thread->sched_deadline_ns = deadline_ns;
    
    /* Update Mach priority based on RT priority */
    if (policy == SCHED_RR || policy == SCHED_FIFO) {
        int mach_prio = 80 + (priority * 47 / 100);
        if (mach_prio > MAXPRI_USER)
            mach_prio = MAXPRI_USER;
        thread->priority = mach_prio;
        compute_priority(thread, TRUE);
    }
    
    thread_unlock(thread);
    splx(s);
    
    return KERN_SUCCESS;
}

/*
 * thread_get_scheduling_parameters
 *
 * Get scheduling parameters for thread.
 */
void thread_get_scheduling_parameters(
    thread_t        thread,
    unsigned int    *policy,
    unsigned int    *priority,
    unsigned int    *runtime_ns,
    unsigned int    *period_ns,
    unsigned int    *deadline_ns)
{
    if (thread == THREAD_NULL)
        return;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    if (policy != NULL)
        *policy = thread->sched_policy;
    if (priority != NULL)
        *priority = thread->sched_priority;
    if (runtime_ns != NULL)
        *runtime_ns = thread->sched_runtime_ns;
    if (period_ns != NULL)
        *period_ns = thread->sched_period_ns;
    if (deadline_ns != NULL)
        *deadline_ns = thread->sched_deadline_ns;
    
    thread_unlock(thread);
    splx(s);
}

/*
 * thread_add_trace_point
 *
 * Add trace point to thread's trace buffer.
 */
void thread_add_trace_point(thread_t thread, unsigned long long trace_data)
{
    if (thread == THREAD_NULL)
        return;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    thread->trace_data[thread->trace_index % 256] = trace_data;
    thread->trace_index++;
    
    thread_unlock(thread);
    splx(s);
}

/*
 * thread_get_trace_buffer
 *
 * Get trace buffer from thread.
 */
unsigned int thread_get_trace_buffer(
    thread_t            thread,
    unsigned long long  *buffer,
    unsigned int        max_entries)
{
    unsigned int i, count;
    
    if (thread == THREAD_NULL || buffer == NULL || max_entries == 0)
        return 0;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    count = (thread->trace_index > max_entries) ? max_entries : thread->trace_index;
    
    for (i = 0; i < count; i++) {
        buffer[i] = thread->trace_data[i];
    }
    
    thread_unlock(thread);
    splx(s);
    
    return count;
}

/*
 * thread_set_oom_score
 *
 * Set OOM (Out-Of-Memory) score for thread.
 */
void thread_set_oom_score(thread_t thread, unsigned int score, int adjustment)
{
    if (thread == THREAD_NULL)
        return;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    thread->oom_score = score;
    thread->oom_score_adj = adjustment;
    
    thread_unlock(thread);
    splx(s);
}

/*
 * thread_set_namespace
 *
 * Set namespace for thread.
 */
kern_return_t thread_set_namespace(
    thread_t        thread,
    unsigned int    ns_type,
    unsigned int    ns_id)
{
    if (thread == THREAD_NULL)
        return KERN_INVALID_ARGUMENT;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    switch (ns_type) {
        case NS_TYPE_UTS:
            thread->ns_uts = ns_id;
            break;
        case NS_TYPE_IPC:
            thread->ns_ipc = ns_id;
            break;
        case NS_TYPE_NET:
            thread->ns_net = ns_id;
            break;
        case NS_TYPE_PID:
            thread->ns_pid = ns_id;
            break;
        case NS_TYPE_MNT:
            thread->ns_mnt = ns_id;
            break;
        case NS_TYPE_USER:
            thread->ns_user = ns_id;
            break;
        default:
            thread_unlock(thread);
            splx(s);
            return KERN_INVALID_ARGUMENT;
    }
    
    thread->namespace_flags |= (1 << ns_type);
    
    thread_unlock(thread);
    splx(s);
    
    return KERN_SUCCESS;
}

/*
 * thread_get_namespace
 *
 * Get namespace ID for thread.
 */
unsigned int thread_get_namespace(thread_t thread, unsigned int ns_type)
{
    unsigned int ns_id = 0;
    
    if (thread == THREAD_NULL)
        return 0;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    switch (ns_type) {
        case NS_TYPE_UTS:
            ns_id = thread->ns_uts;
            break;
        case NS_TYPE_IPC:
            ns_id = thread->ns_ipc;
            break;
        case NS_TYPE_NET:
            ns_id = thread->ns_net;
            break;
        case NS_TYPE_PID:
            ns_id = thread->ns_pid;
            break;
        case NS_TYPE_MNT:
            ns_id = thread->ns_mnt;
            break;
        case NS_TYPE_USER:
            ns_id = thread->ns_user;
            break;
    }
    
    thread_unlock(thread);
    splx(s);
    
    return ns_id;
}

/*
 * thread_set_debug_registers
 *
 * Set debug registers for hardware breakpoints.
 */
kern_return_t thread_set_debug_registers(
    thread_t        thread,
    unsigned int    dr0,
    unsigned int    dr1,
    unsigned int    dr2,
    unsigned int    dr3,
    unsigned int    dr6,
    unsigned int    dr7)
{
    if (thread == THREAD_NULL)
        return KERN_INVALID_ARGUMENT;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    thread->debug_regs[0] = dr0;
    thread->debug_regs[1] = dr1;
    thread->debug_regs[2] = dr2;
    thread->debug_regs[3] = dr3;
    thread->debug_regs[4] = dr6;
    thread->debug_regs[5] = dr7;
    
    thread_unlock(thread);
    splx(s);
    
    return KERN_SUCCESS;
}

/*
 * thread_get_debug_registers
 *
 * Get debug registers from thread.
 */
void thread_get_debug_registers(
    thread_t        thread,
    unsigned int    *dr0,
    unsigned int    *dr1,
    unsigned int    *dr2,
    unsigned int    *dr3,
    unsigned int    *dr6,
    unsigned int    *dr7)
{
    if (thread == THREAD_NULL)
        return;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    if (dr0 != NULL) *dr0 = thread->debug_regs[0];
    if (dr1 != NULL) *dr1 = thread->debug_regs[1];
    if (dr2 != NULL) *dr2 = thread->debug_regs[2];
    if (dr3 != NULL) *dr3 = thread->debug_regs[3];
    if (dr6 != NULL) *dr6 = thread->debug_regs[4];
    if (dr7 != NULL) *dr7 = thread->debug_regs[5];
    
    thread_unlock(thread);
    splx(s);
}

/*
 * thread_set_vdso_mapping
 *
 * Set vDSO mapping for fast syscalls.
 */
kern_return_t thread_set_vdso_mapping(
    thread_t        thread,
    unsigned int    vdso_base,
    unsigned int    vvar_base,
    unsigned int    vvar_seq)
{
    if (thread == THREAD_NULL)
        return KERN_INVALID_ARGUMENT;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    thread->vdso_base = vdso_base;
    thread->vvar_base = vvar_base;
    thread->vvar_seq = vvar_seq;
    
    thread_unlock(thread);
    splx(s);
    
    return KERN_SUCCESS;
}

/*
 * thread_increment_vvar_sequence
 *
 * Increment vVAR sequence counter for time updates.
 */
void thread_increment_vvar_sequence(thread_t thread)
{
    if (thread == THREAD_NULL)
        return;
    
    spl_t s = splsched();
    thread_lock(thread);
    thread->vvar_seq++;
    thread_unlock(thread);
    splx(s);
}

/*
 * thread_set_command_line
 *
 * Set command line for thread (for debugging).
 */
kern_return_t thread_set_command_line(
    thread_t        thread,
    const char      *cmdline)
{
    if (thread == THREAD_NULL || cmdline == NULL)
        return KERN_INVALID_ARGUMENT;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    strncpy(thread->cmdline, cmdline, sizeof(thread->cmdline) - 1);
    thread->cmdline[sizeof(thread->cmdline) - 1] = '\0';
    
    /* Also set comm (truncated command name) */
    strncpy(thread->comm, cmdline, sizeof(thread->comm) - 1);
    thread->comm[sizeof(thread->comm) - 1] = '\0';
    
    thread_unlock(thread);
    splx(s);
    
    return KERN_SUCCESS;
}

/*
 * thread_set_working_directory
 *
 * Set current working directory for thread.
 */
kern_return_t thread_set_working_directory(
    thread_t        thread,
    const char      *cwd)
{
    if (thread == THREAD_NULL || cwd == NULL)
        return KERN_INVALID_ARGUMENT;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    strncpy(thread->cwd, cwd, sizeof(thread->cwd) - 1);
    thread->cwd[sizeof(thread->cwd) - 1] = '\0';
    
    thread_unlock(thread);
    splx(s);
    
    return KERN_SUCCESS;
}

/*
 * thread_set_root_directory
 *
 * Set root directory for chroot jail.
 */
kern_return_t thread_set_root_directory(
    thread_t        thread,
    const char      *root)
{
    if (thread == THREAD_NULL || root == NULL)
        return KERN_INVALID_ARGUMENT;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    strncpy(thread->root, root, sizeof(thread->root) - 1);
    thread->root[sizeof(thread->root) - 1] = '\0';
    
    thread_unlock(thread);
    splx(s);
    
    return KERN_SUCCESS;
}

/*
 * thread_set_fs_credentials
 *
 * Set filesystem credentials for thread.
 */
void thread_set_fs_credentials(
    thread_t        thread,
    unsigned int    uid,
    unsigned int    gid,
    unsigned int    fsuid,
    unsigned int    fsgid)
{
    if (thread == THREAD_NULL)
        return;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    thread->fs_uid = uid;
    thread->fs_gid = gid;
    thread->fsuid = fsuid;
    thread->fsgid = fsgid;
    
    thread_unlock(thread);
    splx(s);
}

/*
 * thread_get_fs_credentials
 *
 * Get filesystem credentials from thread.
 */
void thread_get_fs_credentials(
    thread_t        thread,
    unsigned int    *uid,
    unsigned int    *gid,
    unsigned int    *fsuid,
    unsigned int    *fsgid)
{
    if (thread == THREAD_NULL)
        return;
    
    spl_t s = splsched();
    thread_lock(thread);
    
    if (uid != NULL) *uid = thread->fs_uid;
    if (gid != NULL) *gid = thread->fs_gid;
    if (fsuid != NULL) *fsuid = thread->fsuid;
    if (fsgid != NULL) *fsgid = thread->fsgid;
    
    thread_unlock(thread);
    splx(s);
}

/*
 * thread_print_info
 *
 * Print detailed information about a thread.
 */
void thread_print_info(thread_t thread)
{
    if (thread == THREAD_NULL) {
        printf("Thread: NULL\n");
        return;
    }
    
    spl_t s = splsched();
    thread_lock(thread);
    
    printf("\n=== Thread Information ===\n");
    printf("Thread: %p\n", thread);
    printf("Name: %s\n", thread->name);
    printf("Thread ID: %u\n", thread->thread_id);
    printf("TID: %u, PID: %u, TGID: %u\n", 
           thread->tid, thread->pid, thread->tgid);
    printf("State: 0x%x\n", thread->state);
    printf("Active: %s\n", thread->active ? "Yes" : "No");
    printf("Priority: %d (Mach), %d (Linux)\n", 
           thread->priority, thread->sched_priority);
    printf("CPU Usage: %u.%u%%\n", 
           thread_get_cpu_usage_percent(thread) / 10,
           thread_get_cpu_usage_percent(thread) % 10);
    printf("User Time: %lld.%06lld\n",
           thread->user_time.seconds, thread->user_time.microseconds);
    printf("System Time: %lld.%06lld\n",
           thread->system_time.seconds, thread->system_time.microseconds);
    printf("Context Switches: %llu (voluntary), %llu (involuntary)\n",
           thread->voluntary_switches, thread->involuntary_switches);
    printf("System Calls: %llu\n", thread->syscall_count);
    printf("I/O: read %llu bytes, write %llu bytes\n",
           thread->io_read_bytes, thread->io_write_bytes);
    printf("NUMA: preferred node %u, current node %u\n",
           thread->numa_preferred_node, thread->cpu_id / MAX_CPUS_PER_NODE);
    printf("Cgroup: ID %u, CPU share %u, mem limit %u\n",
           thread->cgroup_id, thread->cgroup_cpu_share, thread->cgroup_mem_limit);
    printf("Seccomp: mode %u\n", thread->seccomp_mode);
    printf("OOM Score: %u (adj %d)\n", thread->oom_score, thread->oom_score_adj);
    printf("Namespaces: UTS=%u IPC=%u NET=%u PID=%u MNT=%u USER=%u\n",
           thread->ns_uts, thread->ns_ipc, thread->ns_net,
           thread->ns_pid, thread->ns_mnt, thread->ns_user);
    
    thread_unlock(thread);
    splx(s);
}

/*
 * thread_dump_all_threads
 *
 * Dump information about all threads in the system.
 */
void thread_dump_all_threads(void)
{
    processor_set_t pset;
    thread_t thread;
    unsigned int count = 0;
    
    printf("\n=== All Threads Dump ===\n");
    printf("%-16s %-16s %-8s %-8s %-10s %-10s %-10s\n",
           "Thread", "Name", "TID", "State", "CPU%", "Priority", "Task");
    printf("%-16s %-16s %-8s %-8s %-10s %-10s %-10s\n",
           "----------------", "----------------", "--------", "--------",
           "----------", "----------", "----------");
    
    simple_lock(&all_psets_lock);
    queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
        pset_lock(pset);
        queue_iterate(&pset->threads, thread, thread_t, pset_threads) {
            printf("%-16p %-16s %-8u %-8x %-10u %-10d %-10p\n",
                   thread, thread->name, thread->tid, thread->state,
                   thread_get_cpu_usage_percent(thread) / 10,
                   thread->priority, thread->task);
            count++;
        }
        pset_unlock(pset);
    }
    simple_unlock(&all_psets_lock);
    
    printf("\nTotal threads: %u\n", count);
}

/*
 * Helper function: Convert time_value64 to nanoseconds
 */
static unsigned long long time_value64_to_nanoseconds(struct time_value64 tv)
{
    return tv.seconds * 1000000000ULL + tv.microseconds * 1000ULL;
}

/*
 * Constants for scheduling policies
 */
#define SCHED_OTHER  0
#define SCHED_FIFO   1
#define SCHED_RR     2
#define SCHED_BATCH  3
#define SCHED_IDLE   5
#define SCHED_DEADLINE 6

/*
 * Constants for namespace types
 */
#define NS_TYPE_UTS  0
#define NS_TYPE_IPC  1
#define NS_TYPE_NET  2
#define NS_TYPE_PID  3
#define NS_TYPE_MNT  4
#define NS_TYPE_USER 5

/*
 * Constants for system calls (simplified)
 */
#define SYS_read     0
#define SYS_write    1
#define SYS_exit     60
#define SYS_rt_sigreturn 15

/*
 * Maximum CPUs per NUMA node
 */
#define MAX_CPUS_PER_NODE 8

/*
 * Additional Thread Management Functions - Part 2
 * Advanced threading features for modern systems
 */

/*
 * thread_create_with_affinity
 *
 * Create a new thread with CPU affinity mask.
 */
kern_return_t thread_create_with_affinity(
	task_t		parent_task,
	unsigned int	cpu_affinity_mask,
	thread_t	*child_thread)
{
	thread_t new_thread;
	kern_return_t kr;
	
	if (parent_task == TASK_NULL || child_thread == NULL)
		return KERN_INVALID_ARGUMENT;
	
	kr = thread_create(parent_task, &new_thread);
	if (kr != KERN_SUCCESS)
		return kr;
	
	/* Set CPU affinity */
	spl_t s = splsched();
	thread_lock(new_thread);
	new_thread->cpu_affinity_mask = cpu_affinity_mask;
	new_thread->last_cpu_id = ffs(cpu_affinity_mask) - 1;
	thread_unlock(new_thread);
	splx(s);
	
	*child_thread = new_thread;
	return KERN_SUCCESS;
}

/*
 * thread_set_affinity_mask
 *
 * Set CPU affinity mask for thread.
 */
kern_return_t thread_set_affinity_mask(
	thread_t	thread,
	unsigned int	cpu_mask)
{
	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	thread->cpu_affinity_mask = cpu_mask;
	
	/* If current CPU not in mask, force migration */
	if ((cpu_mask & (1 << thread->last_cpu_id)) == 0) {
		int new_cpu = ffs(cpu_mask) - 1;
		if (new_cpu >= 0) {
			thread->last_cpu_id = new_cpu;
			if (thread->state & TH_RUN) {
				rem_runq(thread);
				thread_setrun(thread, TRUE);
			}
		}
	}
	
	thread_unlock(thread);
	splx(s);
	
	return KERN_SUCCESS;
}

/*
 * thread_get_affinity_mask
 *
 * Get CPU affinity mask from thread.
 */
unsigned int thread_get_affinity_mask(thread_t thread)
{
	unsigned int mask;
	
	if (thread == THREAD_NULL)
		return 0;
	
	spl_t s = splsched();
	thread_lock(thread);
	mask = thread->cpu_affinity_mask;
	thread_unlock(thread);
	splx(s);
	
	return mask;
}

/*
 * thread_migrate_to_cpu
 *
 * Migrate thread to specific CPU.
 */
kern_return_t thread_migrate_to_cpu(
	thread_t	thread,
	unsigned int	cpu_id)
{
	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	/* Check if CPU is allowed */
	if ((thread->cpu_affinity_mask & (1 << cpu_id)) == 0) {
		thread_unlock(thread);
		splx(s);
		return KERN_INVALID_ARGUMENT;
	}
	
	thread->last_cpu_id = cpu_id;
	
	/* Force reschedule if thread is runnable */
	if (thread->state & TH_RUN) {
		rem_runq(thread);
		thread_setrun(thread, TRUE);
	}
	
	thread_unlock(thread);
	splx(s);
	
	return KERN_SUCCESS;
}

/*
 * thread_set_priority_boost
 *
 * Set priority boost for thread (for interactive tasks).
 */
kern_return_t thread_set_priority_boost(
	thread_t	thread,
	unsigned int	boost_value)
{
	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;
	
	if (boost_value > 50)
		boost_value = 50;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	thread->priority_boost = boost_value;
	
	/* Apply boost to current priority */
	int new_priority = thread->priority + boost_value;
	if (new_priority > thread->max_priority)
		new_priority = thread->max_priority;
	
	thread->priority = new_priority;
	compute_priority(thread, TRUE);
	
	thread_unlock(thread);
	splx(s);
	
	return KERN_SUCCESS;
}

/*
 * thread_set_latency_sensitive
 *
 * Mark thread as latency-sensitive (for low-latency scheduling).
 */
void thread_set_latency_sensitive(thread_t thread, boolean_t sensitive)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	if (sensitive) {
		thread->sched_flags |= THREAD_FLAG_LATENCY_SENSITIVE;
		/* Reduce scheduling latency */
		thread->sched_latency_ns = 100000; /* 100us */
	} else {
		thread->sched_flags &= ~THREAD_FLAG_LATENCY_SENSITIVE;
		thread->sched_latency_ns = 1000000; /* 1ms default */
	}
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_set_io_priority
 *
 * Set I/O priority for thread.
 */
kern_return_t thread_set_io_priority(
	thread_t	thread,
	unsigned int	io_class,
	unsigned int	io_priority)
{
	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;
	
	if (io_class > 3 || io_priority > 7)
		return KERN_INVALID_ARGUMENT;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	thread->io_class = io_class;
	thread->io_priority = io_priority;
	
	thread_unlock(thread);
	splx(s);
	
	return KERN_SUCCESS;
}

/*
 * thread_get_io_priority
 *
 * Get I/O priority from thread.
 */
void thread_get_io_priority(
	thread_t	thread,
	unsigned int	*io_class,
	unsigned int	*io_priority)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	if (io_class != NULL)
		*io_class = thread->io_class;
	if (io_priority != NULL)
		*io_priority = thread->io_priority;
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_account_page_fault
 *
 * Account for page fault in thread statistics.
 */
void thread_account_page_fault(
	thread_t	thread,
	unsigned int	fault_type,
	unsigned int	page_count)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	switch (fault_type) {
		case FAULT_MINOR:
			thread->min_flt += page_count;
			break;
		case FAULT_MAJOR:
			thread->maj_flt += page_count;
			thread->iowait_time_ns += 1000000; /* Assume 1ms I/O wait */
			break;
		case FAULT_COW:
			thread->cow_faults += page_count;
			break;
	}
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_get_page_faults
 *
 * Get page fault statistics from thread.
 */
void thread_get_page_faults(
	thread_t	thread,
	unsigned int	*min_flt,
	unsigned int	*maj_flt,
	unsigned int	*cow_flt)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	if (min_flt != NULL)
		*min_flt = thread->min_flt;
	if (maj_flt != NULL)
		*maj_flt = thread->maj_flt;
	if (cow_flt != NULL)
		*cow_flt = thread->cow_faults;
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_set_robust_futex
 *
 * Set robust futex list for thread.
 */
kern_return_t thread_set_robust_futex(
	thread_t	thread,
	void		*list_head,
	unsigned int	list_len)
{
	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	thread->robust_futex_list = list_head;
	thread->robust_futex_len = list_len;
	
	thread_unlock(thread);
	splx(s);
	
	return KERN_SUCCESS;
}

/*
 * thread_cleanup_robust_futexes
 *
 * Clean up robust futexes when thread exits.
 */
void thread_cleanup_robust_futexes(thread_t thread)
{
	if (thread == THREAD_NULL || thread->robust_futex_list == NULL)
		return;
	
	/* Wake up all waiters on robust futexes */
	thread_wakeup(thread->robust_futex_list);
	
	spl_t s = splsched();
	thread_lock(thread);
	thread->robust_futex_list = NULL;
	thread->robust_futex_len = 0;
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_set_perf_counter
 *
 * Set performance counter for thread profiling.
 */
kern_return_t thread_set_perf_counter(
	thread_t	thread,
	unsigned int	counter_mask,
	void		*data)
{
	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	thread->perf_counter_mask = counter_mask;
	thread->perf_counter_data = data;
	
	thread_unlock(thread);
	splx(s);
	
	return KERN_SUCCESS;
}

/*
 * thread_update_perf_counters
 *
 * Update performance counter values for thread.
 */
void thread_update_perf_counters(thread_t thread)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	if (thread->perf_counter_mask & PERF_COUNT_INSTRUCTIONS) {
		thread->perf_instructions += read_instructions_counter();
	}
	if (thread->perf_counter_mask & PERF_COUNT_CYCLES) {
		thread->perf_cycles += read_cycles_counter();
	}
	if (thread->perf_counter_mask & PERF_COUNT_CACHE_MISSES) {
		thread->perf_cache_misses += read_cache_miss_counter();
	}
	if (thread->perf_counter_mask & PERF_COUNT_BRANCH_MISSES) {
		thread->perf_branch_misses += read_branch_miss_counter();
	}
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_get_perf_counters
 *
 * Get performance counter values from thread.
 */
void thread_get_perf_counters(
	thread_t		thread,
	unsigned long long	*instructions,
	unsigned long long	*cycles,
	unsigned long long	*cache_misses,
	unsigned long long	*branch_misses)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	if (instructions != NULL)
		*instructions = thread->perf_instructions;
	if (cycles != NULL)
		*cycles = thread->perf_cycles;
	if (cache_misses != NULL)
		*cache_misses = thread->perf_cache_misses;
	if (branch_misses != NULL)
		*branch_misses = thread->perf_branch_misses;
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_set_ptrace_options
 *
 * Set ptrace options for debugging.
 */
kern_return_t thread_set_ptrace_options(
	thread_t	thread,
	unsigned int	options,
	void		*data)
{
	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	thread->ptrace_options = options;
	thread->ptrace_data = data;
	
	thread_unlock(thread);
	splx(s);
	
	return KERN_SUCCESS;
}

/*
 * thread_is_being_traced
 *
 * Check if thread is being traced.
 */
boolean_t thread_is_being_traced(thread_t thread)
{
	boolean_t traced;
	
	if (thread == THREAD_NULL)
		return FALSE;
	
	spl_t s = splsched();
	thread_lock(thread);
	traced = (thread->ptrace_options != 0);
	thread_unlock(thread);
	splx(s);
	
	return traced;
}

/*
 * thread_set_trace_flags
 *
 * Set tracing flags for thread.
 */
void thread_set_trace_flags(thread_t thread, unsigned int flags)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	thread->trace_flags = flags;
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_add_trace_event
 *
 * Add trace event to thread's trace buffer.
 */
void thread_add_trace_event(
	thread_t	thread,
	unsigned int	event_type,
	unsigned long	event_data)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	unsigned int idx = thread->trace_index % THREAD_TRACE_BUFFER_SIZE;
	thread->trace_events[idx].type = event_type;
	thread->trace_events[idx].data = event_data;
	thread->trace_events[idx].timestamp = mach_absolute_time();
	thread->trace_index++;
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_get_trace_events
 *
 * Get trace events from thread's buffer.
 */
unsigned int thread_get_trace_events(
	thread_t		thread,
	struct trace_event	*buffer,
	unsigned int		max_events)
{
	unsigned int i, count;
	
	if (thread == THREAD_NULL || buffer == NULL || max_events == 0)
		return 0;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	count = (thread->trace_index > max_events) ? max_events : thread->trace_index;
	
	for (i = 0; i < count; i++) {
		buffer[i] = thread->trace_events[i];
	}
	
	thread_unlock(thread);
	splx(s);
	
	return count;
}

/*
 * thread_set_audit_state
 *
 * Set audit state for thread.
 */
void thread_set_audit_state(
	thread_t	thread,
	unsigned int	audit_state,
	unsigned int	audit_session)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	thread->audit_state = audit_state;
	thread->audit_session = audit_session;
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_log_audit_event
 *
 * Log audit event for thread.
 */
void thread_log_audit_event(
	thread_t	thread,
	unsigned int	event_id,
	unsigned int	event_result,
	const char	*event_name)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	unsigned int idx = thread->audit_index % THREAD_AUDIT_BUFFER_SIZE;
	thread->audit_events[idx].event_id = event_id;
	thread->audit_events[idx].event_result = event_result;
	thread->audit_events[idx].timestamp = mach_absolute_time();
	strncpy(thread->audit_events[idx].event_name, event_name, 31);
	thread->audit_events[idx].event_name[31] = '\0';
	thread->audit_index++;
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_set_syscall_stats
 *
 * Update syscall statistics for thread.
 */
void thread_set_syscall_stats(
	thread_t	thread,
	unsigned int	syscall_nr,
	unsigned long	duration_ns)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	thread->syscall_count++;
	if (syscall_nr < 512) {
		thread->syscall_stats[syscall_nr]++;
		thread->syscall_time[syscall_nr] += duration_ns;
	}
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_get_syscall_stats
 *
 * Get syscall statistics from thread.
 */
unsigned int thread_get_syscall_stats(
	thread_t	thread,
	unsigned int	syscall_nr,
	unsigned int	*call_count,
	unsigned long	*total_time_ns)
{
	if (thread == THREAD_NULL || syscall_nr >= 512)
		return 0;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	if (call_count != NULL)
		*call_count = thread->syscall_stats[syscall_nr];
	if (total_time_ns != NULL)
		*total_time_ns = thread->syscall_time[syscall_nr];
	
	thread_unlock(thread);
	splx(s);
	
	return thread->syscall_stats[syscall_nr];
}

/*
 * thread_set_memory_policy
 *
 * Set memory allocation policy for thread.
 */
kern_return_t thread_set_memory_policy(
	thread_t	thread,
	unsigned int	policy,
	unsigned int	flags)
{
	if (thread == THREAD_NULL)
		return KERN_INVALID_ARGUMENT;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	thread->mem_policy = policy;
	thread->mem_policy_flags = flags;
	
	thread_unlock(thread);
	splx(s);
	
	return KERN_SUCCESS;
}

/*
 * thread_get_memory_policy
 *
 * Get memory allocation policy from thread.
 */
void thread_get_memory_policy(
	thread_t	thread,
	unsigned int	*policy,
	unsigned int	*flags)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	if (policy != NULL)
		*policy = thread->mem_policy;
	if (flags != NULL)
		*flags = thread->mem_policy_flags;
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_update_memory_usage
 *
 * Update thread's memory usage statistics.
 */
void thread_update_memory_usage(
	thread_t	thread,
	long		delta_rss,
	long		delta_vm)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	if (delta_rss > 0 || (thread->rss + delta_rss) >= 0) {
		thread->rss += delta_rss;
	}
	if (delta_vm > 0 || (thread->total_vm + delta_vm) >= 0) {
		thread->total_vm += delta_vm;
	}
	
	/* Check RSS limit */
	if (thread->rss_limit > 0 && thread->rss > thread->rss_limit) {
		/* Send SIGSEGV or SIGKILL */
		thread->flags |= THREAD_FLAG_OOM;
	}
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_set_rss_limit
 *
 * Set RSS (Resident Set Size) limit for thread.
 */
void thread_set_rss_limit(thread_t thread, unsigned int limit_kb)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	thread->rss_limit = limit_kb;
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_set_cpu_limit
 *
 * Set CPU time limit for thread.
 */
void thread_set_cpu_limit(thread_t thread, unsigned int limit_seconds)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	thread->cpu_limit = limit_seconds;
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_check_cpu_limit
 *
 * Check if thread has exceeded CPU time limit.
 */
boolean_t thread_check_cpu_limit(thread_t thread)
{
	boolean_t exceeded = FALSE;
	
	if (thread == THREAD_NULL)
		return FALSE;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	if (thread->cpu_limit > 0) {
		unsigned long long total_time_ns = 
		    time_value64_to_nanoseconds(thread->user_time) +
		    time_value64_to_nanoseconds(thread->system_time);
		unsigned int total_seconds = total_time_ns / 1000000000ULL;
		
		if (total_seconds > thread->cpu_limit) {
			exceeded = TRUE;
			thread->flags |= THREAD_FLAG_CPU_EXCEEDED;
		}
	}
	
	thread_unlock(thread);
	splx(s);
	
	return exceeded;
}

/*
 * thread_set_wait_priority
 *
 * Set wait priority for thread (for lock ordering).
 */
void thread_set_wait_priority(
	thread_t	thread,
	int		wait_priority,
	void		*wait_address)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	thread->wait_priority = wait_priority;
	thread->wait_address = wait_address;
	thread->state |= TH_WAIT_PRIORITY;
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_clear_wait_priority
 *
 * Clear wait priority for thread.
 */
void thread_clear_wait_priority(thread_t thread)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	thread->wait_priority = -1;
	thread->wait_address = NULL;
	thread->state &= ~TH_WAIT_PRIORITY;
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_inherit_priority
 *
 * Inherit priority from another thread (for priority inheritance).
 */
void thread_inherit_priority(thread_t thread, thread_t locker)
{
	if (thread == THREAD_NULL || locker == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	thread_lock(locker);
	
	int locker_prio = locker->priority;
	if (locker_prio > thread->priority) {
		thread->priority = locker_prio;
		thread->priority_inherited = TRUE;
		compute_priority(thread, TRUE);
	}
	
	thread_unlock(locker);
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_restore_priority
 *
 * Restore original priority after inheritance.
 */
void thread_restore_priority(thread_t thread)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	if (thread->priority_inherited) {
		thread->priority = thread->base_priority;
		thread->priority_inherited = FALSE;
		compute_priority(thread, TRUE);
	}
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_get_lock_statistics
 *
 * Get lock statistics for thread.
 */
void thread_get_lock_statistics(
	thread_t	thread,
	unsigned int	*locks_held,
	unsigned int	*locks_waited,
	unsigned long	*lock_wait_time_ns)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	if (locks_held != NULL)
		*locks_held = thread->locks_held;
	if (locks_waited != NULL)
		*locks_waited = thread->locks_waited;
	if (lock_wait_time_ns != NULL)
		*lock_wait_time_ns = thread->lock_wait_time_ns;
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_account_lock_wait
 *
 * Account lock wait time for thread.
 */
void thread_account_lock_wait(thread_t thread, unsigned long wait_time_ns)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	thread->locks_waited++;
	thread->lock_wait_time_ns += wait_time_ns;
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_account_lock_acquire
 *
 * Account lock acquisition for thread.
 */
void thread_account_lock_acquire(thread_t thread)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	thread->locks_held++;
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_account_lock_release
 *
 * Account lock release for thread.
 */
void thread_account_lock_release(thread_t thread)
{
	if (thread == THREAD_NULL)
		return;
	
	spl_t s = splsched();
	thread_lock(thread);
	
	if (thread->locks_held > 0)
		thread->locks_held--;
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_print_detailed_stats
 *
 * Print detailed statistics for a thread.
 */
void thread_print_detailed_stats(thread_t thread)
{
	if (thread == THREAD_NULL) {
		printf("Thread: NULL\n");
		return;
	}
	
	spl_t s = splsched();
	thread_lock(thread);
	
	printf("\n========== THREAD DETAILED STATISTICS ==========\n");
	printf("Thread: %p (%s)\n", thread, thread->name);
	printf("TID: %u, PID: %u, TGID: %u\n", thread->tid, thread->pid, thread->tgid);
	printf("State: 0x%x, Active: %s\n", thread->state, thread->active ? "Yes" : "No");
	
	printf("\n--- Scheduling ---\n");
	printf("Priority: %d (Mach), %d (Linux)\n", thread->priority, thread->sched_priority);
	printf("Max Priority: %d, Base Priority: %d\n", thread->max_priority, thread->base_priority);
	printf("CPU Affinity: 0x%x, Last CPU: %u\n", thread->cpu_affinity_mask, thread->last_cpu_id);
	printf("CPU Usage: %u.%u%%\n", thread_get_cpu_usage_percent(thread) / 10,
	       thread_get_cpu_usage_percent(thread) % 10);
	printf("Sched Policy: %u, Flags: 0x%x\n", thread->sched_policy, thread->sched_flags);
	printf("Latency Sensitive: %s\n", 
	       (thread->sched_flags & THREAD_FLAG_LATENCY_SENSITIVE) ? "Yes" : "No");
	
	printf("\n--- Time ---\n");
	printf("User Time: %lld.%06lld\n", thread->user_time.seconds, thread->user_time.microseconds);
	printf("System Time: %lld.%06lld\n", thread->system_time.seconds, thread->system_time.microseconds);
	printf("I/O Wait Time: %lld ns\n", thread->iowait_time_ns);
	printf("Steal Time: %lld ns\n", thread->steal_time_ns);
	
	printf("\n--- Memory ---\n");
	printf("RSS: %u KB, RSS Limit: %u KB\n", thread->rss, thread->rss_limit);
	printf("Total VM: %u KB\n", thread->total_vm);
	printf("Min Faults: %u, Maj Faults: %u, COW Faults: %u\n",
	       thread->min_flt, thread->maj_flt, thread->cow_faults);
	printf("Mem Policy: %u, Flags: 0x%x\n", thread->mem_policy, thread->mem_policy_flags);
	
	printf("\n--- I/O ---\n");
	printf("I/O Class: %u, Priority: %u\n", thread->io_class, thread->io_priority);
	printf("Read: %llu bytes (%llu ops)\n", thread->io_read_bytes, thread->io_read_ops);
	printf("Write: %llu bytes (%llu ops)\n", thread->io_write_bytes, thread->io_write_ops);
	
	printf("\n--- Context Switches ---\n");
	printf("Voluntary: %llu, Involuntary: %llu\n", 
	       thread->voluntary_switches, thread->involuntary_switches);
	printf("System Calls: %llu\n", thread->syscall_count);
	
	printf("\n--- Lock Statistics ---\n");
	printf("Locks Held: %u, Locks Waited: %u\n", thread->locks_held, thread->locks_waited);
	printf("Lock Wait Time: %lu ns\n", thread->lock_wait_time_ns);
	
	printf("\n--- Performance Counters ---\n");
	printf("Instructions: %llu, Cycles: %llu\n", thread->perf_instructions, thread->perf_cycles);
	printf("Cache Misses: %llu, Branch Misses: %llu\n", 
	       thread->perf_cache_misses, thread->perf_branch_misses);
	
	printf("\n--- Security ---\n");
	printf("Seccomp Mode: %u\n", thread->seccomp_mode);
	printf("Capabilities: 0x%x/0x%x/0x%x/0x%x\n",
	       thread->capabilities[0], thread->capabilities[1],
	       thread->capabilities[2], thread->capabilities[3]);
	printf("Audit State: %u, Session: %u\n", thread->audit_state, thread->audit_session);
	
	printf("\n--- Namespaces ---\n");
	printf("UTS: %u, IPC: %u, NET: %u, PID: %u, MNT: %u, USER: %u\n",
	       thread->ns_uts, thread->ns_ipc, thread->ns_net,
	       thread->ns_pid, thread->ns_mnt, thread->ns_user);
	
	printf("\n--- Cgroup ---\n");
	printf("Cgroup ID: %u, CPU Share: %u, Mem Limit: %u, I/O Weight: %u\n",
	       thread->cgroup_id, thread->cgroup_cpu_share, 
	       thread->cgroup_mem_limit, thread->cgroup_io_weight);
	
	printf("\n--- NUMA ---\n");
	printf("Preferred Node: %u, Node Mask: 0x%x\n", 
	       thread->numa_preferred_node, thread->numa_mask);
	
	printf("\n--- Debug ---\n");
	printf("Ptrace Options: 0x%x, Trace Flags: 0x%x\n", 
	       thread->ptrace_options, thread->trace_flags);
	printf("Debug Regs: DR0=%08x DR1=%08x DR2=%08x DR3=%08x\n",
	       thread->debug_regs[0], thread->debug_regs[1],
	       thread->debug_regs[2], thread->debug_regs[3]);
	
	printf("\n--- OOM ---\n");
	printf("OOM Score: %u, Adjustment: %d\n", thread->oom_score, thread->oom_score_adj);
	printf("CPU Limit: %u seconds, Flags: 0x%x\n", thread->cpu_limit, thread->flags);
	
	printf("\n================================================\n");
	
	thread_unlock(thread);
	splx(s);
}

/*
 * thread_find_by_tid
 *
 * Find thread by TID (Thread ID).
 */
thread_t thread_find_by_tid(unsigned int tid)
{
	processor_set_t pset;
	thread_t thread, found = THREAD_NULL;
	
	simple_lock(&all_psets_lock);
	queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
		pset_lock(pset);
		queue_iterate(&pset->threads, thread, thread_t, pset_threads) {
			if (thread->tid == tid) {
				thread_reference(thread);
				found = thread;
				pset_unlock(pset);
				simple_unlock(&all_psets_lock);
				return found;
			}
		}
		pset_unlock(pset);
	}
	simple_unlock(&all_psets_lock);
	
	return THREAD_NULL;
}

/*
 * thread_find_by_pid
 *
 * Find thread by PID (Process ID).
 */
thread_t thread_find_by_pid(unsigned int pid)
{
	processor_set_t pset;
	thread_t thread, found = THREAD_NULL;
	
	simple_lock(&all_psets_lock);
	queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
		pset_lock(pset);
		queue_iterate(&pset->threads, thread, thread_t, pset_threads) {
			if (thread->pid == pid) {
				thread_reference(thread);
				found = thread;
				pset_unlock(pset);
				simple_unlock(&all_psets_lock);
				return found;
			}
		}
		pset_unlock(pset);
	}
	simple_unlock(&all_psets_lock);
	
	return THREAD_NULL;
}

/*
 * thread_foreach
 *
 * Execute function for each thread in system.
 */
void thread_foreach(void (*func)(thread_t, void *), void *arg)
{
	processor_set_t pset;
	thread_t thread;
	
	if (func == NULL)
		return;
	
	simple_lock(&all_psets_lock);
	queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
		pset_lock(pset);
		queue_iterate(&pset->threads, thread, thread_t, pset_threads) {
			thread_reference(thread);
			pset_unlock(pset);
			simple_unlock(&all_psets_lock);
			
			func(thread, arg);
			
			thread_deallocate(thread);
			simple_lock(&all_psets_lock);
			pset_lock(pset);
		}
		pset_unlock(pset);
	}
	simple_unlock(&all_psets_lock);
}

/*
 * thread_get_system_stats
 *
 * Get system-wide thread statistics.
 */
void thread_get_system_stats(
	unsigned int	*total_threads,
	unsigned int	*running_threads,
	unsigned int	*sleeping_threads,
	unsigned int	*zombie_threads)
{
	processor_set_t pset;
	thread_t thread;
	unsigned int total = 0, running = 0, sleeping = 0, zombie = 0;
	
	simple_lock(&all_psets_lock);
	queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
		pset_lock(pset);
		queue_iterate(&pset->threads, thread, thread_t, pset_threads) {
			total++;
			if (thread->state & TH_RUN)
				running++;
			else if (thread->state & TH_WAIT)
				sleeping++;
			else if (!thread->active)
				zombie++;
		}
		pset_unlock(pset);
	}
	simple_unlock(&all_psets_lock);
	
	if (total_threads != NULL)
		*total_threads = total;
	if (running_threads != NULL)
		*running_threads = running;
	if (sleeping_threads != NULL)
		*sleeping_threads = sleeping;
	if (zombie_threads != NULL)
		*zombie_threads = zombie;
}

/*
 * Helper functions for performance counters
 */
static unsigned long long read_instructions_counter(void)
{
	unsigned long long instructions = 0;
	/* In real implementation, would use RDPMC instruction */
	return instructions;
}

static unsigned long long read_cycles_counter(void)
{
	unsigned long long cycles = 0;
	/* In real implementation, would use RDTSC instruction */
	return cycles;
}

static unsigned long long read_cache_miss_counter(void)
{
	unsigned long long misses = 0;
	/* In real implementation, would use perf counters */
	return misses;
}

static unsigned long long read_branch_miss_counter(void)
{
	unsigned long long misses = 0;
	/* In real implementation, would use perf counters */
	return misses;
}

/*
 * Constants and flags
 */
#define THREAD_FLAG_LATENCY_SENSITIVE	0x00000001
#define THREAD_FLAG_OOM			0x00000002
#define THREAD_FLAG_CPU_EXCEEDED	0x00000004

#define THREAD_TRACE_BUFFER_SIZE	256
#define THREAD_AUDIT_BUFFER_SIZE	128

#define FAULT_MINOR	0
#define FAULT_MAJOR	1
#define FAULT_COW	2

#define PERF_COUNT_INSTRUCTIONS	0x00000001
#define PERF_COUNT_CYCLES	0x00000002
#define PERF_COUNT_CACHE_MISSES	0x00000004
#define PERF_COUNT_BRANCH_MISSES 0x00000008

/*
 * Trace event structure
 */
struct trace_event {
	unsigned int	type;
	unsigned long	data;
	unsigned long long timestamp;
};

/*
 * Audit event structure
 */
struct audit_event {
	unsigned int	event_id;
	unsigned int	event_result;
	unsigned long long timestamp;
	char		event_name[32];
};

/*
 * Performance counter structure
 */
struct perf_counters {
	unsigned long long instructions;
	unsigned long long cycles;
	unsigned long long cache_misses;
	unsigned long long branch_misses;
	unsigned long long tlb_misses;
	unsigned long long stalled_cycles;
};
