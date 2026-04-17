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
 *	File:	kern/task.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young, David Golub,
 *		David Black
 *
 *	Task management primitives implementation.
 */

#include "../linux/kern/sched.h"
#include <string.h>

#include <mach/machine/vm_types.h>
#include <mach/vm_param.h>
#include <mach/task_info.h>
#include <mach/task_special_ports.h>
#include <mach_debug/mach_debug_types.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_types.h>
#include <kern/debug.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/slab.h>
#include <kern/gnumach.server.h>
#include <kern/kalloc.h>
#include <kern/mach.server.h>
#include <kern/mach_host.server.h>
#include <kern/processor.h>
#include <kern/printf.h>
#include <kern/sched_prim.h>	/* for thread_wakeup */
#include <kern/ipc_tt.h>
#include <kern/syscall_emulation.h>
#include <kern/task_notify.user.h>
#include <vm/vm_kern.h>		/* for kernel_map, ipc_kernel_map */
#include <machine/spl.h>	/* for splsched */

task_t	kernel_task = TASK_NULL;
struct kmem_cache task_cache;

/* Where to send notifications about newly created tasks.  */
ipc_port_t new_task_notification = NULL;

void task_init(void)
{
	kmem_cache_init(&task_cache, "task", sizeof(struct task), 0,
			NULL, 0);

	eml_init();
	machine_task_module_init ();

	/*
	 * Create the kernel task as the first task.
	 * Task_create must assign to kernel_task as a side effect,
	 * for other initialization. (:-()
	 */
	(void) task_create_kernel(TASK_NULL, FALSE, &kernel_task);
	(void) task_set_name(kernel_task, "gnumach");
	vm_map_set_name(kernel_map, kernel_task->name);
}

kern_return_t task_create(
	task_t		parent_task,
	boolean_t	inherit_memory,
	task_t		*child_task)		/* OUT */
{
	if (parent_task == TASK_NULL)
		return KERN_INVALID_TASK;

	return task_create_kernel (parent_task, inherit_memory,
				   child_task);
}

kern_return_t
task_create_kernel(
	task_t		parent_task,
	boolean_t	inherit_memory,
	task_t		*child_task)		/* OUT */
{
	task_t		new_task;
	processor_set_t	pset;
#if FAST_TAS
	int i;
#endif

	new_task = (task_t) kmem_cache_alloc(&task_cache);
	if (new_task == TASK_NULL)
		return KERN_RESOURCE_SHORTAGE;

	/* one ref for just being alive; one for our caller */
	new_task->ref_count = 2;

	if (child_task == &kernel_task)  {
		new_task->map = kernel_map;
	} else if (inherit_memory) {
		new_task->map = vm_map_fork(parent_task->map);
	} else {
		pmap_t new_pmap = pmap_create((vm_size_t) 0);
		if (new_pmap == PMAP_NULL)
			new_task->map = VM_MAP_NULL;
		else {
			new_task->map = vm_map_create(new_pmap,
					round_page(VM_MIN_USER_ADDRESS),
					trunc_page(VM_MAX_USER_ADDRESS));
			if (new_task->map == VM_MAP_NULL)
				pmap_destroy(new_pmap);
			else if (parent_task != TASK_NULL) {
				vm_map_lock_read(parent_task->map);
				vm_map_copy_limits(new_task->map, parent_task->map);
				vm_map_unlock_read(parent_task->map);
			}
		}
	}
	if (new_task->map == VM_MAP_NULL) {
		kmem_cache_free(&task_cache, (vm_address_t) new_task);
		return KERN_RESOURCE_SHORTAGE;
	}
	if (child_task != &kernel_task)
		vm_map_set_name(new_task->map, new_task->name);

	simple_lock_init(&new_task->lock);
	queue_init(&new_task->thread_list);
	new_task->suspend_count = 0;
	new_task->active = TRUE;
	new_task->user_stop_count = 0;
	new_task->thread_count = 0;
	new_task->faults = 0;
	new_task->zero_fills = 0;
	new_task->reactivations = 0;
	new_task->pageins = 0;
	new_task->cow_faults = 0;
	new_task->messages_sent = 0;
	new_task->messages_received = 0;

	eml_task_reference(new_task, parent_task);

	ipc_task_init(new_task, parent_task);
	machine_task_init (new_task);

	time_value64_init(&new_task->total_user_time);
	time_value64_init(&new_task->total_system_time);

	record_time_stamp (&new_task->creation_time);

	if (parent_task != TASK_NULL) {
		task_lock(parent_task);
		pset = parent_task->processor_set;
		if (!pset->active)
			pset = &default_pset;
		pset_reference(pset);
		new_task->priority = parent_task->priority;
		task_unlock(parent_task);
	}
	else {
		pset = &default_pset;
		pset_reference(pset);
		new_task->priority = BASEPRI_USER;
	}
	pset_lock(pset);
	pset_add_task(pset, new_task);
	pset_unlock(pset);

	new_task->may_assign = TRUE;
	new_task->assign_active = FALSE;
	new_task->essential = FALSE;

#if	MACH_PCSAMPLE
	new_task->pc_sample.buffer = 0;
	new_task->pc_sample.seqno = 0;
	new_task->pc_sample.sampletypes = 0;
#endif	/* MACH_PCSAMPLE */

#if	FAST_TAS
	for (i = 0; i < TASK_FAST_TAS_NRAS; i++)  {
	    if (inherit_memory) {
		new_task->fast_tas_base[i] = parent_task->fast_tas_base[i];
 		new_task->fast_tas_end[i]  = parent_task->fast_tas_end[i];
	    } else {
 		new_task->fast_tas_base[i] = (vm_offset_t)0;
 		new_task->fast_tas_end[i]  = (vm_offset_t)0;
	    }
	}
#endif	/* FAST_TAS */

	if (parent_task == TASK_NULL)
		snprintf (new_task->name, sizeof new_task->name, "%p",
			  new_task);
	else
		snprintf (new_task->name, sizeof new_task->name, "(%.*s)",
			  (int) (sizeof new_task->name - 3), parent_task->name);

	if (new_task_notification != NULL) {
		task_reference (new_task);
		task_reference (parent_task);
		mach_notify_new_task (new_task_notification,
				      convert_task_to_port (new_task),
				      parent_task
				      ? convert_task_to_port (parent_task)
				      : IP_NULL);
	}

	ipc_task_enable(new_task);

	*child_task = new_task;
	return KERN_SUCCESS;
}

/*
 *	task_deallocate:
 *
 *	Give up a reference to the specified task and destroy it if there
 *	are no other references left.  It is assumed that the current thread
 *	is never in this task.
 */
void task_deallocate(
	task_t	task)
{
	int c;
	processor_set_t pset;

	if (task == TASK_NULL)
		return;

	task_lock(task);
	c = --(task->ref_count);
	task_unlock(task);
	if (c != 0)
		return;

	machine_task_terminate (task);

	eml_task_deallocate(task);

	pset = task->processor_set;
	pset_lock(pset);
	pset_remove_task(pset,task);
	pset_unlock(pset);
	pset_deallocate(pset);
	vm_map_deallocate(task->map);
	is_release(task->itk_space);
	kmem_cache_free(&task_cache, (vm_offset_t) task);
}

void task_reference(
	task_t	task)
{
	if (task == TASK_NULL)
		return;

	task_lock(task);
	task->ref_count++;
	task_unlock(task);
}

/*
 *	task_terminate:
 *
 *	Terminate the specified task.  See comments on thread_terminate
 *	(kern/thread.c) about problems with terminating the "current task."
 */
kern_return_t task_terminate(
	task_t	task)
{
	thread_t		thread, cur_thread;
	queue_head_t		*list;
	task_t			cur_task;
	spl_t			s;

	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	list = &task->thread_list;
	cur_task = current_task();
	cur_thread = current_thread();

	/*
	 *	Deactivate task so that it can't be terminated again,
	 *	and so lengthy operations in progress will abort.
	 *
	 *	If the current thread is in this task, remove it from
	 *	the task's thread list to keep the thread-termination
	 *	loop simple.
	 */
	if (task == cur_task) {
		task_lock(task);
		if (!task->active) {
			/*
			 *	Task is already being terminated.
			 */
			task_unlock(task);
			return KERN_FAILURE;
		}
		/*
		 *	Make sure current thread is not being terminated.
		 */
		s = splsched();
		thread_lock(cur_thread);
		if (!cur_thread->active) {
			thread_unlock(cur_thread);
			(void) splx(s);
			task_unlock(task);
			thread_terminate(cur_thread);
			return KERN_FAILURE;
		}
		task_hold_locked(task);
		task->active = FALSE;
		queue_remove(list, cur_thread, thread_t, thread_list);
		thread_unlock(cur_thread);
		(void) splx(s);
		task_unlock(task);

		/*
		 *	Shut down this thread's ipc now because it must
		 *	be left alone to terminate the task.
		 */
		ipc_thread_disable(cur_thread);
		ipc_thread_terminate(cur_thread);
	}
	else {
		/*
		 *	Lock both current and victim task to check for
		 *	potential deadlock.
		 */
		if ((vm_offset_t)task < (vm_offset_t)cur_task) {
			task_lock(task);
			task_lock(cur_task);
		}
		else {
			task_lock(cur_task);
			task_lock(task);
		}
		/*
		 *	Check if current thread or task is being terminated.
		 */
		s = splsched();
		thread_lock(cur_thread);
		if ((!cur_task->active) ||(!cur_thread->active)) {
			/*
			 * Current task or thread is being terminated.
			 */
			thread_unlock(cur_thread);
			(void) splx(s);
			task_unlock(task);
			task_unlock(cur_task);
			thread_terminate(cur_thread);
			return KERN_FAILURE;
		}
		thread_unlock(cur_thread);
		(void) splx(s);
		task_unlock(cur_task);

		if (!task->active) {
			/*
			 *	Task is already being terminated.
			 */
			task_unlock(task);
			return KERN_FAILURE;
		}
		task_hold_locked(task);
		task->active = FALSE;
		task_unlock(task);
	}

	/*
	 *	Prevent further execution of the task.  ipc_task_disable
	 *	prevents further task operations via the task port.
	 *	If this is the current task, the current thread will
	 *	be left running.
	 */
	(void) task_dowait(task,TRUE);			/* may block */
	ipc_task_disable(task);

	/*
	 *	Terminate each thread in the task.
	 *
	 *      The task_port is closed down, so no more thread_create
	 *      operations can be done.  Thread_force_terminate closes the
	 *      thread port for each thread; when that is done, the
	 *      thread will eventually disappear.  Thus the loop will
	 *      terminate.  Call thread_force_terminate instead of
	 *      thread_terminate to avoid deadlock checks.  Need
	 *      to call thread_block() inside loop because some other
	 *      thread (e.g., the reaper) may have to run to get rid
	 *      of all references to the thread; it won't vanish from
	 *      the task's thread list until the last one is gone.
	 *
	 *      Occasionally there are dependencies between threads
	 *      that require a specific thread to be terminated before
	 *      others are able to. These dependencies are unknown to
	 *      the task so repeated iteration over the thread list is
	 *      required.
	 */
	task_lock(task);
	while (!queue_empty(list)) {
		thread = (thread_t) queue_first(list);
		thread_reference(thread);

		do {
			thread_t next = (thread_t) queue_next(&thread->thread_list);

			if (!queue_end(list, (queue_entry_t) next))
				thread_reference(next);

			task_unlock(task);
			thread_force_terminate(thread);
			thread_deallocate(thread);
			thread_block(thread_no_continuation);
			thread = next;
			task_lock(task);
		} while (!queue_end(list, (queue_entry_t) thread));
	}
	task_unlock(task);

	/*
	 *	Shut down IPC.
	 */
	ipc_task_terminate(task);


	/*
	 *	Deallocate the task's reference to itself.
	 */
	task_deallocate(task);

	/*
	 *	If the current thread is in this task, it has not yet
	 *	been terminated (since it was removed from the task's
	 *	thread-list).  Put it back in the thread list (for
	 *	completeness), and terminate it.  Since it holds the
	 *	last reference to the task, terminating it will deallocate
	 *	the task.
	 */
	if (cur_thread->task == task) {
		task_lock(task);
		s = splsched();
		queue_enter(list, cur_thread, thread_t, thread_list);
		(void) splx(s);
		task_unlock(task);
		(void) thread_terminate(cur_thread);
	}

	return KERN_SUCCESS;
}

/*
 *	task_hold:
 *
 *	Suspend execution of the specified task.
 *	This is a recursive-style suspension of the task, a count of
 *	suspends is maintained.
 *
 *	CONDITIONS: the task is locked and active.
 */
void task_hold_locked(
	task_t	task)
{
	queue_head_t	*list;
	thread_t	thread, cur_thread;

	assert(task->active);

	cur_thread = current_thread();

	task->suspend_count++;

	/*
	 *	Iterate through all the threads and hold them.
	 *	Do not hold the current thread if it is within the
	 *	task.
	 */
	list = &task->thread_list;
	queue_iterate(list, thread, thread_t, thread_list) {
		if (thread != cur_thread)
			thread_hold(thread);
	}
}

/*
 *	task_hold:
 *
 *	Suspend execution of the specified task.
 *	This is a recursive-style suspension of the task, a count of
 *	suspends is maintained.
 */
kern_return_t task_hold(
	task_t	task)
{
	task_lock(task);
	if (!task->active) {
		task_unlock(task);
		return KERN_FAILURE;
	}

	task_hold_locked(task);

	task_unlock(task);
	return KERN_SUCCESS;
}

/*
 *	task_dowait:
 *
 *	Wait until the task has really been suspended (all of the threads
 *	are stopped).  Skip the current thread if it is within the task.
 *
 *	If task is deactivated while waiting, return a failure code unless
 *	must_wait is true.
 */
kern_return_t task_dowait(
	task_t	task,
	boolean_t must_wait)
{
	queue_head_t	*list;
	thread_t	thread, cur_thread, prev_thread;
	kern_return_t	ret = KERN_SUCCESS;

	/*
	 *	Iterate through all the threads.
	 *	While waiting for each thread, we gain a reference to it
	 *	to prevent it from going away on us.  This guarantees
	 *	that the "next" thread in the list will be a valid thread.
	 *
	 *	We depend on the fact that if threads are created while
	 *	we are looping through the threads, they will be held
	 *	automatically.  We don't care about threads that get
	 *	deallocated along the way (the reference prevents it
	 *	from happening to the thread we are working with).
	 *
	 *	If the current thread is in the affected task, it is skipped.
	 *
	 *	If the task is deactivated before we're done, and we don't
	 *	have to wait for it (must_wait is FALSE), just bail out.
	 */
	cur_thread = current_thread();

	list = &task->thread_list;
	prev_thread = THREAD_NULL;
	task_lock(task);
	queue_iterate(list, thread, thread_t, thread_list) {
		if (!(task->active) && !(must_wait)) {
			ret = KERN_FAILURE;
			break;
		}
		if (thread != cur_thread) {
			thread_reference(thread);
			task_unlock(task);
			if (prev_thread != THREAD_NULL)
				thread_deallocate(prev_thread);
							/* may block */
			(void) thread_dowait(thread, TRUE);  /* may block */
			prev_thread = thread;
			task_lock(task);
		}
	}
	task_unlock(task);
	if (prev_thread != THREAD_NULL)
		thread_deallocate(prev_thread);		/* may block */
	return ret;
}

kern_return_t task_release(
	task_t	task)
{
	queue_head_t	*list;
	thread_t	thread, next;

	task_lock(task);
	if (!task->active) {
		task_unlock(task);
		return KERN_FAILURE;
	}

	task->suspend_count--;

	/*
	 *	Iterate through all the threads and release them
	 */
	list = &task->thread_list;
	thread = (thread_t) queue_first(list);
	while (!queue_end(list, (queue_entry_t) thread)) {
		next = (thread_t) queue_next(&thread->thread_list);
		thread_release(thread);
		thread = next;
	}
	task_unlock(task);
	return KERN_SUCCESS;
}

kern_return_t task_threads(
	task_t		task,
	thread_array_t	*thread_list,
	natural_t	*count)
{
	unsigned int actual;	/* this many threads */
	thread_t thread;
	thread_t *threads;
	unsigned i;

	vm_size_t size, size_needed;
	vm_offset_t addr;

	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	size = 0; addr = 0;

	for (;;) {
		task_lock(task);
		if (!task->active) {
			task_unlock(task);
			return KERN_FAILURE;
		}

		actual = task->thread_count;

		/* do we have the memory we need? */

		size_needed = actual * sizeof(mach_port_t);
		if (size_needed <= size)
			break;

		/* unlock the task and allocate more memory */
		task_unlock(task);

		if (size != 0)
			kfree(addr, size);

		assert(size_needed > 0);
		size = size_needed;

		addr = kalloc(size);
		if (addr == 0)
			return KERN_RESOURCE_SHORTAGE;
	}

	/* OK, have memory and the task is locked & active */

	threads = (thread_t *) addr;

	for (i = 0, thread = (thread_t) queue_first(&task->thread_list);
	     i < actual;
	     i++, thread = (thread_t) queue_next(&thread->thread_list)) {
		/* take ref for convert_thread_to_port */
		thread_reference(thread);
		threads[i] = thread;
	}
	assert(queue_end(&task->thread_list, (queue_entry_t) thread));

	/* can unlock task now that we've got the thread refs */
	task_unlock(task);

	if (actual == 0) {
		/* no threads, so return null pointer and deallocate memory */

		*thread_list = 0;
		*count = 0;

		if (size != 0)
			kfree(addr, size);
	} else {
		/* if we allocated too much, must copy */

		if (size_needed < size) {
			vm_offset_t newaddr;

			newaddr = kalloc(size_needed);
			if (newaddr == 0) {
				for (i = 0; i < actual; i++)
					thread_deallocate(threads[i]);
				kfree(addr, size);
				return KERN_RESOURCE_SHORTAGE;
			}

			memcpy((void *) newaddr, (void *) addr, size_needed);
			kfree(addr, size);
			threads = (thread_t *) newaddr;
		}

		*thread_list = (mach_port_t *) threads;
		*count = actual;

		/* do the conversion that Mig should handle */

		for (i = 0; i < actual; i++)
			((ipc_port_t *) threads)[i] =
				convert_thread_to_port(threads[i]);
	}

	return KERN_SUCCESS;
}

kern_return_t task_suspend(
	task_t	task)
{
	boolean_t	hold;

	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	hold = FALSE;
	task_lock(task);
	if ((task->user_stop_count)++ == 0)
		hold = TRUE;
	task_unlock(task);

	/*
	 *	If the stop count was positive, the task is
	 *	already stopped and we can exit.
	 */
	if (!hold) {
		return KERN_SUCCESS;
	}

	/*
	 *	Hold all of the threads in the task, and wait for
	 *	them to stop.  If the current thread is within
	 *	this task, hold it separately so that all of the
	 *	other threads can stop first.
	 */

	if (task_hold(task) != KERN_SUCCESS)
		return KERN_FAILURE;

	if (task_dowait(task, FALSE) != KERN_SUCCESS)
		return KERN_FAILURE;

	if (current_task() == task) {
		spl_t s;

		thread_hold(current_thread());
		/*
		 *	We want to call thread_block on our way out,
		 *	to stop running.
		 */
		s = splsched();
		ast_on(cpu_number(), AST_BLOCK);
		(void) splx(s);
	}

	return KERN_SUCCESS;
}

kern_return_t task_resume(
	task_t	task)
{
	boolean_t	release;

	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	release = FALSE;
	task_lock(task);
	if (task->user_stop_count > 0) {
		if (--(task->user_stop_count) == 0)
	    		release = TRUE;
	}
	else {
		task_unlock(task);
		return KERN_FAILURE;
	}
	task_unlock(task);

	/*
	 *	Release the task if necessary.
	 */
	if (release)
		return task_release(task);

	return KERN_SUCCESS;
}

kern_return_t task_info(
	task_t			task,
	int			flavor,
	task_info_t		task_info_out,	/* pointer to OUT array */
	natural_t		*task_info_count)	/* IN/OUT */
{
	vm_map_t		map;

	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	switch (flavor) {
	    case TASK_BASIC_INFO:
	    {
		task_basic_info_t	basic_info;

		/* Allow *task_info_count to be smaller than the provided amount
		 * that does not contain the new time_value64_t fields as some
		 * callers might not know about them yet. */

		if (*task_info_count <
				TASK_BASIC_INFO_COUNT - 3 * sizeof(time_value64_t)/sizeof(integer_t))
		    return KERN_INVALID_ARGUMENT;

		basic_info = (task_basic_info_t) task_info_out;

		map = (task == kernel_task) ? kernel_map : task->map;

		basic_info->virtual_size  = map->size;
		basic_info->resident_size = ((rpc_vm_size_t) pmap_resident_count(map->pmap))
						   * PAGE_SIZE;

		task_lock(task);
		basic_info->base_priority = task->priority;
		basic_info->suspend_count = task->user_stop_count;
		TIME_VALUE64_TO_TIME_VALUE(&task->total_user_time,
				&basic_info->user_time);
		TIME_VALUE64_TO_TIME_VALUE(&task->total_system_time,
				&basic_info->system_time);
		time_value64_t creation_time64;
		read_time_stamp(&task->creation_time, &creation_time64);
		TIME_VALUE64_TO_TIME_VALUE(&creation_time64, &basic_info->creation_time);
		if (*task_info_count == TASK_BASIC_INFO_COUNT) {
		    /* Copy new time_value64_t fields */
		    basic_info->user_time64 = task->total_user_time;
		    basic_info->system_time64 = task->total_system_time;
		    basic_info->creation_time64 = creation_time64;
		}
		task_unlock(task);

		if (*task_info_count > TASK_BASIC_INFO_COUNT)
		  *task_info_count = TASK_BASIC_INFO_COUNT;
		break;
	    }

	    case TASK_EVENTS_INFO:
	    {
		task_events_info_t	event_info;

		if (*task_info_count < TASK_EVENTS_INFO_COUNT) {
		    return KERN_INVALID_ARGUMENT;
		}

		event_info = (task_events_info_t) task_info_out;

		task_lock(task);
		event_info->faults = task->faults;
		event_info->zero_fills = task->zero_fills;
		event_info->reactivations = task->reactivations;
		event_info->pageins = task->pageins;
		event_info->cow_faults = task->cow_faults;
		event_info->messages_sent = task->messages_sent;
		event_info->messages_received = task->messages_received;
		task_unlock(task);

		*task_info_count = TASK_EVENTS_INFO_COUNT;
		break;
	    }

	    case TASK_THREAD_TIMES_INFO:
	    {
		task_thread_times_info_t times_info;
		thread_t	thread;

		/* Callers might not known about time_value64_t fields yet. */
		if (*task_info_count < TASK_THREAD_TIMES_INFO_COUNT - (2 * sizeof(time_value64_t)) / sizeof(integer_t)) {
		    return KERN_INVALID_ARGUMENT;
		}

		times_info = (task_thread_times_info_t) task_info_out;

		time_value64_t acc_user_time, acc_system_time;
		time_value64_init(&acc_user_time);
		time_value64_init(&acc_system_time);

		task_lock(task);
		queue_iterate(&task->thread_list, thread,
			      thread_t, thread_list)
		{
		    time_value64_t user_time, system_time;
		    spl_t		 s;

		    s = splsched();
		    thread_lock(thread);

		    thread_read_times(thread, &user_time, &system_time);

		    thread_unlock(thread);
		    splx(s);

		    time_value64_add(&acc_user_time, &user_time);
		    time_value64_add(&acc_system_time, &system_time);
		}
		task_unlock(task);
		TIME_VALUE64_TO_TIME_VALUE(&acc_user_time, &times_info->user_time);
		TIME_VALUE64_TO_TIME_VALUE(&acc_system_time, &times_info->system_time);
		if (*task_info_count >= TASK_THREAD_TIMES_INFO_COUNT) {
		    /* Copy new time_value64_t fields */
		    times_info->user_time64 = acc_user_time;
		    times_info->system_time64 = acc_system_time;
		}

		if (*task_info_count > TASK_THREAD_TIMES_INFO_COUNT)
		  *task_info_count = TASK_THREAD_TIMES_INFO_COUNT;
		break;
	    }

	    default:
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

#if	MACH_HOST
/*
 *	task_assign:
 *
 *	Change the assigned processor set for the task
 */
kern_return_t
task_assign(
	task_t		task,
	processor_set_t	new_pset,
	boolean_t	assign_threads)
{
	kern_return_t		ret = KERN_SUCCESS;
	thread_t	thread, prev_thread;
	queue_head_t	*list;
	processor_set_t	pset;

	if (task == TASK_NULL || new_pset == PROCESSOR_SET_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Freeze task`s assignment.  Prelude to assigning
	 *	task.  Only one freeze may be held per task.
	 */

	task_lock(task);
	while (task->may_assign == FALSE) {
		task->assign_active = TRUE;
		assert_wait((event_t)&task->assign_active, TRUE);
		task_unlock(task);
		thread_block(thread_no_continuation);
		task_lock(task);
	}

	/*
	 *	Avoid work if task already in this processor set.
	 */
	if (task->processor_set == new_pset)  {
		/*
		 *	No need for task->assign_active wakeup:
		 *	task->may_assign is still TRUE.
		 */
		task_unlock(task);
		return KERN_SUCCESS;
	}

	task->may_assign = FALSE;
	task_unlock(task);

	/*
	 *	Safe to get the task`s pset: it cannot change while
	 *	task is frozen.
	 */
	pset = task->processor_set;

	/*
	 *	Lock both psets now.  Use ordering to avoid deadlock.
	 */
    Restart:
	if ((vm_offset_t) pset < (vm_offset_t) new_pset) {
	    pset_lock(pset);
	    pset_lock(new_pset);
	}
	else {
	    pset_lock(new_pset);
	    pset_lock(pset);
	}

	/*
	 *	Check if new_pset is ok to assign to.  If not,
	 *	reassign to default_pset.
	 */
	if (!new_pset->active) {
	    pset_unlock(pset);
	    pset_unlock(new_pset);
	    new_pset = &default_pset;
	    goto Restart;
	}

	pset_reference(new_pset);

	/*
	 *	Now grab the task lock and move the task.
	 */

	task_lock(task);
	pset_remove_task(pset, task);
	pset_add_task(new_pset, task);

	pset_unlock(pset);
	pset_unlock(new_pset);

	if (assign_threads == FALSE) {
		/*
		 *	We leave existing threads at their
		 *	old assignments.  Unfreeze task`s
		 *	assignment.
		 */
		task->may_assign = TRUE;
		if (task->assign_active) {
			task->assign_active = FALSE;
			thread_wakeup((event_t) &task->assign_active);
		}
		task_unlock(task);
		pset_deallocate(pset);
		return KERN_SUCCESS;
	}

	/*
	 *	If current thread is in task, freeze its assignment.
	 */
	if (current_thread()->task == task) {
		task_unlock(task);
		thread_freeze(current_thread());
		task_lock(task);
	}

	/*
	 *	Iterate down the thread list reassigning all the threads.
	 *	New threads pick up task's new processor set automatically.
	 *	Do current thread last because new pset may be empty.
	 */
	list = &task->thread_list;
	prev_thread = THREAD_NULL;
	queue_iterate(list, thread, thread_t, thread_list) {
		if (!(task->active)) {
			ret = KERN_FAILURE;
			break;
		}
		if (thread != current_thread()) {
			thread_reference(thread);
			task_unlock(task);
			if (prev_thread != THREAD_NULL)
			    thread_deallocate(prev_thread); /* may block */
			thread_assign(thread,new_pset);	    /* may block */
			prev_thread = thread;
			task_lock(task);
		}
	}

	/*
	 *	Done, wakeup anyone waiting for us.
	 */
	task->may_assign = TRUE;
	if (task->assign_active) {
		task->assign_active = FALSE;
		thread_wakeup((event_t)&task->assign_active);
	}
	task_unlock(task);
	if (prev_thread != THREAD_NULL)
		thread_deallocate(prev_thread);		/* may block */

	/*
	 *	Finish assignment of current thread.
	 */
	if (current_thread()->task == task)
		thread_doassign(current_thread(), new_pset, TRUE);

	pset_deallocate(pset);

	return ret;
}
#else	/* MACH_HOST */
/*
 *	task_assign:
 *
 *	Change the assigned processor set for the task
 */
kern_return_t
task_assign(
	task_t		task,
	processor_set_t	new_pset,
	boolean_t	assign_threads)
{
	return KERN_FAILURE;
}
#endif	/* MACH_HOST */


/*
 *	task_assign_default:
 *
 *	Version of task_assign to assign to default processor set.
 */
kern_return_t
task_assign_default(
	task_t		task,
	boolean_t	assign_threads)
{
	return task_assign(task, &default_pset, assign_threads);
}

/*
 *	task_get_assignment
 *
 *	Return name of processor set that task is assigned to.
 */
kern_return_t task_get_assignment(
	task_t		task,
	processor_set_t	*pset)
{
	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	if (!task->active)
		return KERN_FAILURE;

	*pset = task->processor_set;
	pset_reference(*pset);
	return KERN_SUCCESS;
}

/*
 *	task_priority
 *
 *	Set priority of task; used only for newly created threads.
 *	Optionally change priorities of threads.
 */
kern_return_t
task_priority(
	task_t		task,
	int		priority,
	boolean_t	change_threads)
{
	kern_return_t	ret = KERN_SUCCESS;

	if (task == TASK_NULL || invalid_pri(priority))
		return KERN_INVALID_ARGUMENT;

	task_lock(task);
	task->priority = priority;

	if (change_threads) {
		thread_t	thread;
		queue_head_t	*list;

		list = &task->thread_list;
		queue_iterate(list, thread, thread_t, thread_list) {
			if (thread_priority(thread, priority, FALSE)
				!= KERN_SUCCESS)
					ret = KERN_FAILURE;
		}
	}

	task_unlock(task);
	return ret;
}

/*
 *	task_set_name
 *
 *	Set the name of task TASK to NAME.  This is a debugging aid.
 *	NAME will be used in error messages printed by the kernel.
 */
kern_return_t
task_set_name(
	task_t			task,
	const_kernel_debug_name_t	name)
{
	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	strncpy(task->name, name, sizeof task->name - 1);
	task->name[sizeof task->name - 1] = '\0';
	return KERN_SUCCESS;
}

/*
 *	task_set_essential
 *
 *	Set whether TASK is an essential task, i.e. the whole system will crash
 *	if this task crashes.
 */
kern_return_t
task_set_essential(
	task_t			task,
	boolean_t		essential)
{
	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	task->essential = !!essential;
	return KERN_SUCCESS;
}

/*
 *	task_collect_scan:
 *
 *	Attempt to free resources owned by tasks.
 */

static void task_collect_scan(void)
{
	task_t			task, prev_task;
	processor_set_t		pset, prev_pset;

	prev_task = TASK_NULL;
	prev_pset = PROCESSOR_SET_NULL;

	simple_lock(&all_psets_lock);
	queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
		pset_lock(pset);
		queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
			task_reference(task);
			pset_reference(pset);
			pset_unlock(pset);
			simple_unlock(&all_psets_lock);

			machine_task_collect (task);
			pmap_collect(task->map->pmap);

			if (prev_task != TASK_NULL)
				task_deallocate(prev_task);
			prev_task = task;

			if (prev_pset != PROCESSOR_SET_NULL)
				pset_deallocate(prev_pset);
			prev_pset = pset;

			simple_lock(&all_psets_lock);
			pset_lock(pset);
		}
		pset_unlock(pset);
	}
	simple_unlock(&all_psets_lock);

	if (prev_task != TASK_NULL)
		task_deallocate(prev_task);
	if (prev_pset != PROCESSOR_SET_NULL)
		pset_deallocate(prev_pset);
}

boolean_t task_collect_allowed = TRUE;
unsigned task_collect_last_tick = 0;
unsigned task_collect_max_rate = 0;		/* in ticks */

/*
 *	consider_task_collect:
 *
 *	Called by the pageout daemon when the system needs more free pages.
 */

void consider_task_collect(void)
{
	/*
	 *	By default, don't attempt task collection more frequently
	 *	than once a second.
	 */

	if (task_collect_max_rate == 0)
		task_collect_max_rate = hz;

	if (task_collect_allowed &&
	    (sched_tick > (task_collect_last_tick +
			   task_collect_max_rate / (hz / 1)))) {
		task_collect_last_tick = sched_tick;
		task_collect_scan();
	}
}

kern_return_t
task_ras_control(
 	task_t task,
 	vm_offset_t pc,
 	vm_offset_t endpc,
	int flavor)
{
    kern_return_t ret = KERN_FAILURE;

#if	FAST_TAS
    int i;

    ret = KERN_SUCCESS;
    task_lock(task);
    switch (flavor)  {
    case TASK_RAS_CONTROL_PURGE_ALL:  /* remove all RAS */
	for (i = 0; i < TASK_FAST_TAS_NRAS; i++) {
	    task->fast_tas_base[i] = task->fast_tas_end[i] = 0;
	}
	break;
    case TASK_RAS_CONTROL_PURGE_ONE:  /* remove this RAS, collapse remaining */
	for (i = 0; i < TASK_FAST_TAS_NRAS; i++)  {
	    if ( (task->fast_tas_base[i] == pc)
		&& (task->fast_tas_end[i] == endpc))  {
			while (i < TASK_FAST_TAS_NRAS-1)  {
	    		  task->fast_tas_base[i] = task->fast_tas_base[i+1];
	    		  task->fast_tas_end[i] = task->fast_tas_end[i+1];
			  i++;
			 }
	    		task->fast_tas_base[TASK_FAST_TAS_NRAS-1] = 0;
	    		task->fast_tas_end[TASK_FAST_TAS_NRAS-1] = 0;
			break;
	     }
	}
	if (i == TASK_FAST_TAS_NRAS) {
	    ret = KERN_INVALID_ADDRESS;
	}
	break;
    case TASK_RAS_CONTROL_PURGE_ALL_AND_INSTALL_ONE:
	/* remove all RAS an install this RAS */
	for (i = 0; i < TASK_FAST_TAS_NRAS; i++) {
	    task->fast_tas_base[i] = task->fast_tas_end[i] = 0;
	}
	/* FALL THROUGH */
    case TASK_RAS_CONTROL_INSTALL_ONE: /* install this RAS */
	for (i = 0; i < TASK_FAST_TAS_NRAS; i++)  {
	    if ( (task->fast_tas_base[i] == pc)
	    && (task->fast_tas_end[i] == endpc))   {
		/* already installed */
		break;
	    }
	    if ((task->fast_tas_base[i] == 0) && (task->fast_tas_end[i] == 0)){
		task->fast_tas_base[i] = pc;
		task->fast_tas_end[i] = endpc;
		break;
	    }
	}
	if (i == TASK_FAST_TAS_NRAS)  {
	    ret = KERN_RESOURCE_SHORTAGE;
	}
	break;
    default: ret = KERN_INVALID_VALUE;
	break;
    }
    task_unlock(task);
#endif /* FAST_TAS */
    return ret;
}

/*
 *	register_new_task_notification
 *
 *	Register a port to which a notification about newly created
 *	tasks are sent.
 */
kern_return_t
register_new_task_notification(
	const host_t host,
	ipc_port_t notification)
{
	if (host == HOST_NULL)
		return KERN_INVALID_HOST;

	if (new_task_notification != NULL)
		return KERN_NO_ACCESS;

	new_task_notification = notification;
	return KERN_SUCCESS;
}

kern_return_t task_terminate_with_status(
    task_t      task,
    int         exit_status)
{
    thread_t        thread, cur_thread;
    queue_head_t    *list;
    task_t          cur_task;
    spl_t           s;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    /* Set exit status before termination */
    task_lock(task);
    task->exit_status = exit_status;
    task->is_terminating = TRUE;
    task_unlock(task);
    
    return task_terminate(task);
}

/*
 * task_wait
 *
 * Wait for a task to terminate (like waitpid for tasks).
 */
kern_return_t task_wait(
    task_t      task,
    int         *exit_status,
    boolean_t   wait_all)
{
    spl_t s;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    
    while (task->active && !task->is_terminating) {
        task->assign_active = TRUE;  /* Reuse flag for waiting */
        assert_wait((event_t)&task->active, TRUE);
        task_unlock(task);
        thread_block(thread_no_continuation);
        task_lock(task);
    }
    
    if (exit_status != NULL)
        *exit_status = task->exit_status;
    
    if (task->assign_active) {
        task->assign_active = FALSE;
        thread_wakeup((event_t)&task->assign_active);
    }
    
    task_unlock(task);
    return KERN_SUCCESS;
}

/*
 * task_get_cpu_usage
 *
 * Get total CPU usage for a task including all threads.
 */
kern_return_t task_get_cpu_usage(
    task_t                  task,
    struct time_value64     *user_time,
    struct time_value64     *system_time)
{
    thread_t thread;
    struct time_value64 total_user, total_system;
    
    if (task == TASK_NULL || user_time == NULL || system_time == NULL)
        return KERN_INVALID_ARGUMENT;
    
    time_value64_init(&total_user);
    time_value64_init(&total_system);
    
    task_lock(task);
    
    /* Add task's own times */
    time_value64_add(&total_user, &task->total_user_time);
    time_value64_add(&total_system, &task->total_system_time);
    
    /* Add all thread times */
    queue_iterate(&task->thread_list, thread, thread_t, thread_list) {
        struct time_value64 thread_user, thread_system;
        spl_t s;
        
        s = splsched();
        thread_lock(thread);
        thread_read_times(thread, &thread_user, &thread_system);
        thread_unlock(thread);
        splx(s);
        
        time_value64_add(&total_user, &thread_user);
        time_value64_add(&total_system, &thread_system);
    }
    
    task_unlock(task);
    
    *user_time = total_user;
    *system_time = total_system;
    
    return KERN_SUCCESS;
}

/*
 * task_get_statistics
 *
 * Get comprehensive task statistics.
 */
kern_return_t task_get_statistics(
    task_t              task,
    unsigned int        *page_faults,
    unsigned int        *context_switches,
    unsigned int        *thread_count)
{
    thread_t thread;
    unsigned int total_switches = 0;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    
    if (page_faults != NULL)
        *page_faults = task->faults;
    
    if (thread_count != NULL)
        *thread_count = task->thread_count;
    
    /* Sum context switches from all threads */
    if (context_switches != NULL) {
        queue_iterate(&task->thread_list, thread, thread_t, thread_list) {
            spl_t s;
            s = splsched();
            thread_lock(thread);
            total_switches += thread->context_switches;
            thread_unlock(thread);
            splx(s);
        }
        *context_switches = total_switches;
    }
    
    task_unlock(task);
    return KERN_SUCCESS;
}

/*
 * task_suspend_all_but_self
 *
 * Suspend all threads in task except the current thread.
 */
kern_return_t task_suspend_all_but_self(task_t task)
{
    queue_head_t *list;
    thread_t thread, cur_thread;
    int suspended_count = 0;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    cur_thread = current_thread();
    
    task_lock(task);
    if (!task->active) {
        task_unlock(task);
        return KERN_FAILURE;
    }
    
    task->suspend_count++;
    
    list = &task->thread_list;
    queue_iterate(list, thread, thread_t, thread_list) {
        if (thread != cur_thread) {
            thread_hold(thread);
            suspended_count++;
        }
    }
    
    task_unlock(task);
    
    /* Wait for suspended threads to actually stop */
    if (suspended_count > 0) {
        task_dowait(task, FALSE);
    }
    
    return KERN_SUCCESS;
}

/*
 * task_resume_all
 *
 * Resume all suspended threads in a task.
 */
kern_return_t task_resume_all(task_t task)
{
    queue_head_t *list;
    thread_t thread;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    if (!task->active || task->suspend_count == 0) {
        task_unlock(task);
        return KERN_FAILURE;
    }
    
    task->suspend_count--;
    
    list = &task->thread_list;
    queue_iterate(list, thread, thread_t, thread_list) {
        thread_release(thread);
    }
    
    task_unlock(task);
    return KERN_SUCCESS;
}

/*
 * task_get_thread_count
 *
 * Get the number of threads in a task.
 */
kern_return_t task_get_thread_count(
    task_t      task,
    natural_t   *count)
{
    if (task == TASK_NULL || count == NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    *count = task->thread_count;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_is_alive
 *
 * Check if a task is still alive and active.
 */
boolean_t task_is_alive(task_t task)
{
    boolean_t alive;
    
    if (task == TASK_NULL)
        return FALSE;
    
    task_lock(task);
    alive = task->active && !task->is_terminating;
    task_unlock(task);
    
    return alive;
}

/*
 * task_set_exception_port
 *
 * Set the exception port for a task.
 */
kern_return_t task_set_exception_port(
    task_t      task,
    ipc_port_t  exception_port)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    
    if (task->exception_port != NULL)
        ipc_port_release(task->exception_port);
    
    if (exception_port != NULL)
        ipc_port_reference(exception_port);
    
    task->exception_port = exception_port;
    
    task_unlock(task);
    return KERN_SUCCESS;
}

/*
 * task_has_exceptions
 *
 * Check if a task has exceptions pending.
 */
boolean_t task_has_exceptions(task_t task)
{
    thread_t thread;
    boolean_t has_exceptions = FALSE;
    
    if (task == TASK_NULL)
        return FALSE;
    
    task_lock(task);
    
    queue_iterate(&task->thread_list, thread, thread_t, thread_list) {
        if (thread->has_exception) {
            has_exceptions = TRUE;
            break;
        }
    }
    
    task_unlock(task);
    return has_exceptions;
}

/*
 * task_cleanup_zombies
 *
 * Clean up terminated tasks that are waiting for resources.
 */
void task_cleanup_zombies(void)
{
    task_t task, next_task;
    static queue_head_t zombie_tasks;
    static boolean_t initialized = FALSE;
    
    if (!initialized) {
        queue_init(&zombie_tasks);
        initialized = TRUE;
    }
    
    /* Process zombie tasks */
    task_lock(kernel_task);  /* Lock for zombie queue */
    
    queue_iterate_safe(&zombie_tasks, task, next_task, task_t, zombie_chain) {
        if (task->ref_count == 0) {
            queue_remove(&zombie_tasks, task, task_t, zombie_chain);
            task_unlock(kernel_task);
            
            /* Final cleanup */
            kmem_cache_free(&task_cache, (vm_offset_t)task);
            
            task_lock(kernel_task);
        }
    }
    
    task_unlock(kernel_task);
}

/*
 * Enhanced task_create with more initialization
 */
kern_return_t task_create_enhanced(
    task_t      parent_task,
    boolean_t   inherit_memory,
    int         priority,
    task_t      *child_task)
{
    kern_return_t kr;
    task_t new_task;
    
    kr = task_create_kernel(parent_task, inherit_memory, &new_task);
    if (kr != KERN_SUCCESS)
        return kr;
    
    /* Set priority if specified */
    if (priority != -1) {
        task_priority(new_task, priority, FALSE);
    }
    
    /* Initialize additional fields */
    task_lock(new_task);
    new_task->exit_status = 0;
    new_task->is_terminating = FALSE;
    new_task->exception_port = NULL;
    new_task->page_fault_count = 0;
    new_task->context_switches = 0;
    task_unlock(new_task);
    
    *child_task = new_task;
    return KERN_SUCCESS;
}

/*
 * task_print_info
 *
 * Print debug information about a task.
 */
void task_print_info(task_t task)
{
    if (task == TASK_NULL) {
        printf("Task: NULL\n");
        return;
    }
    
    printf("Task: %p\n", task);
    printf("  Name: %s\n", task->name);
    printf("  Active: %s\n", task->active ? "yes" : "no");
    printf("  Terminating: %s\n", task->is_terminating ? "yes" : "no");
    printf("  Thread count: %d\n", task->thread_count);
    printf("  Ref count: %d\n", task->ref_count);
    printf("  Suspend count: %d\n", task->suspend_count);
    printf("  User stop count: %d\n", task->user_stop_count);
    printf("  Priority: %d\n", task->priority);
    printf("  Essential: %s\n", task->essential ? "yes" : "no");
    printf("  Faults: %d\n", task->faults);
    printf("  Pageins: %d\n", task->pageins);
    
    if (task->map != VM_MAP_NULL) {
        printf("  Map size: 0x%llx\n", (unsigned long long)task->map->size);
    }
}

/*
 * task_validate
 *
 * Validate task structure integrity (for debugging).
 */
boolean_t task_validate(task_t task)
{
    if (task == NULL || task == TASK_NULL)
        return FALSE;
    
    /* Basic sanity checks */
    if (task->ref_count == 0 && task->active)
        return FALSE;
    
    if (task->thread_count < 0)
        return FALSE;
    
    if (task->suspend_count < 0)
        return FALSE;
    
    if (task->user_stop_count < 0)
        return FALSE;
    
    /* Validate map */
    if (task->map == VM_MAP_NULL && task != kernel_task)
        return FALSE;
    
    return TRUE;
}

/*
 * task_set_priority_ceiling
 *
 * Set the priority ceiling for priority inheritance protocol.
 */
kern_return_t task_set_priority_ceiling(
    task_t      task,
    int         ceiling)
{
    if (task == TASK_NULL || invalid_pri(ceiling))
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->priority_ceiling = ceiling;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_set_cpu_affinity
 *
 * Set CPU affinity mask for the task.
 */
kern_return_t task_set_cpu_affinity(
    task_t          task,
    unsigned int    cpu_mask)
{
    thread_t thread;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->cpu_affinity_mask = cpu_mask;
    
    /* Apply to all threads */
    queue_iterate(&task->thread_list, thread, thread_t, thread_list) {
        spl_t s = splsched();
        thread_lock(thread);
        thread->cpu_affinity_mask = cpu_mask;
        thread_unlock(thread);
        splx(s);
    }
    
    task_unlock(task);
    return KERN_SUCCESS;
}

/*
 * task_set_memory_limit
 *
 * Set memory usage limit for the task.
 */
kern_return_t task_set_memory_limit(
    task_t          task,
    unsigned long   limit)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->memory_limit = limit;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_check_memory_limit
 *
 * Check if adding memory would exceed limit.
 */
boolean_t task_check_memory_limit(
    task_t          task,
    unsigned long   additional)
{
    boolean_t within_limit;
    
    if (task == TASK_NULL)
        return FALSE;
    
    task_lock(task);
    if (task->memory_limit == 0) {
        within_limit = TRUE;  /* No limit */
    } else {
        within_limit = (task->current_memory + additional) <= task->memory_limit;
    }
    task_unlock(task);
    
    return within_limit;
}

/*
 * task_update_memory_usage
 *
 * Update task's current memory usage.
 */
void task_update_memory_usage(
    task_t          task,
    long            delta)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    if (delta > 0) {
        task->current_memory += delta;
    } else if (delta < 0 && task->current_memory >= (unsigned long)(-delta)) {
        task->current_memory += delta;  /* delta is negative */
    } else if (delta < 0) {
        task->current_memory = 0;
    }
    task_unlock(task);
}

/*
 * task_get_resource_usage
 *
 * Get detailed resource usage for a task.
 */
kern_return_t task_get_resource_usage(
    task_t              task,
    struct task_rusage  *rusage)
{
    thread_t thread;
    
    if (task == TASK_NULL || rusage == NULL)
        return KERN_INVALID_ARGUMENT;
    
    memset(rusage, 0, sizeof(struct task_rusage));
    
    task_lock(task);
    
    /* Copy task-level usage */
    rusage->ru_utime = task->total_user_time;
    rusage->ru_stime = task->total_system_time;
    rusage->ru_majflt = task->faults;
    rusage->ru_minflt = task->zero_fills;
    rusage->ru_nvcsw = task->voluntary_switches;
    rusage->ru_nivcsw = task->involuntary_switches;
    
    /* Accumulate thread-level usage */
    queue_iterate(&task->thread_list, thread, thread_t, thread_list) {
        spl_t s = splsched();
        thread_lock(thread);
        
        rusage->ru_utime = time_value64_add(rusage->ru_utime, thread->user_time);
        rusage->ru_stime = time_value64_add(rusage->ru_stime, thread->system_time);
        rusage->ru_nvcsw += thread->voluntary_switches;
        rusage->ru_nivcsw += thread->involuntary_switches;
        
        thread_unlock(thread);
        splx(s);
    }
    
    rusage->ru_maxrss = task->current_memory / 1024;  /* In KB */
    rusage->ru_idrss = task->current_memory / 1024;
    
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_set_nice
 *
 * Set nice value for task scheduling.
 */
kern_return_t task_set_nice(
    task_t  task,
    int     nice)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    if (nice < -20 || nice > 20)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->nice_value = nice;
    
    /* Adjust priority based on nice value */
    task->priority = BASEPRI_USER + (nice * PRIORITY_STEP);
    if (task->priority < MINPRI_USER)
        task->priority = MINPRI_USER;
    if (task->priority > MAXPRI_USER)
        task->priority = MAXPRI_USER;
    
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_get_nice
 *
 * Get nice value of task.
 */
int task_get_nice(task_t task)
{
    int nice;
    
    if (task == TASK_NULL)
        return 0;
    
    task_lock(task);
    nice = task->nice_value;
    task_unlock(task);
    
    return nice;
}

/*
 * task_set_scheduling_policy
 *
 * Set scheduling policy for the task.
 */
kern_return_t task_set_scheduling_policy(
    task_t      task,
    unsigned int policy)
{
    thread_t thread;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    /* Validate policy */
    if (policy != SCHED_OTHER && policy != SCHED_FIFO && policy != SCHED_RR)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->scheduling_policy = policy;
    
    /* Apply to all threads */
    queue_iterate(&task->thread_list, thread, thread_t, thread_list) {
        spl_t s = splsched();
        thread_lock(thread);
        thread->sched_policy = policy;
        thread_unlock(thread);
        splx(s);
    }
    
    task_unlock(task);
    return KERN_SUCCESS;
}

/*
 * task_signal
 *
 * Send a signal to a task.
 */
kern_return_t task_signal(
    task_t      task,
    unsigned int signal)
{
    thread_t thread;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    if (signal >= 32)  /* Valid signal range */
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    
    /* Set signal pending */
    task->signal_pending |= (1 << signal);
    
    /* Wake up a thread to handle the signal */
    if (!queue_empty(&task->thread_list)) {
        thread = (thread_t) queue_first(&task->thread_list);
        thread_reference(thread);
        task_unlock(task);
        
        thread_wakeup_one(thread);
        thread_deallocate(thread);
    } else {
        task_unlock(task);
    }
    
    return KERN_SUCCESS;
}

/*
 * task_clear_signal
 *
 * Clear a pending signal.
 */
void task_clear_signal(
    task_t      task,
    unsigned int signal)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->signal_pending &= ~(1 << signal);
    task_unlock(task);
}

/*
 * task_has_pending_signals
 *
 * Check if task has pending signals.
 */
boolean_t task_has_pending_signals(task_t task)
{
    boolean_t has_signals;
    
    if (task == TASK_NULL)
        return FALSE;
    
    task_lock(task);
    has_signals = (task->signal_pending != 0);
    task_unlock(task);
    
    return has_signals;
}

/*
 * task_create_child_relationship
 *
 * Establish parent-child relationship between tasks.
 */
kern_return_t task_create_child_relationship(
    task_t  parent,
    task_t  child)
{
    if (parent == TASK_NULL || child == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(parent);
    task_lock(child);
    
    /* Set parent */
    child->parent = parent;
    task_reference(parent);
    
    /* Add to children list */
    queue_enter(&parent->children, child, task_t, sibling);
    
    task_unlock(child);
    task_unlock(parent);
    
    return KERN_SUCCESS;
}

/*
 * task_get_parent
 *
 * Get parent task of the given task.
 */
task_t task_get_parent(task_t task)
{
    task_t parent;
    
    if (task == TASK_NULL)
        return TASK_NULL;
    
    task_lock(task);
    parent = task->parent;
    if (parent != TASK_NULL)
        task_reference(parent);
    task_unlock(task);
    
    return parent;
}

/*
 * task_get_children
 *
 * Get list of child tasks.
 */
kern_return_t task_get_children(
    task_t      task,
    task_t      **children,
    unsigned int *count)
{
    task_t child;
    task_t *child_array;
    unsigned int num_children = 0;
    unsigned int i;
    
    if (task == TASK_NULL || children == NULL || count == NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    
    /* Count children */
    queue_iterate(&task->children, child, task_t, sibling) {
        num_children++;
    }
    
    if (num_children == 0) {
        task_unlock(task);
        *children = NULL;
        *count = 0;
        return KERN_SUCCESS;
    }
    
    /* Allocate array */
    child_array = (task_t *) kalloc(num_children * sizeof(task_t));
    if (child_array == NULL) {
        task_unlock(task);
        return KERN_RESOURCE_SHORTAGE;
    }
    
    /* Fill array */
    i = 0;
    queue_iterate(&task->children, child, task_t, sibling) {
        task_reference(child);
        child_array[i++] = child;
    }
    
    task_unlock(task);
    
    *children = child_array;
    *count = num_children;
    
    return KERN_SUCCESS;
}

/*
 * task_wait_for_children
 *
 * Wait for all child tasks to terminate.
 */
kern_return_t task_wait_for_children(task_t task)
{
    task_t child;
    kern_return_t kr = KERN_SUCCESS;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    
    queue_iterate(&task->children, child, task_t, sibling) {
        task_reference(child);
        task_unlock(task);
        
        /* Wait for child to terminate */
        kr = task_wait(child, NULL, FALSE);
        if (kr != KERN_SUCCESS) {
            task_deallocate(child);
            return kr;
        }
        
        task_deallocate(child);
        task_lock(task);
    }
    
    task_unlock(task);
    return KERN_SUCCESS;
}

/*
 * task_orphan_children
 *
 * Orphan all child tasks (reparent to init task).
 */
void task_orphan_children(task_t task)
{
    task_t child, next_child;
    extern task_t init_task;
    
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    
    queue_iterate_safe(&task->children, child, next_child, task_t, sibling) {
        queue_remove(&task->children, child, task_t, sibling);
        
        task_lock(child);
        child->parent = init_task;
        task_unlock(child);
        
        if (init_task != TASK_NULL) {
            task_lock(init_task);
            queue_enter(&init_task->children, child, task_t, sibling);
            task_unlock(init_task);
        }
    }
    
    task_unlock(task);
}

/*
 * task_set_debug_flag
 *
 * Set debugging flags for a task.
 */
kern_return_t task_set_debug_flag(
    task_t          task,
    unsigned int    flag,
    boolean_t       set)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    if (set) {
        task->debug_flags |= flag;
    } else {
        task->debug_flags &= ~flag;
    }
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_get_debug_flags
 *
 * Get debugging flags of a task.
 */
unsigned int task_get_debug_flags(task_t task)
{
    unsigned int flags;
    
    if (task == TASK_NULL)
        return 0;
    
    task_lock(task);
    flags = task->debug_flags;
    task_unlock(task);
    
    return flags;
}

/*
 * task_print_debug_info
 *
 * Print detailed debug information about a task.
 */
void task_print_debug_info(task_t task)
{
    if (task == TASK_NULL) {
        printf("Task: NULL\n");
        return;
    }
    
    task_lock(task);
    
    printf("\n=== Task Debug Information ===\n");
    printf("Task: %p\n", task);
    printf("Name: %s\n", task->name);
    printf("Parent: %p\n", task->parent);
    printf("Active: %s\n", task->active ? "Yes" : "No");
    printf("Essential: %s\n", task->essential ? "Yes" : "No");
    printf("\n--- Scheduling ---\n");
    printf("Priority: %d\n", task->priority);
    printf("Nice: %d\n", task->nice_value);
    printf("Priority Ceiling: %d\n", task->priority_ceiling);
    printf("Scheduling Policy: %d\n", task->scheduling_policy);
    printf("CPU Affinity Mask: 0x%x\n", task->cpu_affinity_mask);
    printf("\n--- Memory ---\n");
    printf("Memory Limit: %lu bytes\n", task->memory_limit);
    printf("Current Memory: %lu bytes\n", task->current_memory);
    printf("Memory Usage: %lu%%\n", 
           task->memory_limit ? (task->current_memory * 100 / task->memory_limit) : 0);
    printf("\n--- Statistics ---\n");
    printf("Threads: %d\n", task->thread_count);
    printf("References: %d\n", task->ref_count);
    printf("Suspend Count: %d\n", task->suspend_count);
    printf("User Stop Count: %d\n", task->user_stop_count);
    printf("\n--- Faults ---\n");
    printf("Total Faults: %d\n", task->faults);
    printf("Zero Fills: %d\n", task->zero_fills);
    printf("Pageins: %d\n", task->pageins);
    printf("COW Faults: %d\n", task->cow_faults);
    printf("\n--- IPC ---\n");
    printf("Messages Sent: %d\n", task->messages_sent);
    printf("Messages Received: %d\n", task->messages_received);
    printf("\n--- Context Switches ---\n");
    printf("Voluntary: %d\n", task->voluntary_switches);
    printf("Involuntary: %d\n", task->involuntary_switches);
    printf("\n--- Signals ---\n");
    printf("Pending Signals: 0x%x\n", task->signal_pending);
    printf("\n--- Time ---\n");
    printf("User Time: %lld.%06lld\n", 
           task->total_user_time.seconds, task->total_user_time.microseconds);
    printf("System Time: %lld.%06lld\n", 
           task->total_system_time.seconds, task->total_system_time.microseconds);
    
    task_unlock(task);
}

/*
 * task_dump_all_tasks
 *
 * Dump information about all tasks in the system.
 */
void task_dump_all_tasks(void)
{
    processor_set_t pset;
    task_t task;
    
    printf("\n=== All Tasks Dump ===\n");
    printf("%-16s %-16s %-8s %-8s %-10s %-10s\n", 
           "Task", "Name", "Threads", "Active", "Memory(KB)", "Priority");
    printf("%-16s %-16s %-8s %-8s %-10s %-10s\n",
           "----------------", "----------------", "--------", "--------", 
           "----------", "----------");
    
    simple_lock(&all_psets_lock);
    queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
        pset_lock(pset);
        queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
            printf("%-16p %-16s %-8d %-8s %-10lu %-10d\n",
                   task, task->name, task->thread_count,
                   task->active ? "Yes" : "No",
                   task->current_memory / 1024,
                   task->priority);
        }
        pset_unlock(pset);
    }
    simple_unlock(&all_psets_lock);
}

/*
 * task_find_by_name
 *
 * Find a task by its name.
 */
task_t task_find_by_name(const char *name)
{
    processor_set_t pset;
    task_t task, found = TASK_NULL;
    
    if (name == NULL)
        return TASK_NULL;
    
    simple_lock(&all_psets_lock);
    queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
        pset_lock(pset);
        queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
            if (strcmp(task->name, name) == 0) {
                task_reference(task);
                found = task;
                pset_unlock(pset);
                simple_unlock(&all_psets_lock);
                return found;
            }
        }
        pset_unlock(pset);
    }
    simple_unlock(&all_psets_lock);
    
    return TASK_NULL;
}

/*
 * task_foreach
 *
 * Execute a function for each task in the system.
 */
void task_foreach(void (*func)(task_t, void *), void *arg)
{
    processor_set_t pset;
    task_t task;
    
    if (func == NULL)
        return;
    
    simple_lock(&all_psets_lock);
    queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
        pset_lock(pset);
        queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
            task_reference(task);
            pset_unlock(pset);
            simple_unlock(&all_psets_lock);
            
            func(task, arg);
            
            task_deallocate(task);
            simple_lock(&all_psets_lock);
            pset_lock(pset);
        }
        pset_unlock(pset);
    }
    simple_unlock(&all_psets_lock);
}

/*
 * task_account_context_switch
 *
 * Account for a context switch involving this task.
 */
void task_account_context_switch(
    task_t      task,
    boolean_t   voluntary)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    if (voluntary) {
        task->voluntary_switches++;
    } else {
        task->involuntary_switches++;
    }
    task->context_switches++;
    task_unlock(task);
}

/*
 * task_update_schedule_time
 *
 * Update the last schedule time for a task.
 */
void task_update_schedule_time(task_t task)
{
    struct time_value64 now;
    
    if (task == TASK_NULL)
        return;
    
    read_time_stamp(current_time(), &now);
    
    task_lock(task);
    task->last_schedule_time = now;
    task_unlock(task);
}

/*
 * task_get_scheduling_stats
 *
 * Get scheduling statistics for a task.
 */
kern_return_t task_get_scheduling_stats(
    task_t              task,
    struct time_value64 *last_scheduled,
    unsigned int        *voluntary_switches,
    unsigned int        *involuntary_switches)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    if (last_scheduled != NULL)
        *last_scheduled = task->last_schedule_time;
    if (voluntary_switches != NULL)
        *voluntary_switches = task->voluntary_switches;
    if (involuntary_switches != NULL)
        *involuntary_switches = task->involuntary_switches;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_reset_statistics
 *
 * Reset all statistics counters for a task.
 */
void task_reset_statistics(task_t task)
{
    thread_t thread;
    
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    
    /* Reset task-level statistics */
    task->faults = 0;
    task->zero_fills = 0;
    task->reactivations = 0;
    task->pageins = 0;
    task->cow_faults = 0;
    task->messages_sent = 0;
    task->messages_received = 0;
    task->voluntary_switches = 0;
    task->involuntary_switches = 0;
    task->context_switches = 0;
    time_value64_init(&task->total_user_time);
    time_value64_init(&task->total_system_time);
    
    /* Reset thread-level statistics */
    queue_iterate(&task->thread_list, thread, thread_t, thread_list) {
        spl_t s = splsched();
        thread_lock(thread);
        thread->faults = 0;
        thread->zero_fills = 0;
        thread->pageins = 0;
        thread->cow_faults = 0;
        time_value64_init(&thread->user_time);
        time_value64_init(&thread->system_time);
        thread_unlock(thread);
        splx(s);
    }
    
    task_unlock(task);
}

/*
 * task_get_unique_id
 *
 * Get unique identifier for task.
 */
unsigned int task_get_unique_id(task_t task)
{
    static unsigned int next_task_id = 1;
    static simple_lock_t task_id_lock;
    static boolean_t initialized = FALSE;
    
    if (!initialized) {
        simple_lock_init(&task_id_lock);
        initialized = TRUE;
    }
    
    if (task == TASK_NULL)
        return 0;
    
    if (task->task_id == 0) {
        simple_lock(&task_id_lock);
        task->task_id = next_task_id++;
        simple_unlock(&task_id_lock);
    }
    
    return task->task_id;
}

/*
 * task_set_credentials
 *
 * Set user and group credentials for task.
 */
kern_return_t task_set_credentials(
    task_t  task,
    unsigned int uid,
    unsigned int gid,
    unsigned int euid,
    unsigned int egid)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->uid = uid;
    task->gid = gid;
    task->euid = euid;
    task->egid = egid;
    task->suid = uid;
    task->sgid = gid;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_get_credentials
 *
 * Get user and group credentials of task.
 */
void task_get_credentials(
    task_t      task,
    unsigned int *uid,
    unsigned int *gid,
    unsigned int *euid,
    unsigned int *egid)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    if (uid != NULL) *uid = task->uid;
    if (gid != NULL) *gid = task->gid;
    if (euid != NULL) *euid = task->euid;
    if (egid != NULL) *egid = task->egid;
    task_unlock(task);
}

/*
 * task_check_permission
 *
 * Check if a task has permission to perform an operation on another task.
 */
boolean_t task_check_permission(
    task_t  caller,
    task_t  target,
    unsigned int operation)
{
    unsigned int caller_uid, target_uid;
    boolean_t permitted = FALSE;
    
    if (caller == TASK_NULL || target == TASK_NULL)
        return FALSE;
    
    /* Kernel task has all permissions */
    if (caller == kernel_task)
        return TRUE;
    
    task_get_credentials(caller, &caller_uid, NULL, NULL, NULL);
    task_get_credentials(target, &target_uid, NULL, NULL, NULL);
    
    /* Root has all permissions */
    if (caller_uid == 0)
        return TRUE;
    
    switch (operation) {
        case PERMISSION_READ:
            permitted = (caller_uid == target_uid);
            break;
        case PERMISSION_WRITE:
            permitted = (caller_uid == target_uid);
            break;
        case PERMISSION_SIGNAL:
            permitted = (caller_uid == target_uid);
            break;
        case PERMISSION_PTRACE:
            permitted = (caller_uid == target_uid);
            break;
        default:
            permitted = FALSE;
    }
    
    return permitted;
}

/*
 * task_set_capabilities
 *
 * Set capability sets for a task.
 */
kern_return_t task_set_capabilities(
    task_t      task,
    unsigned int inheritable,
    unsigned int permitted,
    unsigned int effective,
    unsigned int bounding)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->capability_inheritable = inheritable;
    task->capability_permitted = permitted;
    task->capability_effective = effective;
    task->capability_bounding = bounding;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_has_capability
 *
 * Check if task has a specific capability.
 */
boolean_t task_has_capability(task_t task, unsigned int capability)
{
    boolean_t has_cap;
    
    if (task == TASK_NULL)
        return FALSE;
    
    task_lock(task);
    has_cap = (task->capability_effective & (1 << capability)) != 0;
    task_unlock(task);
    
    return has_cap;
}

/*
 * task_set_working_directory
 *
 * Set current working directory for task.
 */
kern_return_t task_set_working_directory(
    task_t      task,
    const char  *path)
{
    if (task == TASK_NULL || path == NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    strncpy(task->cwd, path, PATH_MAX - 1);
    task->cwd[PATH_MAX - 1] = '\0';
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_set_root_directory
 *
 * Set root directory for chroot jail.
 */
kern_return_t task_set_root_directory(
    task_t      task,
    const char  *path)
{
    if (task == TASK_NULL || path == NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    strncpy(task->root, path, PATH_MAX - 1);
    task->root[PATH_MAX - 1] = '\0';
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_set_umask
 *
 * Set file creation mask for task.
 */
void task_set_umask(task_t task, unsigned int umask)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->umask = umask & 0777;
    task_unlock(task);
}

/*
 * task_get_umask
 *
 * Get file creation mask of task.
 */
unsigned int task_get_umask(task_t task)
{
    unsigned int umask;
    
    if (task == TASK_NULL)
        return 022;  /* Default umask */
    
    task_lock(task);
    umask = task->umask;
    task_unlock(task);
    
    return umask;
}

/*
 * task_update_io_stats
 *
 * Update I/O statistics for a task.
 */
void task_update_io_stats(
    task_t          task,
    unsigned int    bytes_read,
    unsigned int    bytes_written,
    unsigned int    ops_read,
    unsigned int    ops_written)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->io_bytes_read += bytes_read;
    task->io_bytes_written += bytes_written;
    task->io_ops_read += ops_read;
    task->io_ops_written += ops_written;
    task_unlock(task);
}

/*
 * task_get_io_stats
 *
 * Get I/O statistics for a task.
 */
void task_get_io_stats(
    task_t          task,
    unsigned int    *bytes_read,
    unsigned int    *bytes_written,
    unsigned int    *ops_read,
    unsigned int    *ops_written)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    if (bytes_read != NULL) *bytes_read = task->io_bytes_read;
    if (bytes_written != NULL) *bytes_written = task->io_bytes_written;
    if (ops_read != NULL) *ops_read = task->io_ops_read;
    if (ops_written != NULL) *ops_written = task->io_ops_written;
    task_unlock(task);
}

/*
 * task_set_io_priority
 *
 * Set I/O priority for a task.
 */
kern_return_t task_set_io_priority(
    task_t      task,
    unsigned int priority)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    if (priority > 7)  /* Valid I/O priority range 0-7 */
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->io_priority = priority;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_set_numa_policy
 *
 * Set NUMA node affinity for task.
 */
kern_return_t task_set_numa_policy(
    task_t          task,
    unsigned int    node_mask,
    unsigned int    preferred_node)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->numa_mask = node_mask;
    task->numa_preferred = preferred_node;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_set_oom_score_adj
 *
 * Set OOM score adjustment for task.
 */
kern_return_t task_set_oom_score_adj(
    task_t      task,
    int         adjustment,
    int         min_value)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    if (adjustment < -1000 || adjustment > 1000)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->oom_score_adj = adjustment;
    task->oom_score_adj_min = min_value;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_calculate_oom_score
 *
 * Calculate OOM score for task based on memory usage and adjustment.
 */
int task_calculate_oom_score(task_t task)
{
    int score;
    unsigned long total_memory;
    unsigned long task_memory;
    
    if (task == TASK_NULL)
        return 0;
    
    total_memory = vm_page_count() * PAGE_SIZE;
    task_memory = task->current_memory;
    
    /* Base score: percentage of memory used (0-1000) */
    if (total_memory > 0) {
        score = (task_memory * 1000) / total_memory;
    } else {
        score = 0;
    }
    
    /* Apply OOM adjustment */
    task_lock(task);
    score += task->oom_score_adj;
    if (score < 0) score = 0;
    if (score > 1000) score = 1000;
    task_unlock(task);
    
    return score;
}

/*
 * task_set_personality
 *
 * Set execution personality for task.
 */
kern_return_t task_set_personality(
    task_t          task,
    unsigned int    personality)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->personality = personality;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_block_signal
 *
 * Block a specific signal for the task.
 */
void task_block_signal(task_t task, unsigned int signal)
{
    if (task == TASK_NULL || signal >= 32)
        return;
    
    task_lock(task);
    task->blocked_signals |= (1 << signal);
    task_unlock(task);
}

/*
 * task_unblock_signal
 *
 * Unblock a specific signal for the task.
 */
void task_unblock_signal(task_t task, unsigned int signal)
{
    if (task == TASK_NULL || signal >= 32)
        return;
    
    task_lock(task);
    task->blocked_signals &= ~(1 << signal);
    task_unlock(task);
}

/*
 * task_is_signal_blocked
 *
 * Check if a signal is blocked for the task.
 */
boolean_t task_is_signal_blocked(task_t task, unsigned int signal)
{
    boolean_t blocked;
    
    if (task == TASK_NULL || signal >= 32)
        return TRUE;  /* Invalid signal, treat as blocked */
    
    task_lock(task);
    blocked = (task->blocked_signals & (1 << signal)) != 0;
    task_unlock(task);
    
    return blocked;
}

/*
 * task_set_exit_signal
 *
 * Set the signal to send to parent when task exits.
 */
void task_set_exit_signal(task_t task, unsigned int signal)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->exit_signal = signal;
    task_unlock(task);
}

/*
 * task_add_zombie_child
 *
 * Add a zombie child to the task's zombie list.
 */
void task_add_zombie_child(task_t parent, task_t child)
{
    if (parent == TASK_NULL || child == TASK_NULL)
        return;
    
    task_lock(parent);
    queue_enter(&parent->zombie_children, child, task_t, zombie_chain);
    parent->nlwp--;  /* Decrease live thread count */
    task_unlock(parent);
}

/*
 * task_reap_zombie_children
 *
 * Reap zombie children and collect their exit status.
 */
kern_return_t task_reap_zombie_children(
    task_t  task,
    int     *exit_status,
    boolean_t wait_for_any)
{
    task_t child, next_child;
    kern_return_t kr = KERN_FAILURE;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    
    queue_iterate_safe(&task->zombie_children, child, next_child, task_t, zombie_chain) {
        queue_remove(&task->zombie_children, child, task_t, zombie_chain);
        
        if (exit_status != NULL)
            *exit_status = child->exit_code;
        
        task_unlock(task);
        
        /* Deallocate the zombie task */
        task_deallocate(child);
        
        task_lock(task);
        kr = KERN_SUCCESS;
        
        if (!wait_for_any)
            break;
    }
    
    task_unlock(task);
    return kr;
}

/*
 * task_set_ptrace_flags
 *
 * Set ptrace flags for debugging.
 */
kern_return_t task_set_ptrace_flags(
    task_t      task,
    int         flags,
    void        *data)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->ptrace_flags = flags;
    task->ptrace_data = data;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_is_being_traced
 *
 * Check if task is being traced by ptrace.
 */
boolean_t task_is_being_traced(task_t task)
{
    boolean_t traced;
    
    if (task == TASK_NULL)
        return FALSE;
    
    task_lock(task);
    traced = (task->ptrace_flags != 0);
    task_unlock(task);
    
    return traced;
}

/*
 * task_set_wait_channel
 *
 * Set wait channel for task.
 */
void task_set_wait_channel(task_t task, void *wchan, const char *name)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->wchan = (unsigned int)wchan;
    if (name != NULL) {
        strncpy(task->wchan_name, name, sizeof(task->wchan_name) - 1);
        task->wchan_name[sizeof(task->wchan_name) - 1] = '\0';
    }
    task_unlock(task);
}

/*
 * task_get_wait_channel
 *
 * Get wait channel for task.
 */
void *task_get_wait_channel(task_t task, char *name_buf, size_t buf_size)
{
    void *wchan;
    
    if (task == TASK_NULL)
        return NULL;
    
    task_lock(task);
    wchan = (void *)task->wchan;
    if (name_buf != NULL && buf_size > 0) {
        strncpy(name_buf, task->wchan_name, buf_size - 1);
        name_buf[buf_size - 1] = '\0';
    }
    task_unlock(task);
    
    return wchan;
}

/*
 * task_get_cpu_usage_percent
 *
 * Calculate CPU usage percentage for task.
 */
unsigned int task_get_cpu_usage_percent(task_t task)
{
    unsigned int usage;
    struct time_value64 now, diff;
    unsigned long long total_time;
    
    if (task == TASK_NULL)
        return 0;
    
    read_time_stamp(current_time(), &now);
    
    task_lock(task);
    diff = time_value64_subtract(now, task->start_time_tv);
    total_time = time_value64_to_microseconds(diff);
    
    if (total_time > 0) {
        unsigned long long cpu_time = time_value64_to_microseconds(task->total_user_time) +
                                      time_value64_to_microseconds(task->total_system_time);
        usage = (cpu_time * 100) / total_time;
        if (usage > 100) usage = 100;
    } else {
        usage = 0;
    }
    
    task_unlock(task);
    return usage;
}

/*
 * task_format_status_line
 *
 * Format a process status line similar to ps command.
 */
void task_format_status_line(
    task_t      task,
    char        *buffer,
    size_t      buf_size)
{
    char state;
    unsigned int cpu_percent;
    
    if (task == TASK_NULL || buffer == NULL || buf_size == 0)
        return;
    
    task_lock(task);
    
    /* Determine process state */
    if (!task->active) {
        state = 'Z';  /* Zombie */
    } else if (task->suspend_count > 0 || task->user_stop_count > 0) {
        state = 'T';  /* Stopped */
    } else if (task->thread_count == 0) {
        state = 'I';  /* Idle */
    } else {
        state = 'R';  /* Running */
    }
    
    cpu_percent = task_get_cpu_usage_percent(task);
    
    snprintf(buffer, buf_size,
             "%5u %5u %5u %c %5u %3u.%1u %8lu %8lu %8lu %8lu %s",
             task->pid,
             task->ppid,
             task->task_id,
             state,
             task->thread_count,
             cpu_percent / 10,
             cpu_percent % 10,
             task->current_memory / 1024,
             task->io_bytes_read / 1024,
             task->io_bytes_written / 1024,
             task->faults,
             task->name);
    
    task_unlock(task);
}

/*
 * task_send_signal_to_process_group
 *
 * Send a signal to all tasks in the same process group.
 */
kern_return_t task_send_signal_to_process_group(
    task_t      task,
    unsigned int signal)
{
    processor_set_t pset;
    task_t other_task;
    unsigned int target_pgid;
    int sent_count = 0;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    target_pgid = task->tgid;
    
    simple_lock(&all_psets_lock);
    queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
        pset_lock(pset);
        queue_iterate(&pset->tasks, other_task, task_t, pset_tasks) {
            if (other_task != task && other_task->tgid == target_pgid) {
                task_signal(other_task, signal);
                sent_count++;
            }
        }
        pset_unlock(pset);
    }
    simple_unlock(&all_psets_lock);
    
    return (sent_count > 0) ? KERN_SUCCESS : KERN_FAILURE;
}

/*
 * task_get_process_group_leader
 *
 * Get the process group leader task.
 */
task_t task_get_process_group_leader(task_t task)
{
    task_t leader = TASK_NULL;
    processor_set_t pset;
    task_t other_task;
    
    if (task == TASK_NULL)
        return TASK_NULL;
    
    simple_lock(&all_psets_lock);
    queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
        pset_lock(pset);
        queue_iterate(&pset->tasks, other_task, task_t, pset_tasks) {
            if (other_task->tgid == task->tgid && other_task->thread_group_leader) {
                task_reference(other_task);
                leader = other_task;
                pset_unlock(pset);
                simple_unlock(&all_psets_lock);
                return leader;
            }
        }
        pset_unlock(pset);
    }
    simple_unlock(&all_psets_lock);
    
    return TASK_NULL;
}

/*
 * task_set_child_clear_tid
 *
 * Set address for child thread ID clearing on exit.
 */
void task_set_child_clear_tid(task_t task, void *address)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->clear_child_tid = address;
    task_unlock(task);
}

/*
 * task_set_child_set_tid
 *
 * Set address for child thread ID setting on clone.
 */
void task_set_child_set_tid(task_t task, void *address)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->set_child_tid = address;
    task_unlock(task);
}

/*
 * task_clear_child_tid
 *
 * Clear child TID on task exit.
 */
void task_clear_child_tid(task_t task)
{
    if (task == TASK_NULL || task->clear_child_tid == NULL)
        return;
    
    /* Write 0 to the clear_child_tid address */
    *(unsigned int *)task->clear_child_tid = 0;
    
    /* Wake up any waiting futex */
    thread_wakeup(task->clear_child_tid);
}

/*
 * task_account_page_fault
 *
 * Account for a page fault with fault type.
 */
void task_account_page_fault(task_t task, unsigned int fault_type)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    switch (fault_type) {
        case FAULT_MINOR:
            task->min_flt++;
            break;
        case FAULT_MAJOR:
            task->maj_flt++;
            break;
        case FAULT_COW:
            task->cow_faults++;
            break;
        default:
            task->faults++;
    }
    task_unlock(task);
}

/*
 * task_update_child_faults
 *
 * Update child fault counters in parent task.
 */
void task_update_child_faults(task_t parent, task_t child)
{
    if (parent == TASK_NULL || child == TASK_NULL)
        return;
    
    task_lock(parent);
    parent->cmin_flt += child->min_flt;
    parent->cmaj_flt += child->maj_flt;
    task_unlock(parent);
}

/*
 * task_get_comprehensive_info
 *
 * Get comprehensive task information in a single call.
 */
kern_return_t task_get_comprehensive_info(
    task_t                  task,
    struct task_comprehensive_info *info)
{
    if (task == TASK_NULL || info == NULL)
        return KERN_INVALID_ARGUMENT;
    
    memset(info, 0, sizeof(struct task_comprehensive_info));
    
    task_lock(task);
    
    /* Basic info */
    info->task_id = task->task_id;
    info->pid = task->pid;
    info->ppid = task->ppid;
    info->tgid = task->tgid;
    strncpy(info->name, task->name, sizeof(info->name) - 1);
    info->active = task->active;
    
    /* Credentials */
    info->uid = task->uid;
    info->gid = task->gid;
    info->euid = task->euid;
    info->egid = task->egid;
    
    /* Memory */
    info->current_memory = task->current_memory;
    info->memory_limit = task->memory_limit;
    info->rss = task->rss;
    
    /* Scheduling */
    info->priority = task->priority;
    info->nice_value = task->nice_value;
    info->scheduling_policy = task->scheduling_policy;
    info->cpu_affinity_mask = task->cpu_affinity_mask;
    
    /* Statistics */
    info->thread_count = task->thread_count;
    info->faults = task->faults;
    info->min_flt = task->min_flt;
    info->maj_flt = task->maj_flt;
    info->pageins = task->pageins;
    info->cow_faults = task->cow_faults;
    info->context_switches = task->context_switches;
    info->voluntary_switches = task->voluntary_switches;
    info->involuntary_switches = task->involuntary_switches;
    
    /* I/O */
    info->io_bytes_read = task->io_bytes_read;
    info->io_bytes_written = task->io_bytes_written;
    info->io_ops_read = task->io_ops_read;
    info->io_ops_written = task->io_ops_written;
    
    /* IPC */
    info->messages_sent = task->messages_sent;
    info->messages_received = task->messages_received;
    
    /* Times */
    info->total_user_time = task->total_user_time;
    info->total_system_time = task->total_system_time;
    info->start_time = task->start_time_tv;
    
    /* CPU usage */
    info->cpu_usage_percent = task_get_cpu_usage_percent(task);
    
    /* OOM */
    info->oom_score = task_calculate_oom_score(task);
    info->oom_score_adj = task->oom_score_adj;
    
    /* Signals */
    info->signal_pending = task->signal_pending;
    info->blocked_signals = task->blocked_signals;
    info->ignored_signals = task->ignored_signals;
    
    /* Wait channel */
    info->wchan = (void *)task->wchan;
    strncpy(info->wchan_name, task->wchan_name, sizeof(info->wchan_name) - 1);
    
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_compare_by_memory_usage
 *
 * Comparison function for sorting tasks by memory usage.
 */
int task_compare_by_memory_usage(const void *a, const void *b)
{
    task_t task_a = *(task_t *)a;
    task_t task_b = *(task_t *)b;
    
    if (task_a->current_memory > task_b->current_memory)
        return -1;
    else if (task_a->current_memory < task_b->current_memory)
        return 1;
    else
        return 0;
}

/*
 * task_compare_by_cpu_usage
 *
 * Comparison function for sorting tasks by CPU usage.
 */
int task_compare_by_cpu_usage(const void *a, const void *b)
{
    task_t task_a = *(task_t *)a;
    task_t task_b = *(task_t *)b;
    unsigned int cpu_a = task_get_cpu_usage_percent(task_a);
    unsigned int cpu_b = task_get_cpu_usage_percent(task_b);
    
    if (cpu_a > cpu_b)
        return -1;
    else if (cpu_a < cpu_b)
        return 1;
    else
        return 0;
}

/*
 * task_get_top_memory_consumers
 *
 * Get the top N memory-consuming tasks.
 */
kern_return_t task_get_top_memory_consumers(
    unsigned int    max_tasks,
    task_t          *tasks,
    unsigned int    *num_tasks)
{
    unsigned int count = 0;
    processor_set_t pset;
    task_t task;
    
    if (tasks == NULL || num_tasks == NULL || max_tasks == 0)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&all_psets_lock);
    queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
        pset_lock(pset);
        queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
            if (count < max_tasks) {
                task_reference(task);
                tasks[count++] = task;
            }
        }
        pset_unlock(pset);
    }
    simple_unlock(&all_psets_lock);
    
    /* Sort by memory usage */
    qsort(tasks, count, sizeof(task_t), task_compare_by_memory_usage);
    
    *num_tasks = count;
    return KERN_SUCCESS;
}

/*
 * task_kill_all_by_user
 *
 * Terminate all tasks belonging to a specific user.
 */
kern_return_t task_kill_all_by_user(unsigned int uid)
{
    processor_set_t pset;
    task_t task;
    unsigned int task_uid;
    int killed_count = 0;
    
    simple_lock(&all_psets_lock);
    queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
        pset_lock(pset);
        queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
            task_get_credentials(task, &task_uid, NULL, NULL, NULL);
            if (task_uid == uid && task != kernel_task) {
                task_reference(task);
                pset_unlock(pset);
                simple_unlock(&all_psets_lock);
                
                task_terminate(task);
                task_deallocate(task);
                killed_count++;
                
                simple_lock(&all_psets_lock);
                pset_lock(pset);
            }
        }
        pset_unlock(pset);
    }
    simple_unlock(&all_psets_lock);
    
    return (killed_count > 0) ? KERN_SUCCESS : KERN_FAILURE;
}

/*
 * task_set_processor_bias
 *
 * Set processor bias for scheduling decisions.
 */
kern_return_t task_set_processor_bias(
    task_t      task,
    unsigned int processor_bias)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    if (processor_bias >= MAX_CPUS)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->processor_bias = processor_bias;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_set_scheduling_class
 *
 * Set scheduling class for task (RT, NORMAL, IDLE).
 */
kern_return_t task_set_scheduling_class(
    task_t          task,
    unsigned int    sched_class,
    int             rt_priority)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    if (sched_class > SCHED_CLASS_IDLE)
        return KERN_INVALID_ARGUMENT;
    
    if (sched_class == SCHED_CLASS_RT && (rt_priority < 1 || rt_priority > 99))
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->sched_class = sched_class;
    task->rt_priority = rt_priority;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_set_deadline_scheduling
 *
 * Set deadline scheduling parameters for real-time tasks.
 */
kern_return_t task_set_deadline_scheduling(
    task_t              task,
    struct time_value64 deadline,
    struct time_value64 period,
    struct time_value64 execution_time)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    /* Validate: execution_time <= period <= deadline */
    if (time_value64_greater(execution_time, period) ||
        time_value64_greater(period, deadline))
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->deadline_policy = 1;
    task->deadline = deadline;
    task->period = period;
    task->execution_time = execution_time;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_check_deadline
 *
 * Check if task has missed its deadline.
 */
boolean_t task_check_deadline(task_t task)
{
    struct time_value64 now;
    boolean_t missed = FALSE;
    
    if (task == TASK_NULL)
        return FALSE;
    
    task_lock(task);
    if (task->deadline_policy) {
        read_time_stamp(current_time(), &now);
        if (time_value64_greater(now, task->deadline))
            missed = TRUE;
    }
    task_unlock(task);
    
    return missed;
}

/*
 * task_set_namespace
 *
 * Set namespace for task (UTS, IPC, NET, PID, MNT, USER).
 */
kern_return_t task_set_namespace(
    task_t          task,
    unsigned int    ns_type,
    void            *ns)
{
    if (task == TASK_NULL || ns == NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->namespace_flags |= (1 << ns_type);
    
    switch (ns_type) {
        case NS_TYPE_UTS:
            task->ns_uts = ns;
            break;
        case NS_TYPE_IPC:
            task->ns_ipc = ns;
            break;
        case NS_TYPE_NET:
            task->ns_net = ns;
            break;
        case NS_TYPE_PID:
            task->ns_pid = ns;
            break;
        case NS_TYPE_MNT:
            task->ns_mnt = ns;
            break;
        case NS_TYPE_USER:
            task->ns_user = ns;
            break;
        default:
            task_unlock(task);
            return KERN_INVALID_ARGUMENT;
    }
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_clone_namespaces
 *
 * Clone all namespaces from parent task.
 */
void task_clone_namespaces(task_t child, task_t parent)
{
    if (child == TASK_NULL || parent == TASK_NULL)
        return;
    
    task_lock(parent);
    task_lock(child);
    
    child->namespace_flags = parent->namespace_flags;
    
    /* Clone namespace references (simplified) */
    if (parent->ns_uts) child->ns_uts = parent->ns_uts;
    if (parent->ns_ipc) child->ns_ipc = parent->ns_ipc;
    if (parent->ns_net) child->ns_net = parent->ns_net;
    if (parent->ns_pid) child->ns_pid = parent->ns_pid;
    if (parent->ns_mnt) child->ns_mnt = parent->ns_mnt;
    if (parent->ns_user) child->ns_user = parent->ns_user;
    
    task_unlock(child);
    task_unlock(parent);
}

/*
 * task_set_seccomp_filter
 *
 * Set seccomp filter for task (secure computing mode).
 */
kern_return_t task_set_seccomp_filter(
    task_t      task,
    unsigned int mode,
    void        *filter)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    if (mode > SECCOMP_MODE_FILTER)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->seccomp_mode = mode;
    task->seccomp_filter = filter;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_is_seccomp_enabled
 *
 * Check if seccomp is enabled for task.
 */
boolean_t task_is_seccomp_enabled(task_t task)
{
    boolean_t enabled;
    
    if (task == TASK_NULL)
        return FALSE;
    
    task_lock(task);
    enabled = (task->seccomp_mode != SECCOMP_MODE_DISABLED);
    task_unlock(task);
    
    return enabled;
}

/*
 * task_set_cgroup
 *
 * Add task to a control group.
 */
kern_return_t task_set_cgroup(
    task_t          task,
    unsigned int    cgroup_mask,
    void            *cgroup_info)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->cgroup_mask = cgroup_mask;
    task->cgroup_info = cgroup_info;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_update_cgroup_stats
 *
 * Update cgroup statistics for task.
 */
void task_update_cgroup_stats(
    task_t          task,
    unsigned int    cpu_usage,
    unsigned int    mem_usage,
    unsigned int    io_usage)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    /* Update cgroup statistics (simplified) */
    if (task->cgroup_info != NULL) {
        /* Actual cgroup update would go here */
        task->cpu_usage = cpu_usage;
        task->current_memory = mem_usage;
    }
    task_unlock(task);
}

/*
 * task_set_robust_futex_list
 *
 * Set robust futex list for task (for robust mutexes).
 */
kern_return_t task_set_robust_futex_list(
    task_t          task,
    void            *list,
    unsigned int    length)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->robust_futex_list = list;
    task->robust_futex_len = length;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_cleanup_robust_futexes
 *
 * Clean up robust futexes when task exits.
 */
void task_cleanup_robust_futexes(task_t task)
{
    if (task == TASK_NULL || task->robust_futex_list == NULL)
        return;
    
    /* Wake up any waiters on robust futexes */
    /* This would walk the list and wake all waiters */
    thread_wakeup(task->robust_futex_list);
    
    task_lock(task);
    task->robust_futex_list = NULL;
    task->robust_futex_len = 0;
    task_unlock(task);
}

/*
 * task_account_numa_memory
 *
 * Account NUMA memory allocations for task.
 */
void task_account_numa_memory(
    task_t          task,
    unsigned int    bytes,
    unsigned int    node,
    unsigned int    type)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    switch (type) {
        case NUMA_MEMORY_LOCAL:
            task->numa_local_memory += bytes;
            break;
        case NUMA_MEMORY_REMOTE:
            task->numa_remote_memory += bytes;
            break;
        case NUMA_MEMORY_FOREIGN:
            task->numa_foreign_memory += bytes;
            break;
    }
    task_unlock(task);
}

/*
 * task_get_numa_stats
 *
 * Get NUMA memory statistics for task.
 */
void task_get_numa_stats(
    task_t          task,
    unsigned int    *local,
    unsigned int    *remote,
    unsigned int    *foreign)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    if (local != NULL) *local = task->numa_local_memory;
    if (remote != NULL) *remote = task->numa_remote_memory;
    if (foreign != NULL) *foreign = task->numa_foreign_memory;
    task_unlock(task);
}

/*
 * task_set_prctl_option
 *
 * Set prctl (process control) option for task.
 */
kern_return_t task_set_prctl_option(
    task_t          task,
    unsigned int    option,
    unsigned int    value,
    void            *data)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->prctl_options |= (1 << option);
    task->prctl_data = data;
    /* Handle specific prctl options */
    switch (option) {
        case PR_SET_PDEATHSIG:
            task->exit_signal = value;
            break;
        case PR_SET_DUMPABLE:
            /* Set dumpable flag */
            break;
        case PR_SET_KEEPCAPS:
            /* Keep capabilities across exec */
            break;
        default:
            break;
    }
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_set_speculation_ctrl
 *
 * Set speculation control flags (Spectre/Meltdown mitigations).
 */
kern_return_t task_set_speculation_ctrl(
    task_t          task,
    unsigned int    flags)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->speculation_ctrl = flags;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_set_lock
 *
 * Record that task has acquired a lock (for deadlock detection).
 */
kern_return_t task_set_lock(task_t task, void *lock_address)
{
    if (task == TASK_NULL || lock_address == NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    if (task->lock_count < 32) {
        task->held_locks[task->lock_count++] = (unsigned int)lock_address;
    }
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_clear_lock
 *
 * Record that task has released a lock.
 */
void task_clear_lock(task_t task, void *lock_address)
{
    unsigned int i;
    
    if (task == TASK_NULL || lock_address == NULL)
        return;
    
    task_lock(task);
    for (i = 0; i < task->lock_count; i++) {
        if (task->held_locks[i] == (unsigned int)lock_address) {
            /* Remove lock from list */
            for (; i < task->lock_count - 1; i++) {
                task->held_locks[i] = task->held_locks[i + 1];
            }
            task->lock_count--;
            break;
        }
    }
    task_unlock(task);
}

/*
 * task_check_lock_order
 *
 * Check if acquiring a lock would cause deadlock.
 */
boolean_t task_check_lock_order(task_t task, void *new_lock)
{
    unsigned int i;
    boolean_t would_deadlock = FALSE;
    
    if (task == TASK_NULL || new_lock == NULL)
        return FALSE;
    
    task_lock(task);
    /* Simple check: if lock is already held, would deadlock */
    for (i = 0; i < task->lock_count; i++) {
        if (task->held_locks[i] == (unsigned int)new_lock) {
            would_deadlock = TRUE;
            break;
        }
    }
    task_unlock(task);
    
    return would_deadlock;
}

/*
 * task_set_wait_lock
 *
 * Set that task is waiting for a lock.
 */
void task_set_wait_lock(task_t task, void *lock_address)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->lock_waiting = 1;
    task->lock_wait_address = lock_address;
    task_unlock(task);
}

/*
 * task_clear_wait_lock
 *
 * Clear that task is waiting for a lock.
 */
void task_clear_wait_lock(task_t task)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->lock_waiting = 0;
    task->lock_wait_address = NULL;
    task_unlock(task);
}

/*
 * task_update_memcg_stats
 *
 * Update memory cgroup statistics.
 */
void task_update_memcg_stats(
    task_t          task,
    unsigned int    usage,
    unsigned int    limit,
    unsigned int    peak)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->kmem_usage = usage;
    task->kmem_limit = limit;
    if (peak > task->kmem_peak)
        task->kmem_peak = peak;
    task_unlock(task);
}

/*
 * task_check_memcg_oom
 *
 * Check if task is under memory cgroup OOM condition.
 */
boolean_t task_check_memcg_oom(task_t task)
{
    boolean_t oom = FALSE;
    
    if (task == TASK_NULL)
        return FALSE;
    
    task_lock(task);
    if (task->memcg_oom_kill) {
        oom = TRUE;
    } else if (task->kmem_usage > task->kmem_limit && task->kmem_limit > 0) {
        oom = TRUE;
        task->memcg_oom_kill = 1;
    }
    task_unlock(task);
    
    return oom;
}

/*
 * task_set_io_context
 *
 * Set I/O context for task (for async I/O).
 */
kern_return_t task_set_io_context(
    task_t          task,
    void            *io_context,
    unsigned int    priority,
    unsigned int    weight)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->io_context = io_context;
    task->io_priority = priority;
    task->blkio_weight = weight;
    task->io_context_active = 1;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_update_blkio_stats
 *
 * Update block I/O statistics.
 */
void task_update_blkio_stats(
    task_t          task,
    unsigned int    bytes_read,
    unsigned int    bytes_written,
    unsigned int    ops_read,
    unsigned int    ops_written)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->io_bytes_read += bytes_read;
    task->io_bytes_written += bytes_written;
    task->io_ops_read += ops_read;
    task->io_ops_written += ops_written;
    task->io_context_switches++;
    task_unlock(task);
}

/*
 * task_set_dirty_pages
 *
 * Set dirty pages count for task.
 */
void task_set_dirty_pages(task_t task, unsigned int count)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->dirty_pages = count;
    task_unlock(task);
}

/*
 * task_add_dirty_pages
 *
 * Add to dirty pages count.
 */
void task_add_dirty_pages(task_t task, unsigned int count)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->dirty_pages += count;
    task_unlock(task);
}

/*
 * task_set_swap_pages
 *
 * Set swapped pages count for task.
 */
void task_set_swap_pages(task_t task, unsigned int count)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->swap_pages = count;
    task_unlock(task);
}

/*
 * task_set_throttle
 *
 * Apply throttling to task (rate limiting).
 */
void task_set_throttle(task_t task, unsigned int rate_limit)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->throttle_count = rate_limit;
    task_unlock(task);
}

/*
 * task_check_throttle
 *
 * Check if task should be throttled.
 */
boolean_t task_check_throttle(task_t task)
{
    boolean_t throttle = FALSE;
    
    if (task == TASK_NULL)
        return FALSE;
    
    task_lock(task);
    if (task->throttle_count > 0) {
        throttle = TRUE;
        if (task->throttle_count > 0)
            task->throttle_count--;
    }
    task_unlock(task);
    
    return throttle;
}

/*
 * task_set_audit_info
 *
 * Set audit information for task.
 */
kern_return_t task_set_audit_info(
    task_t                  task,
    unsigned int            sessionid,
    unsigned int            loginuid,
    unsigned int            audit_state)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->sessionid = sessionid;
    task->loginuid = loginuid;
    task->audit.audit_state = audit_state;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_log_audit_event
 *
 * Log an audit event for the task.
 */
void task_log_audit_event(
    task_t          task,
    unsigned int    event_type,
    void            *event_data)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    /* Audit logging would go here */
    task->audit.last_event = event_type;
    task->audit.event_count++;
    task_unlock(task);
}

/*
 * task_set_perf_counter
 *
 * Set performance counters for task profiling.
 */
kern_return_t task_set_perf_counter(
    task_t          task,
    unsigned int    mask,
    void            *data)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->perf_counter_mask = mask;
    task->perf_counter_data = data;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_update_perf_counter
 *
 * Update performance counter values.
 */
void task_update_perf_counter(
    task_t          task,
    unsigned int    counter_id,
    unsigned long   value)
{
    if (task == TASK_NULL || task->perf_counter_data == NULL)
        return;
    
    task_lock(task);
    /* Update specific performance counter */
    /* Implementation depends on perf counter format */
    task_unlock(task);
}

/*
 * task_set_debug_registers
 *
 * Set debug registers for hardware breakpoints.
 */
kern_return_t task_set_debug_registers(
    task_t          task,
    void            *registers)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->debug_registers = registers;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_set_fpu_state
 *
 * Set FPU/SSE state for task.
 */
void task_set_fpu_state(task_t task, void *state)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->fpu_state = state;
    task_unlock(task);
}

/*
 * task_save_fpu_state
 *
 * Save current FPU state for task.
 */
void task_save_fpu_state(task_t task)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    /* Save FPU state to task structure */
    /* Implementation is architecture-specific */
    task_unlock(task);
}

/*
 * task_restore_fpu_state
 *
 * Restore FPU state for task.
 */
void task_restore_fpu_state(task_t task)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    /* Restore FPU state from task structure */
    /* Implementation is architecture-specific */
    task_unlock(task);
}

/*
 * task_set_vvar_mapping
 *
 * Set vDSO (virtual dynamic shared object) mapping for task.
 */
kern_return_t task_set_vvar_mapping(
    task_t          task,
    void            *vvar_info,
    void            *vvar_mapping,
    unsigned int    sequence)
{
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    task->vvar_info = vvar_info;
    task->vvar_mapping = vvar_mapping;
    task->vvar_sequence = sequence;
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_increment_vvar_sequence
 *
 * Increment vDSO sequence counter (for clock updates).
 */
void task_increment_vvar_sequence(task_t task)
{
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    task->vvar_sequence++;
    task_unlock(task);
}

/*
 * task_get_complete_state
 *
 * Get complete state of task for checkpoint/restore.
 */
kern_return_t task_get_complete_state(
    task_t                  task,
    struct task_complete_state *state)
{
    if (task == TASK_NULL || state == NULL)
        return KERN_INVALID_ARGUMENT;
    
    memset(state, 0, sizeof(struct task_complete_state));
    
    task_lock(task);
    
    /* Basic identification */
    state->task_id = task->task_id;
    state->pid = task->pid;
    state->ppid = task->ppid;
    state->tgid = task->tgid;
    memcpy(state->name, task->name, TASK_NAME_LEN);
    
    /* Credentials */
    state->uid = task->uid;
    state->gid = task->gid;
    state->euid = task->euid;
    state->egid = task->egid;
    
    /* Memory */
    state->current_memory = task->current_memory;
    state->memory_limit = task->memory_limit;
    state->rss = task->rss;
    state->dirty_pages = task->dirty_pages;
    state->swap_pages = task->swap_pages;
    
    /* Scheduling */
    state->priority = task->priority;
    state->nice_value = task->nice_value;
    state->scheduling_policy = task->scheduling_policy;
    state->sched_class = task->sched_class;
    state->rt_priority = task->rt_priority;
    state->cpu_affinity_mask = task->cpu_affinity_mask;
    state->processor_bias = task->processor_bias;
    
    /* Time */
    state->total_user_time = task->total_user_time;
    state->total_system_time = task->total_system_time;
    state->start_time = task->start_time_tv;
    
    /* Statistics */
    state->thread_count = task->thread_count;
    state->context_switches = task->context_switches;
    state->voluntary_switches = task->voluntary_switches;
    state->involuntary_switches = task->involuntary_switches;
    state->io_context_switches = task->io_context_switches;
    
    /* I/O */
    state->io_bytes_read = task->io_bytes_read;
    state->io_bytes_written = task->io_bytes_written;
    state->io_ops_read = task->io_ops_read;
    state->io_ops_written = task->io_ops_written;
    state->blkio_weight = task->blkio_weight;
    state->blkio_priority = task->blkio_priority;
    
    /* Faults */
    state->faults = task->faults;
    state->min_flt = task->min_flt;
    state->maj_flt = task->maj_flt;
    state->pageins = task->pageins;
    state->cow_faults = task->cow_faults;
    
    /* IPC */
    state->messages_sent = task->messages_sent;
    state->messages_received = task->messages_received;
    
    /* Signals */
    state->signal_pending = task->signal_pending;
    state->blocked_signals = task->blocked_signals;
    state->ignored_signals = task->ignored_signals;
    state->exit_signal = task->exit_signal;
    
    /* Namespaces */
    state->namespace_flags = task->namespace_flags;
    state->ns_inum = task->ns_inum;
    
    /* Cgroups */
    state->cgroup_mask = task->cgroup_mask;
    state->kmem_usage = task->kmem_usage;
    state->kmem_limit = task->kmem_limit;
    state->kmem_peak = task->kmem_peak;
    
    /* NUMA */
    state->numa_mask = task->numa_mask;
    state->numa_preferred = task->numa_preferred;
    state->numa_local_memory = task->numa_local_memory;
    state->numa_remote_memory = task->numa_remote_memory;
    state->numa_foreign_memory = task->numa_foreign_memory;
    
    /* Security */
    state->seccomp_mode = task->seccomp_mode;
    state->speculation_ctrl = task->speculation_ctrl;
    state->securebits = task->securebits;
    
    /* Capabilities */
    state->capability_inheritable = task->capability_inheritable;
    state->capability_permitted = task->capability_permitted;
    state->capability_effective = task->capability_effective;
    state->capability_bounding = task->capability_bounding;
    
    /* Debug */
    state->ptrace_flags = task->ptrace_flags;
    state->debug_flags = task->debug_flags;
    
    /* Lock info */
    state->lock_count = task->lock_count;
    state->lock_waiting = task->lock_waiting;
    
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_restore_complete_state
 *
 * Restore complete state of task (for checkpoint/restore).
 */
kern_return_t task_restore_complete_state(
    task_t                      task,
    struct task_complete_state  *state)
{
    if (task == TASK_NULL || state == NULL)
        return KERN_INVALID_ARGUMENT;
    
    task_lock(task);
    
    /* Restore basic information */
    memcpy(task->name, state->name, TASK_NAME_LEN);
    
    /* Restore credentials */
    task->uid = state->uid;
    task->gid = state->gid;
    task->euid = state->euid;
    task->egid = state->egid;
    
    /* Restore memory limits */
    task->memory_limit = state->memory_limit;
    task->rss = state->rss;
    
    /* Restore scheduling */
    task->priority = state->priority;
    task->nice_value = state->nice_value;
    task->scheduling_policy = state->scheduling_policy;
    task->sched_class = state->sched_class;
    task->rt_priority = state->rt_priority;
    task->cpu_affinity_mask = state->cpu_affinity_mask;
    task->processor_bias = state->processor_bias;
    
    /* Restore I/O settings */
    task->blkio_weight = state->blkio_weight;
    task->blkio_priority = state->blkio_priority;
    
    /* Restore namespaces */
    task->namespace_flags = state->namespace_flags;
    task->ns_inum = state->ns_inum;
    
    /* Restore cgroup info */
    task->cgroup_mask = state->cgroup_mask;
    task->kmem_limit = state->kmem_limit;
    
    /* Restore NUMA settings */
    task->numa_mask = state->numa_mask;
    task->numa_preferred = state->numa_preferred;
    
    /* Restore security */
    task->seccomp_mode = state->seccomp_mode;
    task->speculation_ctrl = state->speculation_ctrl;
    task->securebits = state->securebits;
    
    /* Restore capabilities */
    task->capability_inheritable = state->capability_inheritable;
    task->capability_permitted = state->capability_permitted;
    task->capability_effective = state->capability_effective;
    task->capability_bounding = state->capability_bounding;
    
    /* Restore debug settings */
    task->ptrace_flags = state->ptrace_flags;
    task->debug_flags = state->debug_flags;
    
    task_unlock(task);
    
    return KERN_SUCCESS;
}

/*
 * task_detect_lock_leaks
 *
 * Detect lock leaks in a task (locks held but not released).
 */
unsigned int task_detect_lock_leaks(task_t task)
{
    unsigned int leak_count = 0;
    
    if (task == TASK_NULL)
        return 0;
    
    task_lock(task);
    leak_count = task->lock_count;
    task_unlock(task);
    
    return leak_count;
}

/*
 * task_force_unlock_all
 *
 * Forcefully unlock all locks held by task (during termination).
 */
void task_force_unlock_all(task_t task)
{
    unsigned int i;
    
    if (task == TASK_NULL)
        return;
    
    task_lock(task);
    for (i = 0; i < task->lock_count; i++) {
        /* Wake up all waiters on this lock */
        thread_wakeup((void *)task->held_locks[i]);
    }
    task->lock_count = 0;
    task->lock_waiting = 0;
    task->lock_wait_address = NULL;
    task_unlock(task);
}

/*
 * task_dump_lock_info
 *
 * Dump lock information for debugging.
 */
void task_dump_lock_info(task_t task)
{
    unsigned int i;
    
    if (task == TASK_NULL) {
        printf("Task: NULL\n");
        return;
    }
    
    task_lock(task);
    printf("\n=== Lock Information for Task %p (%s) ===\n", task, task->name);
    printf("Lock count: %u\n", task->lock_count);
    printf("Waiting for lock: %s\n", task->lock_waiting ? "yes" : "no");
    if (task->lock_waiting) {
        printf("Lock address: %p\n", task->lock_wait_address);
    }
    printf("Held locks:\n");
    for (i = 0; i < task->lock_count; i++) {
        printf("  [%u] %p\n", i, (void *)task->held_locks[i]);
    }
    task_unlock(task);
}

/*
 * task_get_system_wide_task_count
 *
 * Get total number of tasks in system.
 */
unsigned int task_get_system_wide_task_count(void)
{
    processor_set_t pset;
    task_t task;
    unsigned int count = 0;
    
    simple_lock(&all_psets_lock);
    queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
        pset_lock(pset);
        queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
            count++;
        }
        pset_unlock(pset);
    }
    simple_unlock(&all_psets_lock);
    
    return count;
}

/*
 * task_get_system_wide_memory_usage
 *
 * Get total memory usage of all tasks.
 */
unsigned long task_get_system_wide_memory_usage(void)
{
    processor_set_t pset;
    task_t task;
    unsigned long total = 0;
    
    simple_lock(&all_psets_lock);
    queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
        pset_lock(pset);
        queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
            total += task->current_memory;
        }
        pset_unlock(pset);
    }
    simple_unlock(&all_psets_lock);
    
    return total;
}

/*
 * task_get_system_wide_cpu_usage
 *
 * Get average CPU usage across all tasks.
 */
unsigned int task_get_system_wide_cpu_usage(void)
{
    processor_set_t pset;
    task_t task;
    unsigned int total_cpu = 0;
    unsigned int count = 0;
    
    simple_lock(&all_psets_lock);
    queue_iterate(&all_psets, pset, processor_set_t, all_psets) {
        pset_lock(pset);
        queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
            total_cpu += task_get_cpu_usage_percent(task);
            count++;
        }
        pset_unlock(pset);
    }
    simple_unlock(&all_psets_lock);
    
    return count > 0 ? total_cpu / count : 0;
}

/*
 * task_print_system_summary
 *
 * Print system-wide task summary.
 */
void task_print_system_summary(void)
{
    unsigned int task_count;
    unsigned long total_memory;
    unsigned int avg_cpu;
    
    task_count = task_get_system_wide_task_count();
    total_memory = task_get_system_wide_memory_usage();
    avg_cpu = task_get_system_wide_cpu_usage();
    
    printf("\n=== System Task Summary ===\n");
    printf("Total tasks: %u\n", task_count);
    printf("Total memory usage: %lu KB\n", total_memory / 1024);
    printf("Average CPU usage: %u.%u%%\n", avg_cpu / 10, avg_cpu % 10);
    printf("Kernel task memory: %lu KB\n", kernel_task->current_memory / 1024);
}


/*
 * sched_comm_update_rt_params
 *
 * Update Real-Time scheduler parameters from Linux RT scheduler to Mach task.
 * This communicates bandwidth, deadlines, and throttling information.
 */
kern_return_t sched_comm_update_rt_params(
    task_t              task,
    int                 rt_priority,
    unsigned int        period_ns,
    unsigned int        runtime_ns,
    unsigned int        deadline_ns,
    boolean_t           throttled)
{
    struct time_value64 now;
    unsigned long long current_bandwidth;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    /* Validate RT priority range (1-99) */
    if (rt_priority < 1 || rt_priority > 99)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&task->sched_comm.lock);
    
    /* Update RT parameters */
    task->sched_comm.rt_params.rt_priority = rt_priority;
    task->sched_comm.rt_params.rt_period = period_ns;
    task->sched_comm.rt_params.rt_runtime = runtime_ns;
    task->sched_comm.rt_params.rt_deadline = deadline_ns;
    task->sched_comm.rt_params.rt_throttled = throttled;
    
    /* Calculate bandwidth usage (runtime/period) */
    if (period_ns > 0) {
        current_bandwidth = (runtime_ns * 10000ULL) / period_ns;
        task->sched_comm.rt_params.rt_bandwidth = (unsigned int)current_bandwidth;
    }
    
    /* Set timeout if throttled */
    if (throttled && task->sched_comm.rt_params.rt_timeout == 0) {
        task->sched_comm.rt_params.rt_timeout = 1000; /* 1 second timeout */
    } else if (!throttled) {
        task->sched_comm.rt_params.rt_timeout = 0;
    }
    
    /* Record which scheduler is communicating */
    task->sched_comm.active_scheduler = SCHED_RT;
    
    /* Update timestamp */
    read_time_stamp(current_time(), &now);
    task->sched_comm.stats.last_update_time = now;
    
    /* Translate RT priority to Mach priority influence (not scheduling) */
    int mach_priority_influence = 80 + (rt_priority * 47 / 100); /* Map 1-99 to 81-127 */
    if (mach_priority_influence > MAXPRI_USER)
        mach_priority_influence = MAXPRI_USER;
    if (mach_priority_influence < MINPRI_USER)
        mach_priority_influence = MINPRI_USER;
    
    /* Store the influence value for other kernel components */
    task->sched_comm.stats.last_priority = mach_priority_influence;
    
    simple_unlock(&task->sched_comm.lock);
    
    return KERN_SUCCESS;
}

/*
 * sched_comm_query_rt_bandwidth
 *
 * Query RT bandwidth usage and availability from Mach task.
 * Complex function that calculates whether task has exceeded its RT budget.
 */
kern_return_t sched_comm_query_rt_bandwidth(
    task_t              task,
    unsigned int        *bandwidth_used,
    unsigned int        *bandwidth_available,
    unsigned int        *time_until_next_period,
    boolean_t           *is_overrun)
{
    struct time_value64 now;
    unsigned long long elapsed_ns;
    unsigned long long runtime_used;
    unsigned int period;
    unsigned int runtime_budget;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&task->sched_comm.lock);
    
    period = task->sched_comm.rt_params.rt_period;
    runtime_budget = task->sched_comm.rt_params.rt_runtime;
    
    /* Get current time and calculate elapsed since last period start */
    read_time_stamp(current_time(), &now);
    elapsed_ns = time_value64_to_nanoseconds(
        time_value64_subtract(now, task->sched_comm.stats.last_update_time));
    
    /* Calculate runtime used based on task statistics */
    runtime_used = task->sched_comm.stats.total_exec_time;
    
    /* Calculate bandwidth used (percentage of runtime used vs budget) */
    if (runtime_budget > 0) {
        *bandwidth_used = (unsigned int)((runtime_used * 10000ULL) / runtime_budget);
        if (*bandwidth_used > 10000) *bandwidth_used = 10000;
    } else {
        *bandwidth_used = 0;
    }
    
    /* Calculate available bandwidth */
    *bandwidth_available = 10000 - *bandwidth_used;
    
    /* Calculate time until next period */
    if (period > 0 && elapsed_ns < period) {
        *time_until_next_period = (period - (unsigned int)elapsed_ns) / 1000000; /* in ms */
    } else {
        *time_until_next_period = 0;
    }
    
    /* Check for overrun (runtime used exceeds budget) */
    *is_overrun = (runtime_used > runtime_budget);
    
    /* If overrun, set throttled flag */
    if (*is_overrun && !task->sched_comm.rt_params.rt_throttled) {
        task->sched_comm.rt_params.rt_throttled = TRUE;
        task->sched_comm.rt_params.rt_timeout = 1000;
    }
    
    simple_unlock(&task->sched_comm.lock);
    
    return KERN_SUCCESS;
}

/*
 * sched_comm_update_eevdf_params
 *
 * Update EEVDF (Earliest Eligible Virtual Deadline First) scheduler parameters.
 * Complex function that calculates virtual time, lag, and eligibility.
 */
kern_return_t sched_comm_update_eevdf_params(
    task_t                  task,
    unsigned long long      weight,
    unsigned long long      virtual_time,
    unsigned long long      lag_threshold,
    unsigned int            min_slice,
    boolean_t               force_update)
{
    struct time_value64 now;
    unsigned long long new_virtual_time;
    unsigned long long lag_calculated;
    unsigned int calculated_slice;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&task->sched_comm.lock);
    
    /* Get current time for eligibility calculation */
    read_time_stamp(current_time(), &now);
    
    /* Calculate new virtual time based on actual execution */
    new_virtual_time = virtual_time;
    if (force_update) {
        /* Forced update - use provided virtual time */
        new_virtual_time = virtual_time;
    } else {
        /* Calculate based on elapsed time and weight */
        unsigned long long elapsed_ns = time_value64_to_nanoseconds(
            time_value64_subtract(now, task->sched_comm.stats.last_update_time));
        
        /* Virtual time advances faster for lower weights */
        if (weight > 0) {
            new_virtual_time = task->sched_comm.eevdf_params.virtual_time + 
                               (elapsed_ns * 1024ULL) / weight;
        } else {
            new_virtual_time = task->sched_comm.eevdf_params.virtual_time + elapsed_ns;
        }
    }
    
    /* Calculate scheduling lag (difference between virtual and real time) */
    lag_calculated = (new_virtual_time > task->sched_comm.eevdf_params.eligible_time) ?
                     new_virtual_time - task->sched_comm.eevdf_params.eligible_time :
                     task->sched_comm.eevdf_params.eligible_time - new_virtual_time;
    
    /* Update EEVDF parameters */
    task->sched_comm.eevdf_params.weight = weight;
    task->sched_comm.eevdf_params.virtual_time = new_virtual_time;
    task->sched_comm.eevdf_params.lag = lag_calculated;
    
    /* Calculate deadline based on virtual time and weight */
    if (weight > 0) {
        task->sched_comm.eevdf_params.deadline = new_virtual_time + (min_slice * 1024ULL / weight);
    } else {
        task->sched_comm.eevdf_params.deadline = new_virtual_time + min_slice;
    }
    
    /* Determine if task is eligible (virtual time <= current time) */
    unsigned long long current_time_ns = time_value64_to_nanoseconds(now);
    task->sched_comm.eevdf_params.eligible_time = current_time_ns;
    
    /* Calculate appropriate time slice based on weight and lag */
    if (lag_calculated > lag_threshold) {
        /* High lag - reduce slice to catch up */
        calculated_slice = min_slice / 2;
        if (calculated_slice < 100) calculated_slice = 100;
    } else if (lag_calculated < (lag_threshold / 2)) {
        /* Low lag - increase slice */
        calculated_slice = min_slice * 2;
        if (calculated_slice > 10000) calculated_slice = 10000;
    } else {
        calculated_slice = min_slice;
    }
    
    task->sched_comm.eevdf_params.slice = calculated_slice;
    
    /* Update delayed flag based on lag */
    task->sched_comm.eevdf_params.delayed = (lag_calculated > (lag_threshold * 2));
    
    /* Record active scheduler */
    task->sched_comm.active_scheduler = SCHED_EEVDF;
    task->sched_comm.stats.last_update_time = now;
    
    simple_unlock(&task->sched_comm.lock);
    
    return KERN_SUCCESS;
}

/*
 * sched_comm_query_eevdf_deadline
 *
 * Query EEVDF deadline information and predict next scheduling event.
 * Complex function that calculates when task would miss its deadline.
 */
kern_return_t sched_comm_query_eevdf_deadline(
    task_t                  task,
    unsigned long long      *current_deadline,
    unsigned long long      *virtual_deadline_miss,
    unsigned int            *time_until_deadline_ms,
    unsigned int            *required_slice,
    boolean_t               *will_miss_deadline)
{
    struct time_value64 now;
    unsigned long long current_time_ns;
    unsigned long long deadline;
    unsigned long long exec_needed;
    unsigned long long exec_remaining;
    unsigned long long virtual_time;
    unsigned long long lag;
    unsigned int slice;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&task->sched_comm.lock);
    
    read_time_stamp(current_time(), &now);
    current_time_ns = time_value64_to_nanoseconds(now);
    
    deadline = task->sched_comm.eevdf_params.deadline;
    virtual_time = task->sched_comm.eevdf_params.virtual_time;
    lag = task->sched_comm.eevdf_params.lag;
    slice = task->sched_comm.eevdf_params.slice;
    
    *current_deadline = deadline;
    
    /* Calculate how far behind virtual deadline is */
    if (deadline > current_time_ns) {
        *virtual_deadline_miss = deadline - current_time_ns;
        *time_until_deadline_ms = (unsigned int)((*virtual_deadline_miss) / 1000000ULL);
        *will_miss_deadline = FALSE;
    } else {
        *virtual_deadline_miss = current_time_ns - deadline;
        *time_until_deadline_ms = 0;
        *will_miss_deadline = TRUE;
    }
    
    /* Calculate execution needed to meet deadline */
    exec_needed = (deadline > current_time_ns) ? (deadline - current_time_ns) : 0;
    
    /* Calculate remaining execution budget based on slice usage */
    unsigned int slice_used = task->sched_comm.eevdf_params.timeslice_used;
    exec_remaining = (slice > slice_used) ? (slice - slice_used) : 0;
    
    /* Determine required slice to meet deadline */
    if (*will_miss_deadline) {
        /* Already missed - need urgent scheduling */
        *required_slice = slice * 2;
        if (*required_slice > 10000) *required_slice = 10000;
    } else if (exec_needed > 0 && exec_remaining < exec_needed) {
        /* Need larger slice */
        *required_slice = (unsigned int)(exec_needed + 1000);
        if (*required_slice > 10000) *required_slice = 10000;
    } else {
        *required_slice = slice;
    }
    
    /* Adjust based on lag (high lag tasks need more urgent scheduling) */
    if (lag > 1000000) {  /* 1ms lag threshold */
        *required_slice = (*required_slice * 150) / 100; /* 50% boost */
        if (*required_slice > 10000) *required_slice = 10000;
    }
    
    simple_unlock(&task->sched_comm.lock);
    
    return KERN_SUCCESS;
}

/*
 * sched_comm_update_cfs_stats
 *
 * Update CFS (Completely Fair Scheduler) statistics from Linux to Mach task.
 * Complex function that calculates vruntime and maintains fairness metrics.
 */
kern_return_t sched_comm_update_cfs_stats(
    task_t                  task,
    unsigned long long      vruntime_delta,
    unsigned long long      min_vruntime,
    unsigned int            cpu_id,
    boolean_t               migrated)
{
    struct time_value64 now;
    unsigned long long new_vruntime;
    unsigned long long exec_time_delta;
    unsigned int weight;
    unsigned int slice;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&task->sched_comm.lock);
    
    read_time_stamp(current_time(), &now);
    
    /* Calculate execution time delta since last update */
    exec_time_delta = time_value64_to_nanoseconds(
        time_value64_subtract(now, task->sched_comm.stats.last_update_time));
    
    /* Calculate weight based on priority (inverse relationship) */
    weight = 1024; /* Default weight */
    if (task->sched_comm.cfs_params.sched_priority > 0) {
        /* Higher priority = higher weight (more CPU time) */
        weight = 1024 + (task->sched_comm.cfs_params.sched_priority * 10);
        if (weight > 10000) weight = 10000;
    }
    
    /* Calculate new vruntime (virtual runtime) */
    if (vruntime_delta > 0) {
        new_vruntime = task->sched_comm.cfs_params.vruntime + vruntime_delta;
    } else {
        /* Weighted vruntime increase - lower weight tasks advance faster */
        new_vruntime = task->sched_comm.cfs_params.vruntime + 
                       (exec_time_delta * 1024ULL) / weight;
    }
    
    /* Update CFS parameters */
    task->sched_comm.cfs_params.prev_sum_exec_runtime = 
        task->sched_comm.cfs_params.sum_exec_runtime;
    task->sched_comm.cfs_params.sum_exec_runtime += exec_time_delta;
    task->sched_comm.cfs_params.vruntime = new_vruntime;
    task->sched_comm.cfs_params.min_vruntime = min_vruntime;
    
    /* Update CPU affinity info */
    if (migrated) {
        task->sched_comm.cfs_params.nr_migrations++;
        task->sched_comm.stats.migration_count++;
    }
    task->sched_comm.cfs_params.nr_cpus_allowed = 1; /* Simplified */
    
    /* Calculate scheduling period and slice */
    unsigned int nr_tasks = task->sched_comm.cfs_params.nr_cpus_allowed;
    if (nr_tasks > 0) {
        task->sched_comm.cfs_params.sched_period = 6000000 / nr_tasks; /* 6ms / nr_tasks */
        if (task->sched_comm.cfs_params.sched_period < 300000)
            task->sched_comm.cfs_params.sched_period = 300000; /* Min 0.3ms */
        if (task->sched_comm.cfs_params.sched_period > 6000000)
            task->sched_comm.cfs_params.sched_period = 6000000; /* Max 6ms */
        
        /* Calculate slice (proportional to weight) */
        slice = (task->sched_comm.cfs_params.sched_period * weight) / (1024 * nr_tasks);
        task->sched_comm.cfs_params.sched_slice = slice;
    }
    
    /* Record last CPU */
    task->sched_comm.stats.last_cpu = cpu_id;
    
    /* Update timestamp */
    task->sched_comm.stats.last_update_time = now;
    task->sched_comm.active_scheduler = SCHED_CFS;
    
    simple_unlock(&task->sched_comm.lock);
    
    return KERN_SUCCESS;
}

/*
 * sched_comm_calculate_fairness_index
 *
 * Calculate fairness index for task based on CFS parameters.
 * Complex function that determines how fairly the task has been treated.
 */
kern_return_t sched_comm_calculate_fairness_index(
    task_t                  task,
    unsigned int            *fairness_index,
    unsigned long long      *vruntime_deficit,
    unsigned int            *cpu_time_share_percent,
    boolean_t               *is_starving)
{
    struct time_value64 now;
    unsigned long long current_time_ns;
    unsigned long long expected_vruntime;
    unsigned long long actual_vruntime;
    unsigned long long total_system_time;
    unsigned long long task_time;
    unsigned long long deficit;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&task->sched_comm.lock);
    
    read_time_stamp(current_time(), &now);
    current_time_ns = time_value64_to_nanoseconds(now);
    
    actual_vruntime = task->sched_comm.cfs_params.vruntime;
    total_system_time = task->sched_comm.cfs_params.sum_exec_runtime;
    task_time = total_system_time;
    
    /* Calculate expected vruntime based on weight and system load */
    unsigned int weight = 1024;
    if (task->sched_comm.cfs_params.sched_priority > 0) {
        weight = 1024 + (task->sched_comm.cfs_params.sched_priority * 10);
    }
    
    /* Expected vruntime = (task_time * 1024) / weight */
    if (weight > 0) {
        expected_vruntime = (total_system_time * 1024ULL) / weight;
    } else {
        expected_vruntime = total_system_time;
    }
    
    /* Calculate deficit (how far behind expected) */
    if (actual_vruntime > expected_vruntime) {
        deficit = actual_vruntime - expected_vruntime;
        *vruntime_deficit = deficit;
        *is_starving = (deficit > 1000000000ULL); /* 1 second deficit = starving */
    } else {
        deficit = 0;
        *vruntime_deficit = 0;
        *is_starving = FALSE;
    }
    
    /* Calculate fairness index (0-1000, higher is more fair) */
    if (expected_vruntime > 0) {
        unsigned long long ratio;
        if (actual_vruntime >= expected_vruntime) {
            ratio = (expected_vruntime * 1000ULL) / actual_vruntime;
        } else {
            ratio = (actual_vruntime * 1000ULL) / expected_vruntime;
        }
        *fairness_index = (unsigned int)ratio;
        if (*fairness_index > 1000) *fairness_index = 1000;
    } else {
        *fairness_index = 1000; /* Perfect fairness initially */
    }
    
    /* Calculate CPU time share percentage */
    if (current_time_ns > 0) {
        *cpu_time_share_percent = (unsigned int)((task_time * 1000ULL) / current_time_ns);
        if (*cpu_time_share_percent > 1000) *cpu_time_share_percent = 1000;
    } else {
        *cpu_time_share_percent = 0;
    }
    
    simple_unlock(&task->sched_comm.lock);
    
    return KERN_SUCCESS;
}

/*
 * sched_comm_migrate_scheduling_context
 *
 * Migrate scheduling context from one scheduler type to another.
 * Complex function that converts parameters between RT, EEVDF, and CFS.
 */
kern_return_t sched_comm_migrate_scheduling_context(
    task_t              task,
    enum sched_type     from_scheduler,
    enum sched_type     to_scheduler,
    unsigned long long  conversion_factor)
{
    struct time_value64 now;
    
    if (task == TASK_NULL)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&task->sched_comm.lock);
    
    read_time_stamp(current_time(), &now);
    
    /* Convert from RT to EEVDF */
    if (from_scheduler == SCHED_RT && to_scheduler == SCHED_EEVDF) {
        /* Map RT priority (1-99) to EEVDF weight */
        unsigned long long rt_weight = 1024 + (task->sched_comm.rt_params.rt_priority * 10);
        if (rt_weight > 10000) rt_weight = 10000;
        
        /* Map RT bandwidth to EEVDF lag */
        unsigned long long rt_bandwidth = task->sched_comm.rt_params.rt_bandwidth;
        unsigned long long initial_lag = (rt_bandwidth * 10000ULL) / 10000;
        
        /* Initialize EEVDF parameters from RT */
        task->sched_comm.eevdf_params.weight = rt_weight;
        task->sched_comm.eevdf_params.virtual_time = time_value64_to_nanoseconds(now);
        task->sched_comm.eevdf_params.eligible_time = task->sched_comm.eevdf_params.virtual_time;
        task->sched_comm.eevdf_params.lag = initial_lag;
        task->sched_comm.eevdf_params.slice = task->sched_comm.rt_params.rt_runtime / 1000000;
        if (task->sched_comm.eevdf_params.slice < 100) 
            task->sched_comm.eevdf_params.slice = 100;
        if (task->sched_comm.eevdf_params.slice > 10000)
            task->sched_comm.eevdf_params.slice = 10000;
        
        task->sched_comm.active_scheduler = SCHED_EEVDF;
    }
    
    /* Convert from RT to CFS */
    else if (from_scheduler == SCHED_RT && to_scheduler == SCHED_CFS) {
        /* Map RT priority to CFS priority */
        unsigned int cfs_priority = 100 - task->sched_comm.rt_params.rt_priority;
        if (cfs_priority > 99) cfs_priority = 99;
        
        /* Initialize CFS parameters from RT */
        task->sched_comm.cfs_params.sched_priority = cfs_priority;
        task->sched_comm.cfs_params.vruntime = time_value64_to_nanoseconds(now);
        task->sched_comm.cfs_params.sum_exec_runtime = 0;
        task->sched_comm.cfs_params.sched_period = 6000000; /* 6ms default */
        task->sched_comm.cfs_params.sched_slice = 3000000; /* 3ms default */
        
        task->sched_comm.active_scheduler = SCHED_CFS;
    }
    
    /* Convert from EEVDF to CFS */
    else if (from_scheduler == SCHED_EEVDF && to_scheduler == SCHED_CFS) {
        /* Map EEVDF weight to CFS priority */
        unsigned int cfs_priority = 50; /* Default */
        if (task->sched_comm.eevdf_params.weight > 0) {
            cfs_priority = (unsigned int)((task->sched_comm.eevdf_params.weight - 1024) / 10);
            if (cfs_priority > 99) cfs_priority = 99;
        }
        
        /* Map EEVDF virtual time to CFS vruntime */
        unsigned long long cfs_vruntime = task->sched_comm.eevdf_params.virtual_time;
        
        /* Initialize CFS parameters from EEVDF */
        task->sched_comm.cfs_params.sched_priority = cfs_priority;
        task->sched_comm.cfs_params.vruntime = cfs_vruntime;
        task->sched_comm.cfs_params.sum_exec_runtime = task->sched_comm.stats.total_exec_time;
        task->sched_comm.cfs_params.sched_period = task->sched_comm.eevdf_params.slice * 1000;
        task->sched_comm.cfs_params.sched_slice = task->sched_comm.eevdf_params.slice;
        
        task->sched_comm.active_scheduler = SCHED_CFS;
    }
    
    /* Convert from CFS to EEVDF */
    else if (from_scheduler == SCHED_CFS && to_scheduler == SCHED_EEVDF) {
        /* Map CFS priority to EEVDF weight */
        unsigned long long eevdf_weight = 1024 + (task->sched_comm.cfs_params.sched_priority * 10);
        if (eevdf_weight > 10000) eevdf_weight = 10000;
        
        /* Map CFS vruntime to EEVDF virtual time */
        unsigned long long eevdf_virtual = task->sched_comm.cfs_params.vruntime;
        
        /* Initialize EEVDF parameters from CFS */
        task->sched_comm.eevdf_params.weight = eevdf_weight;
        task->sched_comm.eevdf_params.virtual_time = eevdf_virtual;
        task->sched_comm.eevdf_params.eligible_time = time_value64_to_nanoseconds(now);
        task->sched_comm.eevdf_params.slice = task->sched_comm.cfs_params.sched_slice;
        task->sched_comm.eevdf_params.lag = 0;
        
        task->sched_comm.active_scheduler = SCHED_EEVDF;
    }
    
    /* Convert from CFS to RT */
    else if (from_scheduler == SCHED_CFS && to_scheduler == SCHED_RT) {
        /* Map CFS priority to RT priority */
        int rt_priority = 50; /* Default */
        if (task->sched_comm.cfs_params.sched_priority > 0) {
            rt_priority = 100 - task->sched_comm.cfs_params.sched_priority;
            if (rt_priority < 1) rt_priority = 1;
            if (rt_priority > 99) rt_priority = 99;
        }
        
        /* Initialize RT parameters from CFS */
        task->sched_comm.rt_params.rt_priority = rt_priority;
        task->sched_comm.rt_params.rt_period = 1000000000; /* 1 second default */
        task->sched_comm.rt_params.rt_runtime = task->sched_comm.cfs_params.sched_slice * 1000;
        task->sched_comm.rt_params.rt_bandwidth = 
            (task->sched_comm.rt_params.rt_runtime * 10000ULL) / 
            task->sched_comm.rt_params.rt_period;
        task->sched_comm.rt_params.rt_throttled = FALSE;
        
        task->sched_comm.active_scheduler = SCHED_RT;
    }
    
    /* Update timestamp */
    task->sched_comm.stats.last_update_time = now;
    
    simple_unlock(&task->sched_comm.lock);
    
    return KERN_SUCCESS;
}

/*
 * sched_comm_batch_update_all_params
 *
 * Batch update all scheduling parameters from multiple scheduler types.
 * Complex function that aggregates and reconciles conflicting parameters.
 */
kern_return_t sched_comm_batch_update_all_params(
    task_t                      task,
    struct rt_sched_batch       *rt_batch,
    struct eevdf_sched_batch    *eevdf_batch,
    struct cfs_sched_batch      *cfs_batch,
    unsigned int                batch_size,
    unsigned int                *applied_count,
    unsigned int                *conflict_count)
{
    struct time_value64 now;
    unsigned int applied = 0;
    unsigned int conflicts = 0;
    unsigned int i;
    unsigned long long current_time_ns;
    
    if (task == TASK_NULL || applied_count == NULL || conflict_count == NULL)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&task->sched_comm.lock);
    
    read_time_stamp(current_time(), &now);
    current_time_ns = time_value64_to_nanoseconds(now);
    
    /* Process RT batch updates */
    if (rt_batch != NULL && batch_size > 0) {
        for (i = 0; i < batch_size; i++) {
            /* Check for conflicts with other schedulers */
            boolean_t has_conflict = FALSE;
            
            if (task->sched_comm.active_scheduler == SCHED_CFS && 
                rt_batch[i].rt_priority > 50) {
                /* High RT priority conflicts with CFS */
                has_conflict = TRUE;
                conflicts++;
            }
            
            if (!has_conflict) {
                /* Apply RT update */
                task->sched_comm.rt_params.rt_priority = rt_batch[i].rt_priority;
                task->sched_comm.rt_params.rt_period = rt_batch[i].period_ns;
                task->sched_comm.rt_params.rt_runtime = rt_batch[i].runtime_ns;
                task->sched_comm.rt_params.rt_deadline = rt_batch[i].deadline_ns;
                
                /* Recalculate bandwidth */
                if (task->sched_comm.rt_params.rt_period > 0) {
                    task->sched_comm.rt_params.rt_bandwidth = 
                        (task->sched_comm.rt_params.rt_runtime * 10000ULL) / 
                        task->sched_comm.rt_params.rt_period;
                }
                
                applied++;
            }
        }
    }
    
    /* Process EEVDF batch updates */
    if (eevdf_batch != NULL && batch_size > 0) {
        for (i = 0; i < batch_size; i++) {
            boolean_t has_conflict = FALSE;
            
            /* Check for conflicts with RT scheduler */
            if (task->sched_comm.active_scheduler == SCHED_RT && 
                task->sched_comm.rt_params.rt_priority > 80 &&
                eevdf_batch[i].weight < 2048) {
                /* Low EEVDF weight conflicts with high RT priority */
                has_conflict = TRUE;
                conflicts++;
            }
            
            if (!has_conflict) {
                /* Apply EEVDF update */
                task->sched_comm.eevdf_params.weight = eevdf_batch[i].weight;
                task->sched_comm.eevdf_params.slice = eevdf_batch[i].min_slice;
                
                /* Recalculate virtual time based on current time */
                unsigned long long elapsed = current_time_ns - 
                    time_value64_to_nanoseconds(task->sched_comm.stats.last_update_time);
                
                if (task->sched_comm.eevdf_params.weight > 0) {
                    task->sched_comm.eevdf_params.virtual_time += 
                        (elapsed * 1024ULL) / task->sched_comm.eevdf_params.weight;
                } else {
                    task->sched_comm.eevdf_params.virtual_time += elapsed;
                }
                
                /* Update deadline */
                task->sched_comm.eevdf_params.deadline = 
                    task->sched_comm.eevdf_params.virtual_time + eevdf_batch[i].min_slice;
                
                applied++;
            }
        }
    }
    
    /* Process CFS batch updates */
    if (cfs_batch != NULL && batch_size > 0) {
        for (i = 0; i < batch_size; i++) {
            boolean_t has_conflict = FALSE;
            
            /* Check for conflicts with RT scheduler */
            if (task->sched_comm.active_scheduler == SCHED_RT && 
                task->sched_comm.rt_params.rt_priority > 60) {
                /* RT task should not have CFS updates */
                has_conflict = TRUE;
                conflicts++;
            }
            
            if (!has_conflict) {
                /* Apply CFS update */
                task->sched_comm.cfs_params.sched_priority = cfs_batch[i].cfs_priority;
                task->sched_comm.cfs_params.sched_period = cfs_batch[i].sched_period_ns;
                task->sched_comm.cfs_params.sched_slice = cfs_batch[i].sched_slice_ns;
                
                /* Recalculate vruntime based on weight */
                unsigned int weight = 1024 + (task->sched_comm.cfs_params.sched_priority * 10);
                if (weight > 10000) weight = 10000;
                
                unsigned long long exec_time = 
                    time_value64_to_nanoseconds(task->sched_comm.stats.total_exec_time);
                
                task->sched_comm.cfs_params.vruntime = (exec_time * 1024ULL) / weight;
                task->sched_comm.cfs_params.min_vruntime = cfs_batch[i].min_vruntime;
                
                applied++;
            }
        }
    }
    
    /* Resolve conflicts by applying a reconciliation policy */
    if (conflicts > 0) {
        /* If there are conflicts, prefer the scheduler that was most recently active */
        if (task->sched_comm.active_scheduler == SCHED_RT) {
            /* Keep RT parameters, discard conflicting CFS/EEVDF */
            task->sched_comm.cfs_params.sched_priority = 0;
            task->sched_comm.eevdf_params.weight = 1024;
        } else if (task->sched_comm.active_scheduler == SCHED_CFS) {
            /* Keep CFS parameters, adjust RT priority down */
            if (task->sched_comm.rt_params.rt_priority > 50) {
                task->sched_comm.rt_params.rt_priority = 50;
            }
        }
    }
    
    /* Update timestamp */
    task->sched_comm.stats.last_update_time = now;
    
    *applied_count = applied;
    *conflict_count = conflicts;
    
    simple_unlock(&task->sched_comm.lock);
    
    return KERN_SUCCESS;
}

/*
 * Helper function: Convert time_value64 to nanoseconds
 */
static unsigned long long time_value64_to_nanoseconds(struct time_value64 tv)
{
    return tv.seconds * 1000000000ULL + tv.microseconds * 1000ULL;
}
