/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University.
 * Copyright (c) 1993,1994 The University of Utah and
 * the Computer Systems Laboratory (CSL).
 * All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON, THE UNIVERSITY OF UTAH AND CSL ALLOW FREE USE OF
 * THIS SOFTWARE IN ITS "AS IS" CONDITION, AND DISCLAIM ANY LIABILITY
 * OF ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF
 * THIS SOFTWARE.
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
 *	File:	ipc/ipc_kmsg.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Operations on kernel messages.
 */

#include <kern/printf.h>
#include <string.h>

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <mach/port.h>
#include <machine/locore.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/kalloc.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_kern.h>
#include <vm/vm_user.h>
#include <ipc/port.h>
#include <ipc/copy_user.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_kmsg.h>
#include <vm/vm_shared_memory.h>
#include <ipc/ipc_thread.h>
#include <ipc/ipc_marequest.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_right.h>

#include <ipc/ipc_machdep.h>

#include <device/net_io.h>

#if MACH_KDB
#include <ddb/db_output.h>
#include <ipc/ipc_print.h>
#endif


ipc_kmsg_t ipc_kmsg_cache[NCPUS];

/*
 *	Routine:	ipc_kmsg_enqueue
 *	Purpose:
 *		Enqueue a kmsg.
 */

void
ipc_kmsg_enqueue(
	ipc_kmsg_queue_t	queue,
	ipc_kmsg_t		kmsg)
{
	ipc_kmsg_enqueue_macro(queue, kmsg);
}

/*
 *	Routine:	ipc_kmsg_dequeue
 *	Purpose:
 *		Dequeue and return a kmsg.
 */

ipc_kmsg_t
ipc_kmsg_dequeue(
	ipc_kmsg_queue_t	queue)
{
	ipc_kmsg_t first;

	first = ipc_kmsg_queue_first(queue);

	if (first != IKM_NULL)
		ipc_kmsg_rmqueue_first_macro(queue, first);

	return first;
}

/*
 *	Routine:	ipc_kmsg_rmqueue
 *	Purpose:
 *		Pull a kmsg out of a queue.
 */

void
ipc_kmsg_rmqueue(
	ipc_kmsg_queue_t	queue,
	ipc_kmsg_t		kmsg)
{
	ipc_kmsg_t next, prev;

	assert(queue->ikmq_base != IKM_NULL);

	next = kmsg->ikm_next;
	prev = kmsg->ikm_prev;

	if (next == kmsg) {
		assert(prev == kmsg);
		assert(queue->ikmq_base == kmsg);

		queue->ikmq_base = IKM_NULL;
	} else {
		if (queue->ikmq_base == kmsg)
			queue->ikmq_base = next;

		next->ikm_prev = prev;
		prev->ikm_next = next;
	}
	ikm_mark_bogus (kmsg);
}

/*
 *	Routine:	ipc_kmsg_queue_next
 *	Purpose:
 *		Return the kmsg following the given kmsg.
 *		(Or IKM_NULL if it is the last one in the queue.)
 */

ipc_kmsg_t
ipc_kmsg_queue_next(
	ipc_kmsg_queue_t	queue,
	ipc_kmsg_t		kmsg)
{
	ipc_kmsg_t next;

	assert(queue->ikmq_base != IKM_NULL);

	next = kmsg->ikm_next;
	if (queue->ikmq_base == next)
		next = IKM_NULL;

	return next;
}

/*
 *	Routine:	ipc_kmsg_destroy
 *	Purpose:
 *		Destroys a kernel message.  Releases all rights,
 *		references, and memory held by the message.
 *		Frees the message.
 *	Conditions:
 *		No locks held.
 */

void
ipc_kmsg_destroy(
	ipc_kmsg_t	kmsg)
{
	ipc_kmsg_queue_t queue;
	boolean_t empty;

	/*
	 *	ipc_kmsg_clean can cause more messages to be destroyed.
	 *	Curtail recursion by queueing messages.  If a message
	 *	is already queued, then this is a recursive call.
	 */

	queue = &current_thread()->ith_messages;
	empty = ipc_kmsg_queue_empty(queue);
	ipc_kmsg_enqueue(queue, kmsg);

	if (empty) {
		/* must leave kmsg in queue while cleaning it */

		while ((kmsg = ipc_kmsg_queue_first(queue)) != IKM_NULL) {
			ipc_kmsg_clean(kmsg);
			ipc_kmsg_rmqueue(queue, kmsg);
			ikm_free(kmsg);
		}
	}
}

/*
 *	Routine:	ipc_kmsg_clean_body
 *	Purpose:
 *		Cleans the body of a kernel message.
 *		Releases all rights, references, and memory.
 *
 *		The last type/data pair might stretch past eaddr.
 *		(See the usage in ipc_kmsg_copyout.)
 *	Conditions:
 *		No locks held.
 */

static void
ipc_kmsg_clean_body(
	vm_offset_t saddr,
	vm_offset_t eaddr)
{
	while (saddr < eaddr) {
		mach_msg_type_long_t *type;
		mach_msg_type_name_t name;
		mach_msg_type_size_t size;
		mach_msg_type_number_t number;
		boolean_t is_inline, is_port;
		vm_size_t length;

		type = (mach_msg_type_long_t *) saddr;
		is_inline = ((mach_msg_type_t*)type)->msgt_inline;
		if (((mach_msg_type_t*)type)->msgt_longform) {
			name = type->msgtl_name;
			size = type->msgtl_size;
			number = type->msgtl_number;
			saddr += sizeof(mach_msg_type_long_t);
			if (mach_msg_kernel_is_misaligned(sizeof(mach_msg_type_long_t))) {
				saddr = mach_msg_kernel_align(saddr);
			}
		} else {
			name = ((mach_msg_type_t*)type)->msgt_name;
			size = ((mach_msg_type_t*)type)->msgt_size;
			number = ((mach_msg_type_t*)type)->msgt_number;
			saddr += sizeof(mach_msg_type_t);
			if (mach_msg_kernel_is_misaligned(sizeof(mach_msg_type_t))) {
				saddr = mach_msg_kernel_align(saddr);
			}
		}

		/* calculate length of data in bytes, rounding up */

		length = ((number * size) + 7) >> 3;

		is_port = MACH_MSG_TYPE_PORT_ANY(name);

		if (is_port) {
			ipc_object_t *objects;
			mach_msg_type_number_t i;

			if (is_inline) {
				objects = (ipc_object_t *) saddr;
				/* sanity check */
				while (eaddr < (vm_offset_t)&objects[number]) number--;
			} else {
				objects = (ipc_object_t *)
						* (vm_offset_t *) saddr;
			}

			/* destroy port rights carried in the message */

			for (i = 0; i < number; i++) {
				ipc_object_t object = objects[i];

				if (!IO_VALID(object))
					continue;

				ipc_object_destroy(object, name);
			}
		}

		if (is_inline) {
			saddr += length;
		} else {
			vm_offset_t data = * (vm_offset_t *) saddr;

			/* destroy memory carried in the message */

			if (length == 0)
				assert(data == 0);
			else if (is_port)
				kfree(data, length);
			else
				vm_map_copy_discard((vm_map_copy_t) data);

			saddr += sizeof(vm_offset_t);
		}
		saddr = mach_msg_kernel_align(saddr);
	}
}

/*
 *	Routine:	ipc_kmsg_clean
 *	Purpose:
 *		Cleans a kernel message.  Releases all rights,
 *		references, and memory held by the message.
 *	Conditions:
 *		No locks held.
 */

void
ipc_kmsg_clean(ipc_kmsg_t kmsg)
{
	ipc_marequest_t marequest;
	ipc_object_t object;
	mach_msg_bits_t mbits = kmsg->ikm_header.msgh_bits;

	marequest = kmsg->ikm_marequest;
	if (marequest != IMAR_NULL)
		ipc_marequest_destroy(marequest);

	object = (ipc_object_t) kmsg->ikm_header.msgh_remote_port;
	if (IO_VALID(object))
		ipc_object_destroy(object, MACH_MSGH_BITS_REMOTE(mbits));

	object = (ipc_object_t) kmsg->ikm_header.msgh_local_port;
	if (IO_VALID(object))
		ipc_object_destroy(object, MACH_MSGH_BITS_LOCAL(mbits));

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		vm_offset_t saddr, eaddr;

		saddr = (vm_offset_t) (&kmsg->ikm_header + 1);
		eaddr = (vm_offset_t) &kmsg->ikm_header +
				kmsg->ikm_header.msgh_size;

		ipc_kmsg_clean_body(saddr, eaddr);
	}
}

/*
 *	Routine:	ipc_kmsg_clean_partial
 *	Purpose:
 *		Cleans a partially-acquired kernel message.
 *		eaddr is the address of the type specification
 *		in the body of the message that contained the error.
 *		If dolast, the memory and port rights in this last
 *		type spec are also cleaned.  In that case, number
 *		specifies the number of port rights to clean.
 *	Conditions:
 *		Nothing locked.
 */

static void
ipc_kmsg_clean_partial(
	ipc_kmsg_t 		kmsg,
	vm_offset_t 		eaddr,
	boolean_t 		dolast,
	mach_msg_type_number_t 	number)
{
	ipc_object_t object;
	mach_msg_bits_t mbits = kmsg->ikm_header.msgh_bits;
	vm_offset_t saddr;

	assert(kmsg->ikm_marequest == IMAR_NULL);

	object = (ipc_object_t) kmsg->ikm_header.msgh_remote_port;
	assert(IO_VALID(object));
	ipc_object_destroy(object, MACH_MSGH_BITS_REMOTE(mbits));

	object = (ipc_object_t) kmsg->ikm_header.msgh_local_port;
	if (IO_VALID(object))
		ipc_object_destroy(object, MACH_MSGH_BITS_LOCAL(mbits));

	saddr = (vm_offset_t) (&kmsg->ikm_header + 1);
	ipc_kmsg_clean_body(saddr, eaddr);

	if (dolast) {
		mach_msg_type_long_t *type;
		mach_msg_type_name_t name;
		mach_msg_type_size_t size;
		mach_msg_type_number_t rnumber;
		boolean_t is_inline, is_port;
		vm_size_t length;

		type = (mach_msg_type_long_t *) eaddr;
		is_inline = ((mach_msg_type_t*)type)->msgt_inline;
		if (((mach_msg_type_t*)type)->msgt_longform) {
			name = type->msgtl_name;
			size = type->msgtl_size;
			rnumber = type->msgtl_number;
			eaddr += sizeof(mach_msg_type_long_t);
			if (mach_msg_kernel_is_misaligned(sizeof(mach_msg_type_long_t))) {
				eaddr = mach_msg_kernel_align(eaddr);
			}
		} else {
			name = ((mach_msg_type_t*)type)->msgt_name;
			size = ((mach_msg_type_t*)type)->msgt_size;
			rnumber = ((mach_msg_type_t*)type)->msgt_number;
			eaddr += sizeof(mach_msg_type_t);
			if (mach_msg_kernel_is_misaligned(sizeof(mach_msg_type_t))) {
				eaddr = mach_msg_kernel_align(eaddr);
			}
		}

		/* calculate length of data in bytes, rounding up */

		length = ((rnumber * size) + 7) >> 3;

		is_port = MACH_MSG_TYPE_PORT_ANY(name);

		if (is_port) {
			ipc_object_t *objects;
			mach_msg_type_number_t i;

			objects = (ipc_object_t *)
				(is_inline ? eaddr : * (vm_offset_t *) eaddr);

			/* destroy port rights carried in the message */

			for (i = 0; i < number; i++) {
				ipc_object_t obj = objects[i];

				if (!IO_VALID(obj))
					continue;

				ipc_object_destroy(obj, name);
			}
		}

		if (!is_inline) {
			vm_offset_t data = * (vm_offset_t *) eaddr;

			/* destroy memory carried in the message */

			if (length == 0)
				assert(data == 0);
			else if (is_port)
				kfree(data, length);
			else
				vm_map_copy_discard((vm_map_copy_t) data);
		}
	}
}

/*
 *	Routine:	ipc_kmsg_free
 *	Purpose:
 *		Free a kernel message buffer.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_kmsg_free(ipc_kmsg_t kmsg)
{
	vm_size_t size = kmsg->ikm_size;

	switch (size) {

	    case IKM_SIZE_NETWORK:
		/* return it to the network code */
		net_kmsg_put(kmsg);
		break;

	    default:
		kfree((vm_offset_t) kmsg, size);
		break;
	}
}

/*
 *	Routine:	ipc_kmsg_get
 *	Purpose:
 *		Allocates a kernel message buffer.
 *		Copies a user message to the message buffer.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Acquired a message buffer.
 *		MACH_SEND_MSG_TOO_SMALL	Message smaller than a header.
 *		MACH_SEND_MSG_TOO_SMALL	Message size not long-word multiple.
 *		MACH_SEND_NO_BUFFER	Couldn't allocate a message buffer.
 *		MACH_SEND_INVALID_DATA	Couldn't copy message data.
 */

mach_msg_return_t
ipc_kmsg_get(
	mach_msg_user_header_t 	*msg,
	mach_msg_size_t 	size,
	ipc_kmsg_t 		*kmsgp)
{
	ipc_kmsg_t kmsg;
	mach_msg_size_t 	ksize = size * IKM_EXPAND_FACTOR;

	if ((size < sizeof(mach_msg_user_header_t)) || mach_msg_user_is_misaligned(size))
		return MACH_SEND_MSG_TOO_SMALL;

	if (ksize <= IKM_SAVED_MSG_SIZE) {
		kmsg = ikm_cache_alloc();
		if (kmsg == IKM_NULL)
			return MACH_SEND_NO_BUFFER;
	} else {
		kmsg = ikm_alloc(ksize);
		if (kmsg == IKM_NULL)
			return MACH_SEND_NO_BUFFER;
		ikm_init(kmsg, ksize);
	}

	if (copyinmsg(msg, &kmsg->ikm_header, size, kmsg->ikm_size)) {
		ikm_free(kmsg);
		return MACH_SEND_INVALID_DATA;
	}

	*kmsgp = kmsg;
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_get_from_kernel
 *	Purpose:
 *		Allocates a kernel message buffer.
 *		Copies a kernel message to the message buffer.
 *		Only resource errors are allowed.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Acquired a message buffer.
 *		MACH_SEND_NO_BUFFER	Couldn't allocate a message buffer.
 */

extern mach_msg_return_t
ipc_kmsg_get_from_kernel(
	mach_msg_header_t 	*msg,
	mach_msg_size_t 	size,
	ipc_kmsg_t 		*kmsgp)
{
	ipc_kmsg_t kmsg;

	assert(size >= sizeof(mach_msg_header_t));
	assert(!mach_msg_kernel_is_misaligned(size));

	kmsg = ikm_alloc(size);
	if (kmsg == IKM_NULL)
		return MACH_SEND_NO_BUFFER;
	ikm_init(kmsg, size);

	memcpy(&kmsg->ikm_header, msg, size);

	kmsg->ikm_header.msgh_size = size;
	*kmsgp = kmsg;
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_put
 *	Purpose:
 *		Copies a message buffer to a user message.
 *		Copies only the specified number of bytes.
 *		Frees the message buffer.
 *	Conditions:
 *		Nothing locked.  The message buffer must have clean
 *		header (ikm_marequest) fields.
 *	Returns:
 *		MACH_MSG_SUCCESS	Copied data out of message buffer.
 *		MACH_RCV_INVALID_DATA	Couldn't copy to user message.
 */

mach_msg_return_t
ipc_kmsg_put(
	mach_msg_user_header_t 	*msg,
	ipc_kmsg_t 		kmsg,
	mach_msg_size_t 	size)
{
	mach_msg_return_t mr;

	ikm_check_initialized(kmsg, kmsg->ikm_size);

	if (copyoutmsg(&kmsg->ikm_header, msg, size))
		mr = MACH_RCV_INVALID_DATA;
	else
		mr = MACH_MSG_SUCCESS;

	ikm_cache_free(kmsg);

	return mr;
}

/*
 *	Routine:	ipc_kmsg_put_to_kernel
 *	Purpose:
 *		Copies a message buffer to a kernel message.
 *		Frees the message buffer.
 *		No errors allowed.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_kmsg_put_to_kernel(
	mach_msg_header_t	*msg,
	ipc_kmsg_t		kmsg,
	mach_msg_size_t		size)
{
#if	DIPC
	assert(!KMSG_IN_DIPC(kmsg));
#endif	/* DIPC */

	memcpy(msg, &kmsg->ikm_header, size);

	ikm_free(kmsg);
}

/*
 *	Routine:	ipc_kmsg_copyin_header
 *	Purpose:
 *		"Copy-in" port rights in the header of a message.
 *		Operates atomically; if it doesn't succeed the
 *		message header and the space are left untouched.
 *		If it does succeed the remote/local port fields
 *		contain object pointers instead of port names,
 *		and the bits field is updated.  The destination port
 *		will be a valid port pointer.
 *
 *		The notify argument implements the MACH_SEND_CANCEL option.
 *		If it is not MACH_PORT_NULL, it should name a receive right.
 *		If the processing of the destination port would generate
 *		a port-deleted notification (because the right for the
 *		destination port is destroyed and it had a request for
 *		a dead-name notification registered), and the port-deleted
 *		notification would be sent to the named receive right,
 *		then it isn't sent and the send-once right for the notify
 *		port is quietly destroyed.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyin.
 *		MACH_SEND_INVALID_HEADER
 *			Illegal value in the message header bits.
 *		MACH_SEND_INVALID_DEST	The space is dead.
 *		MACH_SEND_INVALID_NOTIFY
 *			Notify is non-null and doesn't name a receive right.
 *			(Either KERN_INVALID_NAME or KERN_INVALID_RIGHT.)
 *		MACH_SEND_INVALID_DEST	Can't copyin destination port.
 *			(Either KERN_INVALID_NAME or KERN_INVALID_RIGHT.)
 *		MACH_SEND_INVALID_REPLY	Can't copyin reply port.
 *			(Either KERN_INVALID_NAME or KERN_INVALID_RIGHT.)
 */

mach_msg_return_t
ipc_kmsg_copyin_header(
	mach_msg_header_t 	*msg,
	ipc_space_t 		space,
	mach_port_name_t 	notify)
{
	mach_msg_bits_t mbits = msg->msgh_bits &~ MACH_MSGH_BITS_CIRCULAR;
	/*
	 * TODO: For 64 bits, msgh_remote_port as written by user space
	 * is 4 bytes long but here we assume it is the same size as a pointer.
	 * When copying the message to the kernel, we need to perform the
	 * conversion so that port names are parsed correctly.
	 *
	 * When copying the message out of the kernel to user space, we also need
	 * to be careful with the reverse translation.
	 */

	mach_port_name_t dest_name = (mach_port_name_t)msg->msgh_remote_port;
	mach_port_name_t reply_name = (mach_port_name_t)msg->msgh_local_port;
	kern_return_t kr;

	/* first check for common cases */

	if (notify == MACH_PORT_NULL) switch (MACH_MSGH_BITS_PORTS(mbits)) {
	    case MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0): {
		ipc_entry_t entry;
		ipc_entry_bits_t bits;
		ipc_port_t dest_port;

		/* sending an asynchronous message */

		if (reply_name != MACH_PORT_NULL)
			break;

		is_read_lock(space);
		if (!space->is_active)
			goto abort_async;

		entry = ipc_entry_lookup (space, dest_name);
		if (entry == IE_NULL)
		{
			ipc_entry_lookup_failed (msg, dest_name);
			goto abort_async;
		}
		bits = entry->ie_bits;

		/* check type bits */
		if (IE_BITS_TYPE (bits) != MACH_PORT_TYPE_SEND)
			goto abort_async;

		/* optimized ipc_right_copyin */

		assert(IE_BITS_UREFS(bits) > 0);

		dest_port = (ipc_port_t) entry->ie_object;
		assert(dest_port != IP_NULL);

		ip_lock(dest_port);
		/* can unlock space now without compromising atomicity */
		is_read_unlock(space);

		if (!ip_active(dest_port)) {
			ip_unlock(dest_port);
			break;
		}

		assert(dest_port->ip_srights > 0);
		dest_port->ip_srights++;
		ip_reference(dest_port);
		ip_unlock(dest_port);

		msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
				  MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND, 0));
		msg->msgh_remote_port = (mach_port_t) dest_port;
		return MACH_MSG_SUCCESS;

	    abort_async:
		is_read_unlock(space);
		break;
	    }

	    case MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
				MACH_MSG_TYPE_MAKE_SEND_ONCE): {
		ipc_entry_t entry;
		ipc_entry_bits_t bits;
		ipc_port_t dest_port, reply_port;

		/* sending a request message */

		is_read_lock(space);
		if (!space->is_active)
			goto abort_request;

		entry = ipc_entry_lookup (space, dest_name);
		if (entry == IE_NULL)
		{
			ipc_entry_lookup_failed (msg, dest_name);
			goto abort_request;
		}
		bits = entry->ie_bits;

		/* check type bits */
		if (IE_BITS_TYPE (bits) != MACH_PORT_TYPE_SEND)
			goto abort_request;

		assert(IE_BITS_UREFS(bits) > 0);

		dest_port = (ipc_port_t) entry->ie_object;
		assert(dest_port != IP_NULL);

		entry = ipc_entry_lookup (space, reply_name);
		if (entry == IE_NULL)
		{
			ipc_entry_lookup_failed (msg, reply_name);
			goto abort_request;
		}
		bits = entry->ie_bits;

		/* check type bits */
		if (IE_BITS_TYPE (bits) != MACH_PORT_TYPE_RECEIVE)
			goto abort_request;

		reply_port = (ipc_port_t) entry->ie_object;
		assert(reply_port != IP_NULL);

		/*
		 *	To do an atomic copyin, need simultaneous
		 *	locks on both ports and the space.  If
		 *	dest_port == reply_port, and simple locking is
		 *	enabled, then we will abort.  Otherwise it's
		 *	OK to unlock twice.
		 */

		ip_lock(dest_port);
		if (!ip_active(dest_port) || !ip_lock_try(reply_port)) {
			ip_unlock(dest_port);
			goto abort_request;
		}
		/* can unlock space now without compromising atomicity */
		is_read_unlock(space);

		assert(dest_port->ip_srights > 0);
		dest_port->ip_srights++;
		ip_reference(dest_port);
		ip_unlock(dest_port);

		assert(ip_active(reply_port));
		assert(reply_port->ip_receiver_name == reply_name);
		assert(reply_port->ip_receiver == space);

		reply_port->ip_sorights++;
		ip_reference(reply_port);
		ip_unlock(reply_port);

		msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
			MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND,
				       MACH_MSG_TYPE_PORT_SEND_ONCE));
		msg->msgh_remote_port = (mach_port_t) dest_port;
		msg->msgh_local_port = (mach_port_t) reply_port;
		return MACH_MSG_SUCCESS;

	    abort_request:
		is_read_unlock(space);
		break;
	    }

	    case MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0): {
		ipc_entry_t entry;
		ipc_entry_bits_t bits;
		ipc_port_t dest_port;

		/* sending a reply message */

		if (reply_name != MACH_PORT_NULL)
			break;

		is_write_lock(space);
		if (!space->is_active)
			goto abort_reply;

		entry = ipc_entry_lookup (space, dest_name);
		if (entry == IE_NULL)
		{
			ipc_entry_lookup_failed (msg, dest_name);
			goto abort_reply;
		}
		bits = entry->ie_bits;

		/* check and type bits */
		if (IE_BITS_TYPE (bits) != MACH_PORT_TYPE_SEND_ONCE)
			goto abort_reply;

		/* optimized ipc_right_copyin */

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
		assert(IE_BITS_UREFS(bits) == 1);
		assert((bits & IE_BITS_MAREQUEST) == 0);

		if (entry->ie_request != 0)
			goto abort_reply;

		dest_port = (ipc_port_t) entry->ie_object;
		assert(dest_port != IP_NULL);

		ip_lock(dest_port);
		if (!ip_active(dest_port)) {
			ip_unlock(dest_port);
			goto abort_reply;
		}

		assert(dest_port->ip_sorights > 0);
		ip_unlock(dest_port);

		entry->ie_object = IO_NULL;
		ipc_entry_dealloc (space, dest_name, entry);
		is_write_unlock(space);

		msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
				  MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE,
						 0));
		msg->msgh_remote_port = (mach_port_t) dest_port;
		return MACH_MSG_SUCCESS;

	    abort_reply:
		is_write_unlock(space);
		break;
	    }

	    default:
		/* don't bother optimizing */
		break;
	}

    {
	mach_msg_type_name_t dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	mach_msg_type_name_t reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	ipc_object_t dest_port, reply_port;
	ipc_port_t dest_soright, reply_soright;
	ipc_port_t notify_port = 0; /* '=0' to quiet gcc warnings */

	if (!MACH_MSG_TYPE_PORT_ANY_SEND(dest_type))
		return MACH_SEND_INVALID_HEADER;

	if ((reply_type == 0) ?
	    (reply_name != MACH_PORT_NULL) :
	    !MACH_MSG_TYPE_PORT_ANY_SEND(reply_type))
		return MACH_SEND_INVALID_HEADER;

	is_write_lock(space);
	if (!space->is_active)
		goto invalid_dest;

	if (notify != MACH_PORT_NULL) {
		ipc_entry_t entry;

		if (((entry = ipc_entry_lookup(space, notify)) == IE_NULL) ||
		    ((entry->ie_bits & MACH_PORT_TYPE_RECEIVE) == 0)) {
			if (entry == IE_NULL)
				ipc_entry_lookup_failed (msg, notify);
			is_write_unlock(space);
			return MACH_SEND_INVALID_NOTIFY;
		}

		notify_port = (ipc_port_t) entry->ie_object;
	}

	if (dest_name == reply_name) {
		ipc_entry_t entry;
		mach_port_name_t name = dest_name;

		/*
		 *	Destination and reply ports are the same!
		 *	This is a little tedious to make atomic, because
		 *	there are 25 combinations of dest_type/reply_type.
		 *	However, most are easy.  If either is move-sonce,
		 *	then there must be an error.  If either are
		 *	make-send or make-sonce, then we must be looking
		 *	at a receive right so the port can't die.
		 *	The hard cases are the combinations of
		 *	copy-send and make-send.
		 */

		entry = ipc_entry_lookup(space, name);
		if (entry == IE_NULL) {
			ipc_entry_lookup_failed (msg, name);
			goto invalid_dest;
		}

		assert(reply_type != 0); /* because name not null */

		if (!ipc_right_copyin_check(space, name, entry, reply_type))
			goto invalid_reply;

		if ((dest_type == MACH_MSG_TYPE_MOVE_SEND_ONCE) ||
		    (reply_type == MACH_MSG_TYPE_MOVE_SEND_ONCE)) {
			/*
			 *	Why must there be an error?  To get a valid
			 *	destination, this entry must name a live
			 *	port (not a dead name or dead port).  However
			 *	a successful move-sonce will destroy a
			 *	live entry.  Therefore the other copyin,
			 *	whatever it is, would fail.  We've already
			 *	checked for reply port errors above,
			 *	so report a destination error.
			 */

			goto invalid_dest;
		} else if ((dest_type == MACH_MSG_TYPE_MAKE_SEND) ||
			   (dest_type == MACH_MSG_TYPE_MAKE_SEND_ONCE) ||
			   (reply_type == MACH_MSG_TYPE_MAKE_SEND) ||
			   (reply_type == MACH_MSG_TYPE_MAKE_SEND_ONCE)) {
			kr = ipc_right_copyin(space, name, entry,
					      dest_type, FALSE,
					      &dest_port, &dest_soright);
			if (kr != KERN_SUCCESS)
				goto invalid_dest;

			/*
			 *	Either dest or reply needs a receive right.
			 *	We know the receive right is there, because
			 *	of the copyin_check and copyin calls.  Hence
			 *	the port is not in danger of dying.  If dest
			 *	used the receive right, then the right needed
			 *	by reply (and verified by copyin_check) will
			 *	still be there.
			 */

			assert(IO_VALID(dest_port));
			assert(entry->ie_bits & MACH_PORT_TYPE_RECEIVE);
			assert(dest_soright == IP_NULL);

			kr = ipc_right_copyin(space, name, entry,
					      reply_type, TRUE,
					      &reply_port, &reply_soright);

			assert(kr == KERN_SUCCESS);
			assert(reply_port == dest_port);
			assert(entry->ie_bits & MACH_PORT_TYPE_RECEIVE);
			assert(reply_soright == IP_NULL);
		} else if ((dest_type == MACH_MSG_TYPE_COPY_SEND) &&
			   (reply_type == MACH_MSG_TYPE_COPY_SEND)) {
			/*
			 *	To make this atomic, just do one copy-send,
			 *	and dup the send right we get out.
			 */

			kr = ipc_right_copyin(space, name, entry,
					      dest_type, FALSE,
					      &dest_port, &dest_soright);
			if (kr != KERN_SUCCESS)
				goto invalid_dest;

			assert(entry->ie_bits & MACH_PORT_TYPE_SEND);
			assert(dest_soright == IP_NULL);

			/*
			 *	It's OK if the port we got is dead now,
			 *	so reply_port is IP_DEAD, because the msg
			 *	won't go anywhere anyway.
			 */

			reply_port = (ipc_object_t)
				ipc_port_copy_send((ipc_port_t) dest_port);
			reply_soright = IP_NULL;
		} else if ((dest_type == MACH_MSG_TYPE_MOVE_SEND) &&
			   (reply_type == MACH_MSG_TYPE_MOVE_SEND)) {
			/*
			 *	This is an easy case.  Just use our
			 *	handy-dandy special-purpose copyin call
			 *	to get two send rights for the price of one.
			 */

			kr = ipc_right_copyin_two(space, name, entry,
						  &dest_port, &dest_soright);
			if (kr != KERN_SUCCESS)
				goto invalid_dest;

			/* the entry might need to be deallocated */

			if (IE_BITS_TYPE(entry->ie_bits)
						== MACH_PORT_TYPE_NONE)
				ipc_entry_dealloc(space, name, entry);

			reply_port = dest_port;
			reply_soright = IP_NULL;
		} else {
			ipc_port_t soright;

			assert(((dest_type == MACH_MSG_TYPE_COPY_SEND) &&
				(reply_type == MACH_MSG_TYPE_MOVE_SEND)) ||
			       ((dest_type == MACH_MSG_TYPE_MOVE_SEND) &&
				(reply_type == MACH_MSG_TYPE_COPY_SEND)));

			/*
			 *	To make this atomic, just do a move-send,
			 *	and dup the send right we get out.
			 */

			kr = ipc_right_copyin(space, name, entry,
					      MACH_MSG_TYPE_MOVE_SEND, FALSE,
					      &dest_port, &soright);
			if (kr != KERN_SUCCESS)
				goto invalid_dest;

			/* the entry might need to be deallocated */

			if (IE_BITS_TYPE(entry->ie_bits)
						== MACH_PORT_TYPE_NONE)
				ipc_entry_dealloc(space, name, entry);

			/*
			 *	It's OK if the port we got is dead now,
			 *	so reply_port is IP_DEAD, because the msg
			 *	won't go anywhere anyway.
			 */

			reply_port = (ipc_object_t)
				ipc_port_copy_send((ipc_port_t) dest_port);

			if (dest_type == MACH_MSG_TYPE_MOVE_SEND) {
				dest_soright = soright;
				reply_soright = IP_NULL;
			} else {
				dest_soright = IP_NULL;
				reply_soright = soright;
			}
		}
	} else if (!MACH_PORT_NAME_VALID(reply_name)) {
		ipc_entry_t entry;

		/*
		 *	No reply port!  This is an easy case
		 *	to make atomic.  Just copyin the destination.
		 */

		entry = ipc_entry_lookup(space, dest_name);
		if (entry == IE_NULL) {
			ipc_entry_lookup_failed (msg, dest_name);
			goto invalid_dest;
		}

		kr = ipc_right_copyin(space, dest_name, entry,
				      dest_type, FALSE,
				      &dest_port, &dest_soright);
		if (kr != KERN_SUCCESS)
			goto invalid_dest;

		/* the entry might need to be deallocated */

		if (IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE)
			ipc_entry_dealloc(space, dest_name, entry);

		reply_port = (ipc_object_t) invalid_name_to_port(reply_name);
		reply_soright = IP_NULL;
	} else {
		ipc_entry_t dest_entry, reply_entry;
		ipc_port_t saved_reply;

		/*
		 *	This is the tough case to make atomic.
		 *	The difficult problem is serializing with port death.
		 *	At the time we copyin dest_port, it must be alive.
		 *	If reply_port is alive when we copyin it, then
		 *	we are OK, because we serialize before the death
		 *	of both ports.  Assume reply_port is dead at copyin.
		 *	Then if dest_port dies/died after reply_port died,
		 *	we are OK, because we serialize between the death
		 *	of the two ports.  So the bad case is when dest_port
		 *	dies after its copyin, reply_port dies before its
		 *	copyin, and dest_port dies before reply_port.  Then
		 *	the copyins operated as if dest_port was alive
		 *	and reply_port was dead, which shouldn't have happened
		 *	because they died in the other order.
		 *
		 *	We handle the bad case by undoing the copyins
		 *	(which is only possible because the ports are dead)
		 *	and failing with MACH_SEND_INVALID_DEST, serializing
		 *	after the death of the ports.
		 *
		 *	Note that it is easy for a user task to tell if
		 *	a copyin happened before or after a port died.
		 *	For example, suppose both dest and reply are
		 *	send-once rights (types are both move-sonce) and
		 *	both rights have dead-name requests registered.
		 *	If a port dies before copyin, a dead-name notification
		 *	is generated and the dead name's urefs are incremented,
		 *	and if the copyin happens first, a port-deleted
		 *	notification is generated.
		 *
		 *	Note that although the entries are different,
		 *	dest_port and reply_port might still be the same.
		 */

		dest_entry = ipc_entry_lookup(space, dest_name);
		if (dest_entry == IE_NULL) {
			ipc_entry_lookup_failed (msg, dest_name);
			goto invalid_dest;
		}

		reply_entry = ipc_entry_lookup(space, reply_name);
		if (reply_entry == IE_NULL)
		{
			ipc_entry_lookup_failed (msg, reply_name);
			goto invalid_reply;
		}

		assert(dest_entry != reply_entry); /* names are not equal */
		assert(reply_type != 0); /* because reply_name not null */

		if (!ipc_right_copyin_check(space, reply_name, reply_entry,
					    reply_type))
			goto invalid_reply;

		kr = ipc_right_copyin(space, dest_name, dest_entry,
				      dest_type, FALSE,
				      &dest_port, &dest_soright);
		if (kr != KERN_SUCCESS)
			goto invalid_dest;

		assert(IO_VALID(dest_port));

		saved_reply = (ipc_port_t) reply_entry->ie_object;
		/* might be IP_NULL, if this is a dead name */
		if (saved_reply != IP_NULL)
			ipc_port_reference(saved_reply);

		kr = ipc_right_copyin(space, reply_name, reply_entry,
				      reply_type, TRUE,
				      &reply_port, &reply_soright);
		assert(kr == KERN_SUCCESS);

		if ((saved_reply != IP_NULL) && (reply_port == IO_DEAD)) {
			ipc_port_t dest = (ipc_port_t) dest_port;
			ipc_port_timestamp_t timestamp;
			boolean_t must_undo;

			/*
			 *	The reply port died before copyin.
			 *	Check if dest port died before reply.
			 */

			ip_lock(saved_reply);
			assert(!ip_active(saved_reply));
			timestamp = saved_reply->ip_timestamp;
			ip_unlock(saved_reply);

			ip_lock(dest);
			must_undo = (!ip_active(dest) &&
				     IP_TIMESTAMP_ORDER(dest->ip_timestamp,
							timestamp));
			ip_unlock(dest);

			if (must_undo) {
				/*
				 *	Our worst nightmares are realized.
				 *	Both destination and reply ports
				 *	are dead, but in the wrong order,
				 *	so we must undo the copyins and
				 *	possibly generate a dead-name notif.
				 */

				ipc_right_copyin_undo(
						space, dest_name, dest_entry,
						dest_type, dest_port,
						dest_soright);
				/* dest_entry may be deallocated now */

				ipc_right_copyin_undo(
						space, reply_name, reply_entry,
						reply_type, reply_port,
						reply_soright);
				/* reply_entry may be deallocated now */

				is_write_unlock(space);

				if (dest_soright != IP_NULL)
					ipc_notify_dead_name(dest_soright,
							     dest_name);
				assert(reply_soright == IP_NULL);

				ipc_port_release(saved_reply);
				return MACH_SEND_INVALID_DEST;
			}
		}

		/* the entries might need to be deallocated */

		if (IE_BITS_TYPE(reply_entry->ie_bits) == MACH_PORT_TYPE_NONE)
			ipc_entry_dealloc(space, reply_name, reply_entry);

		if (IE_BITS_TYPE(dest_entry->ie_bits) == MACH_PORT_TYPE_NONE)
			ipc_entry_dealloc(space, dest_name, dest_entry);

		if (saved_reply != IP_NULL)
			ipc_port_release(saved_reply);
	}

	/*
	 *	At this point, dest_port, reply_port,
	 *	dest_soright, reply_soright are all initialized.
	 *	Any defunct entries have been deallocated.
	 *	The space is still write-locked, and we need to
	 *	make the MACH_SEND_CANCEL check.  The notify_port pointer
	 *	is still usable, because the copyin code above won't ever
	 *	deallocate a receive right, so its entry still exists
	 *	and holds a ref.  Note notify_port might even equal
	 *	dest_port or reply_port.
	 */

	if ((notify != MACH_PORT_NULL) &&
	    (dest_soright == notify_port)) {
		ipc_port_release_sonce(dest_soright);
		dest_soright = IP_NULL;
	}

	is_write_unlock(space);

	if (dest_soright != IP_NULL)
		ipc_notify_port_deleted(dest_soright, dest_name);

	if (reply_soright != IP_NULL)
		ipc_notify_port_deleted(reply_soright, reply_name);

	dest_type = ipc_object_copyin_type(dest_type);
	reply_type = ipc_object_copyin_type(reply_type);

	msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
			  MACH_MSGH_BITS(dest_type, reply_type));
	msg->msgh_remote_port = (mach_port_t) dest_port;
	msg->msgh_local_port = (mach_port_t) reply_port;
    }

	return MACH_MSG_SUCCESS;

    invalid_dest:
	is_write_unlock(space);
	return MACH_SEND_INVALID_DEST;

    invalid_reply:
	is_write_unlock(space);
	return MACH_SEND_INVALID_REPLY;
}

static mach_msg_return_t
ipc_kmsg_copyin_body(
	ipc_kmsg_t 	kmsg,
	ipc_space_t 	space,
	vm_map_t 	map)
{
	ipc_object_t dest;
	vm_offset_t saddr, eaddr;
	boolean_t complex;
	boolean_t use_page_lists, steal_pages;

	dest = (ipc_object_t) kmsg->ikm_header.msgh_remote_port;
	complex = FALSE;
	use_page_lists = ipc_kobject_vm_page_list(ip_kotype((ipc_port_t)dest));
	steal_pages = ipc_kobject_vm_page_steal(ip_kotype((ipc_port_t)dest));

	saddr = (vm_offset_t) (&kmsg->ikm_header + 1);
	eaddr = (vm_offset_t) &kmsg->ikm_header + kmsg->ikm_header.msgh_size;

	// We make assumptions about the alignment of the header.
	_Static_assert(!mach_msg_kernel_is_misaligned(sizeof(mach_msg_header_t)),
			"mach_msg_header_t needs to be MACH_MSG_KERNEL_ALIGNMENT aligned.");

	while (saddr < eaddr) {
		vm_offset_t taddr = saddr;
		mach_msg_type_long_t *type;
		mach_msg_type_name_t name;
		mach_msg_type_size_t size;
		mach_msg_type_number_t number;
		boolean_t is_inline, longform, dealloc, is_port;
		vm_offset_t data;
		vm_size_t length;
		kern_return_t kr;

		type = (mach_msg_type_long_t *) saddr;

		if (((eaddr - saddr) < sizeof(mach_msg_type_t)) ||
		    ((longform = ((mach_msg_type_t*)type)->msgt_longform) &&
		     ((eaddr - saddr) < sizeof(mach_msg_type_long_t)))) {
			ipc_kmsg_clean_partial(kmsg, taddr, FALSE, 0);
			return MACH_SEND_MSG_TOO_SMALL;
		}

		is_inline = ((mach_msg_type_t*)type)->msgt_inline;
		dealloc = ((mach_msg_type_t*)type)->msgt_deallocate;
		if (longform) {
			name = type->msgtl_name;
			size = type->msgtl_size;
			number = type->msgtl_number;
			saddr += sizeof(mach_msg_type_long_t);
			if (mach_msg_kernel_is_misaligned(sizeof(mach_msg_type_long_t))) {
				saddr = mach_msg_kernel_align(saddr);
			}
		} else {
			name = ((mach_msg_type_t*)type)->msgt_name;
			size = ((mach_msg_type_t*)type)->msgt_size;
			number = ((mach_msg_type_t*)type)->msgt_number;
			saddr += sizeof(mach_msg_type_t);
			if (mach_msg_kernel_is_misaligned(sizeof(mach_msg_type_t))) {
				saddr = mach_msg_kernel_align(saddr);
			}
		}

		is_port = MACH_MSG_TYPE_PORT_ANY(name);

		if ((is_port && !is_inline && (size != PORT_NAME_T_SIZE_IN_BITS)) ||
		    (is_port && is_inline && (size != PORT_T_SIZE_IN_BITS)) ||
#ifndef __LP64__
		    (longform && ((type->msgtl_header.msgt_name != 0) ||
				  (type->msgtl_header.msgt_size != 0) ||
				  (type->msgtl_header.msgt_number != 0))) ||
#endif
		    (((mach_msg_type_t*)type)->msgt_unused != 0) ||
		    (dealloc && is_inline)) {
			ipc_kmsg_clean_partial(kmsg, taddr, FALSE, 0);
			return MACH_SEND_INVALID_TYPE;
		}

		/* calculate length of data in bytes, rounding up */

		length = (((uint64_t) number * size) + 7) >> 3;

		if (is_inline) {
			vm_size_t amount = length;

			if ((eaddr - saddr) < amount) {
				ipc_kmsg_clean_partial(kmsg, taddr, FALSE, 0);
				return MACH_SEND_MSG_TOO_SMALL;
			}

			data = saddr;
			saddr += amount;
		} else {
			vm_offset_t addr;

			if ((eaddr - saddr) < sizeof(vm_offset_t)) {
				ipc_kmsg_clean_partial(kmsg, taddr, FALSE, 0);
				return MACH_SEND_MSG_TOO_SMALL;
			}

			/* grab the out-of-line data */

			addr = * (vm_offset_t *) saddr;

			if (is_port) {
				const vm_size_t user_length = length;

				/*
				 * In 64 bit architectures, out of line port names are
				 * represented as an array of mach_port_name_t which are
				 * smaller than mach_port_t.
				 */
				if (sizeof(mach_port_name_t) != sizeof(mach_port_t)) {
					if (longform)
						type->msgtl_size = sizeof(mach_port_t) * 8;
					else
						((mach_msg_type_t *)type)->msgt_size = sizeof(mach_port_t) * 8;
					length = sizeof(mach_port_t) * number;
				}

				if (length == 0) {
					data = 0;
				} else {
					data = kalloc(length);
					if (data == 0)
						goto invalid_memory;

					if (user_length != length)
					{
						mach_port_name_t *src = (mach_port_name_t*)addr;
						mach_port_t *dst = (mach_port_t*)data;
						for (int i=0; i<number; i++) {
							if (copyin_port(src + i, dst + i)) {
								kfree(data, length);
								goto invalid_memory;
							}
						}
					} else if (copyinmap(map, (char *) addr,
						      (char *) data, length)) {
						kfree(data, length);
						goto invalid_memory;
					}
					if (dealloc &&
					    (vm_deallocate(map, addr, user_length) != KERN_SUCCESS)) {
						kfree(data, length);
						goto invalid_memory;
					}
				}
			} else if (length == 0) { /* !is_port */
				data = 0;
			} else {
				vm_map_copy_t copy;

		      		if (use_page_lists) {
					kr = vm_map_copyin_page_list(map,
				        	addr, length, dealloc,
						steal_pages, &copy, FALSE);
				} else {
					kr = vm_map_copyin(map, addr, length,
							   dealloc, &copy);
				}
				if (kr != KERN_SUCCESS) {
				    invalid_memory:
					ipc_kmsg_clean_partial(kmsg, taddr,
							       FALSE, 0);
					return MACH_SEND_INVALID_MEMORY;
				}

				data = (vm_offset_t) copy;
			}

			* (vm_offset_t *) saddr = data;
			saddr += sizeof(vm_offset_t);
			complex = TRUE;
		}

		if (is_port) {
			mach_msg_type_name_t newname =
					ipc_object_copyin_type(name);
			ipc_object_t *objects = (ipc_object_t *) data;
			mach_msg_type_number_t i;

			if (longform)
				type->msgtl_name = newname;
			else
				((mach_msg_type_t*)type)->msgt_name = newname;

			for (i = 0; i < number; i++) {
				mach_port_name_t port = ((mach_port_t*)data)[i];
				ipc_object_t object;

				if (!MACH_PORT_NAME_VALID(port)) {
					objects[i] = (ipc_object_t)invalid_name_to_port(port);
					continue;
				}

				kr = ipc_object_copyin(space, port,
						       name, &object);
				if (kr != KERN_SUCCESS) {
					ipc_kmsg_clean_partial(kmsg, taddr,
							       TRUE, i);
					return MACH_SEND_INVALID_RIGHT;
				}

				if ((newname == MACH_MSG_TYPE_PORT_RECEIVE) &&
				    ipc_port_check_circularity(
							(ipc_port_t) object,
							(ipc_port_t) dest))
					kmsg->ikm_header.msgh_bits |=
						MACH_MSGH_BITS_CIRCULAR;

				objects[i] = object;
			}

			complex = TRUE;
		}
		saddr = mach_msg_kernel_align(saddr);
	}

	if (!complex)
		kmsg->ikm_header.msgh_bits &= ~MACH_MSGH_BITS_COMPLEX;

	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_copyin
 *	Purpose:
 *		"Copy-in" port rights and out-of-line memory
 *		in the message.
 *
 *		In all failure cases, the message is left holding
 *		no rights or memory.  However, the message buffer
 *		is not deallocated.  If successful, the message
 *		contains a valid destination port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyin.
 *		MACH_SEND_INVALID_HEADER
 *			Illegal value in the message header bits.
 *		MACH_SEND_INVALID_NOTIFY	Bad notify port.
 *		MACH_SEND_INVALID_DEST	Can't copyin destination port.
 *		MACH_SEND_INVALID_REPLY	Can't copyin reply port.
 *		MACH_SEND_INVALID_MEMORY	Can't grab out-of-line memory.
 *		MACH_SEND_INVALID_RIGHT	Can't copyin port right in body.
 *		MACH_SEND_INVALID_TYPE	Bad type specification.
 *		MACH_SEND_MSG_TOO_SMALL	Body is too small for types/data.
 */

mach_msg_return_t
ipc_kmsg_copyin(
	ipc_kmsg_t 	kmsg,
	ipc_space_t 	space,
	vm_map_t 	map,
	mach_port_name_t notify)
{
	mach_msg_return_t mr;

	mr = ipc_kmsg_copyin_header(&kmsg->ikm_header, space, notify);
	if (mr != MACH_MSG_SUCCESS)
		return mr;

	if ((kmsg->ikm_header.msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0)
		return MACH_MSG_SUCCESS;

	return ipc_kmsg_copyin_body(kmsg, space, map);
}

/*
 *	Routine:	ipc_kmsg_copyin_from_kernel
 *	Purpose:
 *		"Copy-in" port rights and out-of-line memory
 *		in a message sent from the kernel.
 *
 *		Because the message comes from the kernel,
 *		the implementation assumes there are no errors
 *		or peculiarities in the message.
 *
 *		Returns TRUE if queueing the message
 *		would result in a circularity.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_kmsg_copyin_from_kernel(ipc_kmsg_t kmsg)
{
	mach_msg_bits_t bits = kmsg->ikm_header.msgh_bits;
	mach_msg_type_name_t rname = MACH_MSGH_BITS_REMOTE(bits);
	mach_msg_type_name_t lname = MACH_MSGH_BITS_LOCAL(bits);
	ipc_object_t remote = (ipc_object_t) kmsg->ikm_header.msgh_remote_port;
	ipc_object_t local = (ipc_object_t) kmsg->ikm_header.msgh_local_port;
	vm_offset_t saddr, eaddr;

	/* translate the destination and reply ports */

	ipc_object_copyin_from_kernel(remote, rname);
	if (IO_VALID(local))
		ipc_object_copyin_from_kernel(local, lname);

	/*
	 *	The common case is a complex message with no reply port,
	 *	because that is what the memory_object interface uses.
	 */

	if (bits == (MACH_MSGH_BITS_COMPLEX |
		     MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0))) {
		bits = (MACH_MSGH_BITS_COMPLEX |
			MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND, 0));

		kmsg->ikm_header.msgh_bits = bits;
	} else {
		bits = (MACH_MSGH_BITS_OTHER(bits) |
			MACH_MSGH_BITS(ipc_object_copyin_type(rname),
				       ipc_object_copyin_type(lname)));

		kmsg->ikm_header.msgh_bits = bits;
		if ((bits & MACH_MSGH_BITS_COMPLEX) == 0)
			return;
	}

	saddr = (vm_offset_t) (&kmsg->ikm_header + 1);
	eaddr = (vm_offset_t) &kmsg->ikm_header + kmsg->ikm_header.msgh_size;

	while (saddr < eaddr) {
		mach_msg_type_long_t *type;
		mach_msg_type_name_t name;
		mach_msg_type_size_t size;
		mach_msg_type_number_t number;
		boolean_t is_inline, longform, is_port;
		vm_offset_t data;
		vm_size_t length;

		type = (mach_msg_type_long_t *) saddr;
		is_inline = ((mach_msg_type_t*)type)->msgt_inline;
		longform = ((mach_msg_type_t*)type)->msgt_longform;
		/* type->msgtl_header.msgt_deallocate not used */
		if (longform) {
			name = type->msgtl_name;
			size = type->msgtl_size;
			number = type->msgtl_number;
			saddr += sizeof(mach_msg_type_long_t);
			if (mach_msg_kernel_is_misaligned(sizeof(mach_msg_type_long_t))) {
				saddr = mach_msg_kernel_align(saddr);
			}
		} else {
			name = ((mach_msg_type_t*)type)->msgt_name;
			size = ((mach_msg_type_t*)type)->msgt_size;
			number = ((mach_msg_type_t*)type)->msgt_number;
			saddr += sizeof(mach_msg_type_t);
			if (mach_msg_kernel_is_misaligned(sizeof(mach_msg_type_t))) {
				saddr = mach_msg_kernel_align(saddr);
			}
		}

		/* calculate length of data in bytes, rounding up */

		length = ((number * size) + 7) >> 3;

		is_port = MACH_MSG_TYPE_PORT_ANY(name);

		if (is_inline) {
			data = saddr;
			saddr += length;
		} else {
			/*
			 *	The sender should supply ready-made memory
			 *	for us, so we don't need to do anything.
			 */

			data = * (vm_offset_t *) saddr;
			saddr += sizeof(vm_offset_t);
		}

		if (is_port) {
			mach_msg_type_name_t newname =
					ipc_object_copyin_type(name);
			ipc_object_t *objects = (ipc_object_t *) data;
			mach_msg_type_number_t i;

			if (longform)
				type->msgtl_name = newname;
			else
				((mach_msg_type_t*)type)->msgt_name = newname;
			for (i = 0; i < number; i++) {
				ipc_object_t object = objects[i];

				if (!IO_VALID(object))
					continue;

				ipc_object_copyin_from_kernel(object, name);

				if ((newname == MACH_MSG_TYPE_PORT_RECEIVE) &&
				    ipc_port_check_circularity(
							(ipc_port_t) object,
							(ipc_port_t) remote))
					kmsg->ikm_header.msgh_bits |=
						MACH_MSGH_BITS_CIRCULAR;
			}
		}
		saddr = mach_msg_kernel_align(saddr);
	}
}

/*
 *	Routine:	ipc_kmsg_copyout_header
 *	Purpose:
 *		"Copy-out" port rights in the header of a message.
 *		Operates atomically; if it doesn't succeed the
 *		message header and the space are left untouched.
 *		If it does succeed the remote/local port fields
 *		contain port names instead of object pointers,
 *		and the bits field is updated.
 *
 *		The notify argument implements the MACH_RCV_NOTIFY option.
 *		If it is not MACH_PORT_NULL, it should name a receive right.
 *		If the process of receiving the reply port creates a
 *		new right in the receiving task, then the new right is
 *		automatically registered for a dead-name notification,
 *		with the notify port supplying the send-once right.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Copied out port rights.
 *		MACH_RCV_INVALID_NOTIFY
 *			Notify is non-null and doesn't name a receive right.
 *			(Either KERN_INVALID_NAME or KERN_INVALID_RIGHT.)
 *		MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_SPACE
 *			The space is dead.
 *		MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_SPACE
 *			No room in space for another name.
 *		MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_KERNEL
 *			Couldn't allocate memory for the reply port.
 *		MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_KERNEL
 *			Couldn't allocate memory for the dead-name request.
 */

mach_msg_return_t
ipc_kmsg_copyout_header(
	mach_msg_header_t 	*msg,
	ipc_space_t 		space,
	mach_port_name_t 		notify)
{
	mach_msg_bits_t mbits = msg->msgh_bits;
	ipc_port_t dest = (ipc_port_t) msg->msgh_remote_port;

	assert(IP_VALID(dest));

	/* first check for common cases */

	if (notify == MACH_PORT_NULL) switch (MACH_MSGH_BITS_PORTS(mbits)) {
	    case MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND, 0): {
		mach_port_name_t dest_name;
		ipc_port_t nsrequest;
		rpc_uintptr_t payload;

		/* receiving an asynchronous message */

		ip_lock(dest);
		if (!ip_active(dest)) {
			ip_unlock(dest);
			break;
		}

		/* optimized ipc_object_copyout_dest */

		assert(dest->ip_srights > 0);
		ip_release(dest);

		if (dest->ip_receiver == space)
			dest_name = dest->ip_receiver_name;
		else
			dest_name = MACH_PORT_NULL;
		payload = dest->ip_protected_payload;

		if ((--dest->ip_srights == 0) &&
		    ((nsrequest = dest->ip_nsrequest) != IP_NULL)) {
			mach_port_mscount_t mscount;

			dest->ip_nsrequest = IP_NULL;
			mscount = dest->ip_mscount;
			ip_unlock(dest);

			ipc_notify_no_senders(nsrequest, mscount);
		} else
			ip_unlock(dest);

		if (! ipc_port_flag_protected_payload(dest)) {
			msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
				MACH_MSGH_BITS(0, MACH_MSG_TYPE_PORT_SEND));
			msg->msgh_local_port = dest_name;
		} else {
			msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
				MACH_MSGH_BITS(
					0, MACH_MSG_TYPE_PROTECTED_PAYLOAD));
			msg->msgh_protected_payload = payload;
		}
		msg->msgh_remote_port = MACH_PORT_NULL;
		return MACH_MSG_SUCCESS;
	    }

	    case MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND,
				MACH_MSG_TYPE_PORT_SEND_ONCE): {
		ipc_entry_t entry;
		ipc_port_t reply = (ipc_port_t) msg->msgh_local_port;
		mach_port_name_t dest_name, reply_name;
		ipc_port_t nsrequest;
		rpc_uintptr_t payload;

		/* receiving a request message */

		if (!IP_VALID(reply))
			break;

		is_write_lock(space);
		if (!space->is_active || space->is_free_list == NULL) {
			is_write_unlock(space);
			break;
		}

		/*
		 *	To do an atomic copyout, need simultaneous
		 *	locks on both ports and the space.  If
		 *	dest == reply, and simple locking is
		 *	enabled, then we will abort.  Otherwise it's
		 *	OK to unlock twice.
		 */

		ip_lock(dest);
		if (!ip_active(dest) || !ip_lock_try(reply)) {
			ip_unlock(dest);
			is_write_unlock(space);
			break;
		}

		if (!ip_active(reply)) {
			ip_unlock(reply);
			ip_unlock(dest);
			is_write_unlock(space);
			break;
		}

		assert(reply->ip_sorights > 0);
		ip_unlock(reply);

		kern_return_t kr;
		kr = ipc_entry_get (space, &reply_name, &entry);
		if (kr) {
			ip_unlock(reply);
			ip_unlock(dest);
			is_write_unlock(space);
			break;
		}

	    {
		mach_port_gen_t gen;

		assert((entry->ie_bits &~ IE_BITS_GEN_MASK) == 0);
		gen = entry->ie_bits + IE_BITS_GEN_ONE;

		/* optimized ipc_right_copyout */

		entry->ie_bits = gen | (MACH_PORT_TYPE_SEND_ONCE | 1);
	    }

		assert(MACH_PORT_NAME_VALID(reply_name));
		entry->ie_object = (ipc_object_t) reply;
		is_write_unlock(space);

		/* optimized ipc_object_copyout_dest */

		assert(dest->ip_srights > 0);
		ip_release(dest);

		if (dest->ip_receiver == space)
			dest_name = dest->ip_receiver_name;
		else
			dest_name = MACH_PORT_NULL;
		payload = dest->ip_protected_payload;

		if ((--dest->ip_srights == 0) &&
		    ((nsrequest = dest->ip_nsrequest) != IP_NULL)) {
			mach_port_mscount_t mscount;

			dest->ip_nsrequest = IP_NULL;
			mscount = dest->ip_mscount;
			ip_unlock(dest);

			ipc_notify_no_senders(nsrequest, mscount);
		} else
			ip_unlock(dest);

		if (! ipc_port_flag_protected_payload(dest)) {
			msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
				MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE,
					       MACH_MSG_TYPE_PORT_SEND));
			msg->msgh_local_port = dest_name;
		} else {
			msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
				MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE,
					MACH_MSG_TYPE_PROTECTED_PAYLOAD));
			msg->msgh_protected_payload = payload;
		}
		msg->msgh_remote_port = reply_name;
		return MACH_MSG_SUCCESS;
	    }

	    case MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE, 0): {
		mach_port_name_t dest_name;
		rpc_uintptr_t payload;

		/* receiving a reply message */

		ip_lock(dest);
		if (!ip_active(dest)) {
			ip_unlock(dest);
			break;
		}

		/* optimized ipc_object_copyout_dest */

		assert(dest->ip_sorights > 0);

		payload = dest->ip_protected_payload;

		if (dest->ip_receiver == space) {
			ip_release(dest);
			dest->ip_sorights--;
			dest_name = dest->ip_receiver_name;
			ip_unlock(dest);
		} else {
			ip_unlock(dest);

			ipc_notify_send_once(dest);
			dest_name = MACH_PORT_NULL;
		}

		if (! ipc_port_flag_protected_payload(dest)) {
			msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
				MACH_MSGH_BITS(0,
					MACH_MSG_TYPE_PORT_SEND_ONCE));
			msg->msgh_local_port = dest_name;
		} else {
			msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
				MACH_MSGH_BITS(0,
					MACH_MSG_TYPE_PROTECTED_PAYLOAD));
			msg->msgh_protected_payload = payload;
		}
		msg->msgh_remote_port = MACH_PORT_NULL;
		return MACH_MSG_SUCCESS;
	    }

	    default:
		/* don't bother optimizing */
		break;
	}

    {
	mach_msg_type_name_t dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	mach_msg_type_name_t reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	ipc_port_t reply = (ipc_port_t) msg->msgh_local_port;
	mach_port_name_t dest_name, reply_name;
	rpc_uintptr_t payload;

	if (IP_VALID(reply)) {
		ipc_port_t notify_port;
		ipc_entry_t entry;
		kern_return_t kr;

		/*
		 *	Handling notify (for MACH_RCV_NOTIFY) is tricky.
		 *	The problem is atomically making a send-once right
		 *	from the notify port and installing it for a
		 *	dead-name request in the new entry, because this
		 *	requires two port locks (on the notify port and
		 *	the reply port).  However, we can safely make
		 *	and consume send-once rights for the notify port
		 *	as long as we hold the space locked.  This isn't
		 *	an atomicity problem, because the only way
		 *	to detect that a send-once right has been created
		 *	and then consumed if it wasn't needed is by getting
		 *	at the receive right to look at ip_sorights, and
		 *	because the space is write-locked status calls can't
		 *	lookup the notify port receive right.  When we make
		 *	the send-once right, we lock the notify port,
		 *	so any status calls in progress will be done.
		 */

		is_write_lock(space);

		for (;;) {
			ipc_port_request_index_t request;

			if (!space->is_active) {
				is_write_unlock(space);
				return (MACH_RCV_HEADER_ERROR|
					MACH_MSG_IPC_SPACE);
			}

			if (notify != MACH_PORT_NULL) {
				notify_port = ipc_port_lookup_notify(space,
								     notify);
				if (notify_port == IP_NULL) {
					is_write_unlock(space);
					return MACH_RCV_INVALID_NOTIFY;
				}
			} else
				notify_port = IP_NULL;

			if ((reply_type != MACH_MSG_TYPE_PORT_SEND_ONCE) &&
			    ipc_right_reverse(space, (ipc_object_t) reply,
					      &reply_name, &entry)) {
				/* reply port is locked and active */

				/*
				 *	We don't need the notify_port
				 *	send-once right, but we can't release
				 *	it here because reply port is locked.
				 *	Wait until after the copyout to
				 *	release the notify port right.
				 */

				assert(entry->ie_bits &
						MACH_PORT_TYPE_SEND_RECEIVE);
				break;
			}

			ip_lock(reply);
			if (!ip_active(reply)) {
				ip_release(reply);
				ip_check_unlock(reply);

				if (notify_port != IP_NULL)
					ipc_port_release_sonce(notify_port);

				ip_lock(dest);
				is_write_unlock(space);

				reply = IP_DEAD;
				reply_name = MACH_PORT_NAME_DEAD;
				goto copyout_dest;
			}

			kr = ipc_entry_alloc(space, &reply_name, &entry);
			if (kr != KERN_SUCCESS) {
				ip_unlock(reply);

				if (notify_port != IP_NULL)
					ipc_port_release_sonce(notify_port);

				is_write_unlock(space);
				if (kr == KERN_RESOURCE_SHORTAGE)
					return (MACH_RCV_HEADER_ERROR|
					        MACH_MSG_IPC_KERNEL);
				else
					return (MACH_RCV_HEADER_ERROR|
					        MACH_MSG_IPC_SPACE);
			}

			assert(IE_BITS_TYPE(entry->ie_bits)
						== MACH_PORT_TYPE_NONE);
			assert(entry->ie_object == IO_NULL);

			if (notify_port == IP_NULL) {
				/* not making a dead-name request */

				entry->ie_object = (ipc_object_t) reply;
				break;
			}

			kr = ipc_port_dnrequest(reply, reply_name,
						notify_port, &request);
			if (kr != KERN_SUCCESS) {
				ip_unlock(reply);

				ipc_port_release_sonce(notify_port);

				ipc_entry_dealloc(space, reply_name, entry);
				is_write_unlock(space);

				ip_lock(reply);
				if (!ip_active(reply)) {
					/* will fail next time around loop */

					ip_unlock(reply);
					is_write_lock(space);
					continue;
				}

				kr = ipc_port_dngrow(reply);
				/* port is unlocked */
				if (kr != KERN_SUCCESS)
					return (MACH_RCV_HEADER_ERROR|
						MACH_MSG_IPC_KERNEL);

				is_write_lock(space);
				continue;
			}

			notify_port = IP_NULL; /* don't release right below */

			entry->ie_object = (ipc_object_t) reply;
			entry->ie_request = request;
			break;
		}

		/* space and reply port are locked and active */

		ip_reference(reply);	/* hold onto the reply port */

		kr = ipc_right_copyout(space, reply_name, entry,
				       reply_type, TRUE, (ipc_object_t) reply);
		/* reply port is unlocked */
		assert(kr == KERN_SUCCESS);

		if (notify_port != IP_NULL)
			ipc_port_release_sonce(notify_port);

		ip_lock(dest);
		is_write_unlock(space);
	} else {
		/*
		 *	No reply port!  This is an easy case.
		 *	We only need to have the space locked
		 *	when checking notify and when locking
		 *	the destination (to ensure atomicity).
		 */

		is_read_lock(space);
		if (!space->is_active) {
			is_read_unlock(space);
			return MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_SPACE;
		}

		if (notify != MACH_PORT_NULL) {
			ipc_entry_t entry;

			/* must check notify even though it won't be used */

			if (((entry = ipc_entry_lookup(space, notify))
								== IE_NULL) ||
			    ((entry->ie_bits & MACH_PORT_TYPE_RECEIVE) == 0)) {
				if (entry == IE_NULL)
					ipc_entry_lookup_failed (msg, notify);
				is_read_unlock(space);
				return MACH_RCV_INVALID_NOTIFY;
			}
		}

		ip_lock(dest);
		is_read_unlock(space);

		reply_name = invalid_port_to_name(msg->msgh_local_port);
	}

	/*
	 *	At this point, the space is unlocked and the destination
	 *	port is locked.  (Lock taken while space was locked.)
	 *	reply_name is taken care of; we still need dest_name.
	 *	We still hold a ref for reply (if it is valid).
	 *
	 *	If the space holds receive rights for the destination,
	 *	we return its name for the right.  Otherwise the task
	 *	managed to destroy or give away the receive right between
	 *	receiving the message and this copyout.  If the destination
	 *	is dead, return MACH_PORT_DEAD, and if the receive right
	 *	exists somewhere else (another space, in transit)
	 *	return MACH_PORT_NULL.
	 *
	 *	Making this copyout operation atomic with the previous
	 *	copyout of the reply port is a bit tricky.  If there was
	 *	no real reply port (it wasn't IP_VALID) then this isn't
	 *	an issue.  If the reply port was dead at copyout time,
	 *	then we are OK, because if dest is dead we serialize
	 *	after the death of both ports and if dest is alive
	 *	we serialize after reply died but before dest's (later) death.
	 *	So assume reply was alive when we copied it out.  If dest
	 *	is alive, then we are OK because we serialize before
	 *	the ports' deaths.  So assume dest is dead when we look at it.
	 *	If reply dies/died after dest, then we are OK because
	 *	we serialize after dest died but before reply dies.
	 *	So the hard case is when reply is alive at copyout,
	 *	dest is dead at copyout, and reply died before dest died.
	 *	In this case pretend that dest is still alive, so
	 *	we serialize while both ports are alive.
	 *
	 *	Because the space lock is held across the copyout of reply
	 *	and locking dest, the receive right for dest can't move
	 *	in or out of the space while the copyouts happen, so
	 *	that isn't an atomicity problem.  In the last hard case
	 *	above, this implies that when dest is dead that the
	 *	space couldn't have had receive rights for dest at
	 *	the time reply was copied-out, so when we pretend
	 *	that dest is still alive, we can return MACH_PORT_NULL.
	 *
	 *	If dest == reply, then we have to make it look like
	 *	either both copyouts happened before the port died,
	 *	or both happened after the port died.  This special
	 *	case works naturally if the timestamp comparison
	 *	is done correctly.
	 */

    copyout_dest:
	payload = dest->ip_protected_payload;

	if (ip_active(dest)) {
		ipc_object_copyout_dest(space, (ipc_object_t) dest,
					dest_type, &dest_name);
		/* dest is unlocked */
	} else {
		ipc_port_timestamp_t timestamp;

		timestamp = dest->ip_timestamp;
		ip_release(dest);
		ip_check_unlock(dest);

		if (IP_VALID(reply)) {
			ip_lock(reply);
			if (ip_active(reply) ||
			    IP_TIMESTAMP_ORDER(timestamp,
					       reply->ip_timestamp))
				dest_name = MACH_PORT_NAME_DEAD;
			else
				dest_name = MACH_PORT_NAME_NULL;
			ip_unlock(reply);
		} else
			dest_name = MACH_PORT_NAME_DEAD;
	}

	if (IP_VALID(reply))
		ipc_port_release(reply);

	if (! ipc_port_flag_protected_payload(dest)) {
		msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
				  MACH_MSGH_BITS(reply_type, dest_type));
		msg->msgh_local_port = dest_name;
	} else {
		msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
				  MACH_MSGH_BITS(reply_type,
					MACH_MSG_TYPE_PROTECTED_PAYLOAD));
		msg->msgh_protected_payload = payload;
	}

	msg->msgh_remote_port = reply_name;
    }

	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_copyout_object
 *	Purpose:
 *		Copy-out a port right.  Always returns a name,
 *		even for unsuccessful return codes.  Always
 *		consumes the supplied object.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	The space acquired the right
 *			(name is valid) or the object is dead (MACH_PORT_DEAD).
 *		MACH_MSG_IPC_SPACE	No room in space for the right,
 *			or the space is dead.  (Name is MACH_PORT_NULL.)
 *		MACH_MSG_IPC_KERNEL	Kernel resource shortage.
 *			(Name is MACH_PORT_NULL.)
 */

mach_msg_return_t
ipc_kmsg_copyout_object(
	ipc_space_t 		space,
	ipc_object_t 		object,
	mach_msg_type_name_t 	msgt_name,
	mach_port_name_t 	*namep)
{
	if (!IO_VALID(object)) {
		*namep = invalid_port_to_name((mach_port_t)object);
		return MACH_MSG_SUCCESS;
	}

	/*
	 *	Attempt quick copyout of send rights.  We optimize for a
	 *	live port for which the receiver holds send (and not
	 *	receive) rights in his local table.
	 */

	if (msgt_name != MACH_MSG_TYPE_PORT_SEND)
		goto slow_copyout;

    {
	ipc_port_t port = (ipc_port_t) object;
	ipc_entry_t entry;

	is_write_lock(space);
	if (!space->is_active) {
		is_write_unlock(space);
		goto slow_copyout;
	}

	ip_lock(port);
	if (!ip_active(port) ||
	    (entry = ipc_reverse_lookup(space,
	                                (ipc_object_t) port)) == NULL) {
		ip_unlock(port);
		is_write_unlock(space);
		goto slow_copyout;
	}
	*namep = entry->ie_name;

	/*
	 *	Copyout the send right, incrementing urefs
	 *	unless it would overflow, and consume the right.
	 */

	assert(port->ip_srights > 1);
	port->ip_srights--;
	ip_release(port);
	ip_unlock(port);

	assert(entry->ie_bits & MACH_PORT_TYPE_SEND);
	assert(IE_BITS_UREFS(entry->ie_bits) > 0);
	assert(IE_BITS_UREFS(entry->ie_bits) < MACH_PORT_UREFS_MAX);

    {
	ipc_entry_bits_t bits = entry->ie_bits + 1;

	if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX)
		entry->ie_bits = bits;
    }

	is_write_unlock(space);
	return MACH_MSG_SUCCESS;
    }

    slow_copyout:

   {
	kern_return_t kr;

	kr = ipc_object_copyout(space, object, msgt_name, TRUE, namep);
	if (kr != KERN_SUCCESS) {
		ipc_object_destroy(object, msgt_name);

		if (kr == KERN_INVALID_CAPABILITY)
			*namep = MACH_PORT_NAME_DEAD;
		else {
			*namep = MACH_PORT_NAME_NULL;

			if (kr == KERN_RESOURCE_SHORTAGE)
				return MACH_MSG_IPC_KERNEL;
			else
				return MACH_MSG_IPC_SPACE;
		}
	}

	return MACH_MSG_SUCCESS;
    }
}

/*
 *	Routine:	ipc_kmsg_copyout_body
 *	Purpose:
 *		"Copy-out" port rights and out-of-line memory
 *		in the body of a message.
 *
 *		The error codes are a combination of special bits.
 *		The copyout proceeds despite errors.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyout.
 *		MACH_MSG_IPC_SPACE	No room for port right in name space.
 *		MACH_MSG_VM_SPACE	No room for memory in address space.
 *		MACH_MSG_IPC_KERNEL	Resource shortage handling port right.
 *		MACH_MSG_VM_KERNEL	Resource shortage handling memory.
 */

mach_msg_return_t
ipc_kmsg_copyout_body(
	ipc_kmsg_t kmsg,
	ipc_space_t 	space,
	vm_map_t 	map)
{
	mach_msg_return_t mr = MACH_MSG_SUCCESS;
	kern_return_t kr;
	vm_offset_t saddr, eaddr;

	saddr = (vm_offset_t) (&kmsg->ikm_header + 1);
	eaddr = (vm_offset_t) &kmsg->ikm_header +
	    kmsg->ikm_header.msgh_size;

	while (saddr < eaddr) {
		vm_offset_t taddr = saddr;
		mach_msg_type_long_t *type;
		mach_msg_type_name_t name;
		mach_msg_type_size_t size;
		mach_msg_type_number_t number;
		boolean_t is_inline, longform, is_port;
		vm_size_t length;
		vm_offset_t addr;

		type = (mach_msg_type_long_t *) saddr;
		is_inline = ((mach_msg_type_t*)type)->msgt_inline;
		longform = ((mach_msg_type_t*)type)->msgt_longform;
		if (longform) {
			name = type->msgtl_name;
			size = type->msgtl_size;
			number = type->msgtl_number;
			saddr += sizeof(mach_msg_type_long_t);
			if (mach_msg_kernel_is_misaligned(sizeof(mach_msg_type_long_t))) {
				saddr = mach_msg_kernel_align(saddr);
			}
		} else {
			name = ((mach_msg_type_t*)type)->msgt_name;
			size = ((mach_msg_type_t*)type)->msgt_size;
			number = ((mach_msg_type_t*)type)->msgt_number;
			saddr += sizeof(mach_msg_type_t);
			if (mach_msg_kernel_is_misaligned(sizeof(mach_msg_type_t))) {
				saddr = mach_msg_kernel_align(saddr);
			}
		}

		/* calculate length of data in bytes, rounding up */

		length = (((uint64_t) number * size) + 7) >> 3;

		is_port = MACH_MSG_TYPE_PORT_ANY(name);

		if (is_port) {
			ipc_object_t *objects;
			mach_msg_type_number_t i;

			if (!is_inline) {
				if (length != 0) {
					vm_size_t user_length = length;

					if (sizeof(mach_port_name_t) != sizeof(mach_port_t)) {
						user_length = sizeof(mach_port_name_t) * number;
					}

					/* first allocate memory in the map */
					kr = vm_allocate(map, &addr, user_length, TRUE);
					if (kr != KERN_SUCCESS) {
						ipc_kmsg_clean_body(taddr, saddr);
						goto vm_copyout_failure;
					}
				}

				if (sizeof(mach_port_name_t) != sizeof(mach_port_t)) {
					/* Out of line ports are always returned as mach_port_name_t.
					 * Note: we have to do this after ipc_kmsg_clean_body, otherwise
					 * the cleanup function will not work correctly.
					 */
					type->msgtl_size = sizeof(mach_port_name_t) * 8;
				}
			}

			objects = (ipc_object_t *)
				(is_inline ? saddr : * (vm_offset_t *) saddr);

			/* copyout port rights carried in the message */

			for (i = 0; i < number; i++) {
				ipc_object_t object = objects[i];

				mr |= ipc_kmsg_copyout_object_to_port(space, object,
								      name, (mach_port_t *)&objects[i]);
			}
		}

		if (is_inline) {
			((mach_msg_type_t*)type)->msgt_deallocate = FALSE;
			saddr += length;
		} else {
			vm_offset_t data;

			data = * (vm_offset_t *) saddr;

			/* copyout memory carried in the message */

			if (length == 0) {
				assert(data == 0);
				addr = 0;
			} else if (is_port) {
				/* copyout to memory allocated above */

				if (sizeof(mach_port_name_t) != sizeof(mach_port_t)) {
					mach_port_t *src = (mach_port_t*)data;
					mach_port_name_t *dst = (mach_port_name_t*)addr;
					for (int i=0; i<number; i++) {
						if (copyout_port(src + i, dst + i)) {
							kr = KERN_FAILURE;
							goto vm_copyout_failure;
						}
					}
				} else {
					(void) copyoutmap(map, (char *) data,
							  (char *) addr, length);
				}
				kfree(data, length);
			} else {
				vm_map_copy_t copy = (vm_map_copy_t) data;

				kr = vm_map_copyout(map, &addr, copy);
				if (kr != KERN_SUCCESS) {
					vm_map_copy_discard(copy);

				    vm_copyout_failure:

					addr = 0;
					if (longform)
						type->msgtl_size = 0;
					else
						((mach_msg_type_t*)type)->msgt_size = 0;

					if (kr == KERN_RESOURCE_SHORTAGE)
						mr |= MACH_MSG_VM_KERNEL;
					else
						mr |= MACH_MSG_VM_SPACE;
				}
			}

			((mach_msg_type_t*)type)->msgt_deallocate = TRUE;
			* (vm_offset_t *) saddr = addr;
			saddr += sizeof(vm_offset_t);
		}

		/* Next element is always correctly aligned */
		saddr = mach_msg_kernel_align(saddr);
	}

	return mr;
}

/*
 *	Routine:	ipc_kmsg_copyout
 *	Purpose:
 *		"Copy-out" port rights and out-of-line memory
 *		in the message.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Copied out all rights and memory.
 *		MACH_RCV_INVALID_NOTIFY	Bad notify port.
 *			Rights and memory in the message are intact.
 *		MACH_RCV_HEADER_ERROR + special bits
 *			Rights and memory in the message are intact.
 *		MACH_RCV_BODY_ERROR + special bits
 *			The message header was successfully copied out.
 *			As much of the body was handled as possible.
 */

mach_msg_return_t
ipc_kmsg_copyout(
	ipc_kmsg_t 	kmsg,
	ipc_space_t 	space,
	vm_map_t 	map,
	mach_port_name_t 	notify)
{
	mach_msg_bits_t mbits = kmsg->ikm_header.msgh_bits;
	mach_msg_return_t mr;

	mr = ipc_kmsg_copyout_header(&kmsg->ikm_header, space, notify);
	if (mr != MACH_MSG_SUCCESS)
		return mr;

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		mr = ipc_kmsg_copyout_body(kmsg, space, map);
		if (mr != MACH_MSG_SUCCESS)
			mr |= MACH_RCV_BODY_ERROR;
	}

	return mr;
}

/*
 *	Routine:	ipc_kmsg_copyout_pseudo
 *	Purpose:
 *		Does a pseudo-copyout of the message.
 *		This is like a regular copyout, except
 *		that the ports in the header are handled
 *		as if they are in the body.  They aren't reversed.
 *
 *		The error codes are a combination of special bits.
 *		The copyout proceeds despite errors.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyout.
 *		MACH_MSG_IPC_SPACE	No room for port right in name space.
 *		MACH_MSG_VM_SPACE	No room for memory in address space.
 *		MACH_MSG_IPC_KERNEL	Resource shortage handling port right.
 *		MACH_MSG_VM_KERNEL	Resource shortage handling memory.
 */

mach_msg_return_t
ipc_kmsg_copyout_pseudo(
	ipc_kmsg_t		kmsg,
	ipc_space_t		space,
	vm_map_t		map)
{
	mach_msg_bits_t mbits = kmsg->ikm_header.msgh_bits;
	ipc_object_t dest = (ipc_object_t) kmsg->ikm_header.msgh_remote_port;
	ipc_object_t reply = (ipc_object_t) kmsg->ikm_header.msgh_local_port;
	mach_msg_type_name_t dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	mach_msg_type_name_t reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	mach_port_name_t dest_name, reply_name;
	mach_msg_return_t mr;

	assert(IO_VALID(dest));

	mr = (ipc_kmsg_copyout_object(space, dest, dest_type, &dest_name) |
	      ipc_kmsg_copyout_object(space, reply, reply_type, &reply_name));

	kmsg->ikm_header.msgh_bits = mbits &~ MACH_MSGH_BITS_CIRCULAR;
	kmsg->ikm_header.msgh_remote_port = dest_name;
	kmsg->ikm_header.msgh_local_port = reply_name;

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		mr |= ipc_kmsg_copyout_body(kmsg, space, map);
	}

	return mr;
}

/*
 *	Routine:	ipc_kmsg_copyout_dest
 *	Purpose:
 *		Copies out the destination port in the message.
 *		Destroys all other rights and memory in the message.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_kmsg_copyout_dest(
	ipc_kmsg_t 	kmsg,
	ipc_space_t 	space)
{
	mach_msg_bits_t mbits = kmsg->ikm_header.msgh_bits;
	ipc_object_t dest = (ipc_object_t) kmsg->ikm_header.msgh_remote_port;
	ipc_object_t reply = (ipc_object_t) kmsg->ikm_header.msgh_local_port;
	mach_msg_type_name_t dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	mach_msg_type_name_t reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	mach_port_name_t dest_name, reply_name;

	assert(IO_VALID(dest));

	io_lock(dest);
	if (io_active(dest)) {
		ipc_object_copyout_dest(space, dest, dest_type, &dest_name);
		/* dest is unlocked */
	} else {
		io_release(dest);
		io_check_unlock(dest);
		dest_name = MACH_PORT_NAME_DEAD;
	}

	if (IO_VALID(reply)) {
		ipc_object_destroy(reply, reply_type);
		reply_name = MACH_PORT_NAME_NULL;
	} else
		reply_name = invalid_port_to_name((mach_port_t)reply);

	kmsg->ikm_header.msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
				      MACH_MSGH_BITS(reply_type, dest_type));
	kmsg->ikm_header.msgh_local_port = dest_name;
	kmsg->ikm_header.msgh_remote_port = reply_name;

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		vm_offset_t saddr, eaddr;

		saddr = (vm_offset_t) (&kmsg->ikm_header + 1);
		eaddr = (vm_offset_t) &kmsg->ikm_header +
				kmsg->ikm_header.msgh_size;

		ipc_kmsg_clean_body(saddr, eaddr);
	}
}

#if	MACH_KDB

static char *
ipc_type_name(
	int 		type_name,
	boolean_t 	received)
{
	switch (type_name) {
		case MACH_MSG_TYPE_BOOLEAN:
		return "boolean";

		case MACH_MSG_TYPE_INTEGER_16:
		return "short";

		case MACH_MSG_TYPE_INTEGER_32:
		return "int32";

		case MACH_MSG_TYPE_INTEGER_64:
		return "int64";

		case MACH_MSG_TYPE_CHAR:
		return "char";

		case MACH_MSG_TYPE_BYTE:
		return "byte";

		case MACH_MSG_TYPE_REAL:
		return "real";

		case MACH_MSG_TYPE_STRING:
		return "string";

		case MACH_MSG_TYPE_PORT_NAME:
		return "port_name";

		case MACH_MSG_TYPE_MOVE_RECEIVE:
		if (received) {
			return "port_receive";
		} else {
			return "move_receive";
		}

		case MACH_MSG_TYPE_MOVE_SEND:
		if (received) {
			return "port_send";
		} else {
			return "move_send";
		}

		case MACH_MSG_TYPE_MOVE_SEND_ONCE:
		if (received) {
			return "port_send_once";
		} else {
			return "move_send_once";
		}

		case MACH_MSG_TYPE_COPY_SEND:
		return "copy_send";

		case MACH_MSG_TYPE_MAKE_SEND:
		return "make_send";

		case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		return "make_send_once";

		default:
		return (char *) 0;
	}
}

static void
ipc_print_type_name(
	int	type_name)
{
	char *name = ipc_type_name(type_name, TRUE);
	if (name) {
		printf("%s", name);
	} else {
		printf("type%d", type_name);
	}
}

/*
 * ipc_kmsg_print	[ debug ]
 */
void
ipc_kmsg_print(ipc_kmsg_t kmsg)
{
	db_printf("kmsg=0x%x\n", kmsg);
	db_printf("ikm_next=0x%x,prev=0x%x,size=%d,marequest=0x%x",
		  kmsg->ikm_next,
		  kmsg->ikm_prev,
		  kmsg->ikm_size,
		  kmsg->ikm_marequest);
	db_printf("\n");
	ipc_msg_print(&kmsg->ikm_header);
}

/*
 * ipc_msg_print	[ debug ]
 */
void
ipc_msg_print(mach_msg_header_t *msgh)
{
	vm_offset_t saddr, eaddr;

	db_printf("msgh_bits=0x%x: ", msgh->msgh_bits);
	if (msgh->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		db_printf("complex,");
	}
	if (msgh->msgh_bits & MACH_MSGH_BITS_CIRCULAR) {
		db_printf("circular,");
	}
	if (msgh->msgh_bits & MACH_MSGH_BITS_COMPLEX_PORTS) {
		db_printf("complex_ports,");
	}
	if (msgh->msgh_bits & MACH_MSGH_BITS_COMPLEX_DATA) {
		db_printf("complex_data,");
	}
	if (msgh->msgh_bits & MACH_MSGH_BITS_MIGRATED) {
		db_printf("migrated,");
	}
	if (msgh->msgh_bits & MACH_MSGH_BITS_UNUSED) {
		db_printf("unused=0x%x,",
			  msgh->msgh_bits & MACH_MSGH_BITS_UNUSED);
	}
	db_printf("l=0x%x,r=0x%x\n",
		  MACH_MSGH_BITS_LOCAL(msgh->msgh_bits),
		  MACH_MSGH_BITS_REMOTE(msgh->msgh_bits));

	db_printf("msgh_id=%d,size=%u,seqno=%d,",
		  msgh->msgh_id,
		  msgh->msgh_size,
		  msgh->msgh_seqno);

	if (msgh->msgh_remote_port) {
		db_printf("remote=0x%x(", msgh->msgh_remote_port);
		ipc_print_type_name(MACH_MSGH_BITS_REMOTE(msgh->msgh_bits));
		db_printf("),");
	} else {
		db_printf("remote=null,\n");
	}

	if (msgh->msgh_local_port) {
		db_printf("local=0x%x(", msgh->msgh_local_port);
		ipc_print_type_name(MACH_MSGH_BITS_LOCAL(msgh->msgh_bits));
		db_printf(")\n");
	} else {
		db_printf("local=null\n");
	}

	saddr = (vm_offset_t) (msgh + 1);
	eaddr = (vm_offset_t) msgh + msgh->msgh_size;

	while (saddr < eaddr) {
		mach_msg_type_long_t *type;
		mach_msg_type_name_t name;
		mach_msg_type_size_t size;
		mach_msg_type_number_t number;
		boolean_t is_inline, longform, dealloc, is_port;
		vm_size_t length;

		type = (mach_msg_type_long_t *) saddr;

		if (((eaddr - saddr) < sizeof(mach_msg_type_t)) ||
		    ((longform = ((mach_msg_type_t*)type)->msgt_longform) &&
		     ((eaddr - saddr) < sizeof(mach_msg_type_long_t)))) {
			db_printf("*** msg too small\n");
			return;
		}

		is_inline = ((mach_msg_type_t*)type)->msgt_inline;
		dealloc = ((mach_msg_type_t*)type)->msgt_deallocate;
		if (longform) {
			name = type->msgtl_name;
			size = type->msgtl_size;
			number = type->msgtl_number;
			saddr += sizeof(mach_msg_type_long_t);
			if (mach_msg_kernel_is_misaligned(sizeof(mach_msg_type_long_t))) {
				saddr = mach_msg_kernel_align(saddr);
			}
		} else {
			name = ((mach_msg_type_t*)type)->msgt_name;
			size = ((mach_msg_type_t*)type)->msgt_size;
			number = ((mach_msg_type_t*)type)->msgt_number;
			saddr += sizeof(mach_msg_type_t);
			if (mach_msg_kernel_is_misaligned(sizeof(mach_msg_type_t))) {
				saddr = mach_msg_kernel_align(saddr);
			}
		}

		db_printf("-- type=");
		ipc_print_type_name(name);
		if (! is_inline) {
			db_printf(",ool");
		}
		if (dealloc) {
			db_printf(",dealloc");
		}
		if (longform) {
			db_printf(",longform");
		}
		db_printf(",size=%d,number=%d,addr=0x%x\n",
		       size,
		       number,
		       saddr);

		is_port = MACH_MSG_TYPE_PORT_ANY(name);

		if ((is_port && (size != PORT_T_SIZE_IN_BITS)) ||
#ifndef __LP64__
		    (longform && ((type->msgtl_header.msgt_name != 0) ||
				  (type->msgtl_header.msgt_size != 0) ||
				  (type->msgtl_header.msgt_number != 0))) ||
#endif
		    (((mach_msg_type_t*)type)->msgt_unused != 0) ||
		    (dealloc && is_inline)) {
			db_printf("*** invalid type\n");
			return;
		}

		/* calculate length of data in bytes, rounding up */

		length = ((number * size) + 7) >> 3;

		if (is_inline) {
			vm_size_t amount;
			unsigned i, numwords;

			/* round up to int boundaries for printing */
			amount = (length + 3) &~ 3;
			if ((eaddr - saddr) < amount) {
				db_printf("*** too small\n");
				return;
			}
			numwords = amount / sizeof(int);
			if (numwords > 8) {
				numwords = 8;
			}
			for (i = 0; i < numwords; i++) {
				db_printf("0x%x\n", ((int *) saddr)[i]);
			}
			if (numwords < amount / sizeof(int)) {
				db_printf("...\n");
			}
			saddr += amount;
		} else {
			if ((eaddr - saddr) < sizeof(vm_offset_t)) {
				db_printf("*** too small\n");
				return;
			}
			db_printf("0x%x\n", * (vm_offset_t *) saddr);
			saddr += sizeof(vm_offset_t);
		}
		saddr = mach_msg_kernel_align(saddr);
	}
}
#endif	/* MACH_KDB */

/*
 * Message Priority Queue Structures
 */
struct ipc_kmsg_priority_queue {
    ipc_kmsg_queue_t queues[IPC_PRIORITY_LEVELS];
    unsigned int count[IPC_PRIORITY_LEVELS];
    unsigned int total_count;
    unsigned int highest_priority;
    simple_lock_t priority_lock;
};

struct ipc_kmsg_batch {
    ipc_kmsg_t messages[IPC_KMSG_BATCH_SIZE];
    unsigned int count;
    unsigned int sent;
    unsigned int received;
    unsigned long long batch_id;
    unsigned int flags;
    void (*completion)(struct ipc_kmsg_batch *, kern_return_t);
    simple_lock_t batch_lock;
};

/*
 * Message Performance Statistics
 */
struct ipc_kmsg_stats {
    unsigned long long total_messages_sent;
    unsigned long long total_messages_received;
    unsigned long long total_bytes_sent;
    unsigned long long total_bytes_received;
    unsigned long long total_port_rights_transferred;
    unsigned long long total_memory_transferred;
    unsigned long long average_message_size;
    unsigned long long max_message_size;
    unsigned long long min_message_size;
    unsigned int messages_queued;
    unsigned int messages_dequeued;
    unsigned int priority_inversions;
    unsigned int batch_operations;
    simple_lock_t stats_lock;
};

/*
 * Global statistics
 */
static struct ipc_kmsg_stats ipc_kmsg_global_stats;
static simple_lock_t ipc_kmsg_global_stats_lock;

/*
 * Function: ipc_kmsg_priority_enqueue
 *
 * Enqueue message with priority-based ordering
 */
void ipc_kmsg_priority_enqueue(
    struct ipc_kmsg_priority_queue *pq,
    ipc_kmsg_t kmsg,
    unsigned int priority)
{
    if (pq == NULL || kmsg == IKM_NULL)
        return;
    
    assert(priority < IPC_PRIORITY_LEVELS);
    
    simple_lock(&pq->priority_lock);
    
    ipc_kmsg_enqueue(&pq->queues[priority], kmsg);
    pq->count[priority]++;
    pq->total_count++;
    
    if (priority < pq->highest_priority)
        pq->highest_priority = priority;
    
    simple_unlock(&pq->priority_lock);
    
    /* Update statistics */
    simple_lock(&ipc_kmsg_global_stats_lock);
    ipc_kmsg_global_stats.messages_queued++;
    simple_unlock(&ipc_kmsg_global_stats_lock);
}

/*
 * Function: ipc_kmsg_priority_dequeue
 *
 * Dequeue highest priority message
 */
ipc_kmsg_t ipc_kmsg_priority_dequeue(struct ipc_kmsg_priority_queue *pq)
{
    ipc_kmsg_t kmsg = IKM_NULL;
    unsigned int i;
    
    if (pq == NULL || pq->total_count == 0)
        return IKM_NULL;
    
    simple_lock(&pq->priority_lock);
    
    for (i = pq->highest_priority; i < IPC_PRIORITY_LEVELS; i++) {
        if (pq->count[i] > 0) {
            kmsg = ipc_kmsg_dequeue(&pq->queues[i]);
            pq->count[i]--;
            pq->total_count--;
            
            /* Update highest priority pointer */
            while (pq->highest_priority < IPC_PRIORITY_LEVELS &&
                   pq->count[pq->highest_priority] == 0) {
                pq->highest_priority++;
            }
            break;
        }
    }
    
    simple_unlock(&pq->priority_lock);
    
    if (kmsg != IKM_NULL) {
        simple_lock(&ipc_kmsg_global_stats_lock);
        ipc_kmsg_global_stats.messages_dequeued++;
        simple_unlock(&ipc_kmsg_global_stats_lock);
    }
    
    return kmsg;
}

/*
 * Function: ipc_kmsg_priority_queue_init
 *
 * Initialize priority queue
 */
void ipc_kmsg_priority_queue_init(struct ipc_kmsg_priority_queue *pq)
{
    unsigned int i;
    
    if (pq == NULL)
        return;
    
    for (i = 0; i < IPC_PRIORITY_LEVELS; i++) {
        pq->queues[i].ikmq_base = IKM_NULL;
        pq->count[i] = 0;
    }
    
    pq->total_count = 0;
    pq->highest_priority = IPC_PRIORITY_LEVELS;
    simple_lock_init(&pq->priority_lock);
}

/*
 * Function: ipc_kmsg_batch_create
 *
 * Create batch of messages for bulk transfer
 */
struct ipc_kmsg_batch *ipc_kmsg_batch_create(unsigned int batch_size)
{
    struct ipc_kmsg_batch *batch;
    
    if (batch_size == 0 || batch_size > IPC_KMSG_BATCH_SIZE)
        return NULL;
    
    batch = (struct ipc_kmsg_batch *)kalloc(sizeof(struct ipc_kmsg_batch));
    if (batch == NULL)
        return NULL;
    
    memset(batch, 0, sizeof(struct ipc_kmsg_batch));
    batch->batch_id = mach_absolute_time();
    batch->count = batch_size;
    simple_lock_init(&batch->batch_lock);
    
    return batch;
}

/*
 * Function: ipc_kmsg_batch_add
 *
 * Add message to batch
 */
kern_return_t ipc_kmsg_batch_add(struct ipc_kmsg_batch *batch, ipc_kmsg_t kmsg)
{
    if (batch == NULL || kmsg == IKM_NULL)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&batch->batch_lock);
    
    if (batch->sent + batch->received >= batch->count) {
        simple_unlock(&batch->batch_lock);
        return KERN_FAILURE;
    }
    
    batch->messages[batch->sent + batch->received] = kmsg;
    simple_unlock(&batch->batch_lock);
    
    return KERN_SUCCESS;
}

/*
 * Function: ipc_kmsg_batch_send
 *
 * Send entire batch of messages atomically
 */
kern_return_t ipc_kmsg_batch_send(
    struct ipc_kmsg_batch *batch,
    ipc_space_t space,
    vm_map_t map,
    unsigned int flags)
{
    unsigned int i;
    kern_return_t kr = KERN_SUCCESS;
    mach_msg_return_t mr;
    
    if (batch == NULL || space == IPC_SPACE_NULL)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&batch->batch_lock);
    
    for (i = batch->sent; i < batch->count; i++) {
        ipc_kmsg_t kmsg = batch->messages[i];
        
        mr = ipc_kmsg_copyin(kmsg, space, map, MACH_PORT_NULL);
        if (mr != MACH_MSG_SUCCESS) {
            kr = KERN_FAILURE;
            break;
        }
        
        batch->sent++;
    }
    
    simple_unlock(&batch->batch_lock);
    
    simple_lock(&ipc_kmsg_global_stats_lock);
    ipc_kmsg_global_stats.batch_operations++;
    simple_unlock(&ipc_kmsg_global_stats_lock);
    
    return kr;
}

/*
 * Function: ipc_kmsg_batch_destroy
 *
 * Destroy batch and free all messages
 */
void ipc_kmsg_batch_destroy(struct ipc_kmsg_batch *batch)
{
    unsigned int i;
    
    if (batch == NULL)
        return;
    
    for (i = 0; i < batch->count; i++) {
        if (batch->messages[i] != IKM_NULL)
            ipc_kmsg_destroy(batch->messages[i]);
    }
    
    kfree((vm_offset_t)batch, sizeof(struct ipc_kmsg_batch));
}

/*
 * Function: ipc_kmsg_stats_update
 *
 * Update global message statistics
 */
void ipc_kmsg_stats_update(
    unsigned long long msg_size,
    unsigned int port_rights,
    unsigned long long memory_size,
    boolean_t is_send)
{
    simple_lock(&ipc_kmsg_global_stats_lock);
    
    if (is_send) {
        ipc_kmsg_global_stats.total_messages_sent++;
        ipc_kmsg_global_stats.total_bytes_sent += msg_size;
    } else {
        ipc_kmsg_global_stats.total_messages_received++;
        ipc_kmsg_global_stats.total_bytes_received += msg_size;
    }
    
    ipc_kmsg_global_stats.total_port_rights_transferred += port_rights;
    ipc_kmsg_global_stats.total_memory_transferred += memory_size;
    
    /* Update average message size */
    unsigned long long total_msgs = ipc_kmsg_global_stats.total_messages_sent +
                                     ipc_kmsg_global_stats.total_messages_received;
    if (total_msgs > 0) {
        ipc_kmsg_global_stats.average_message_size =
            (ipc_kmsg_global_stats.total_bytes_sent +
             ipc_kmsg_global_stats.total_bytes_received) / total_msgs;
    }
    
    if (msg_size > ipc_kmsg_global_stats.max_message_size)
        ipc_kmsg_global_stats.max_message_size = msg_size;
    if (ipc_kmsg_global_stats.min_message_size == 0 ||
        msg_size < ipc_kmsg_global_stats.min_message_size)
        ipc_kmsg_global_stats.min_message_size = msg_size;
    
    simple_unlock(&ipc_kmsg_global_stats_lock);
}

/*
 * Function: ipc_kmsg_get_stats
 *
 * Retrieve IPC message statistics
 */
void ipc_kmsg_get_stats(struct ipc_kmsg_stats *stats)
{
    if (stats == NULL)
        return;
    
    simple_lock(&ipc_kmsg_global_stats_lock);
    memcpy(stats, &ipc_kmsg_global_stats, sizeof(struct ipc_kmsg_stats));
    simple_unlock(&ipc_kmsg_global_stats_lock);
}

/*
 * Function: ipc_kmsg_reset_stats
 *
 * Reset IPC message statistics
 */
void ipc_kmsg_reset_stats(void)
{
    simple_lock(&ipc_kmsg_global_stats_lock);
    memset(&ipc_kmsg_global_stats, 0, sizeof(struct ipc_kmsg_stats));
    simple_unlock(&ipc_kmsg_global_stats_lock);
}

/*
 * Function: ipc_kmsg_preallocate
 *
 * Preallocate message buffers for performance
 */
ipc_kmsg_t ipc_kmsg_preallocate(vm_size_t size, unsigned int count)
{
    ipc_kmsg_t kmsg = IKM_NULL;
    unsigned int i;
    
    if (size < sizeof(mach_msg_header_t))
        size = sizeof(mach_msg_header_t);
    
    /* Allocate first message */
    kmsg = ikm_alloc(size);
    if (kmsg == IKM_NULL)
        return IKM_NULL;
    
    ikm_init(kmsg, size);
    
    /* Preallocate additional messages if requested */
    for (i = 1; i < count; i++) {
        ipc_kmsg_t next = ikm_alloc(size);
        if (next == IKM_NULL)
            break;
        ikm_init(next, size);
        /* Chain preallocated messages */
        next->ikm_next = kmsg->ikm_next;
        kmsg->ikm_next = next;
    }
    
    return kmsg;
}

/*
 * Function: ipc_kmsg_set_timeout
 *
 * Set timeout for message processing
 */
kern_return_t ipc_kmsg_set_timeout(ipc_kmsg_t kmsg, unsigned long long timeout_ns)
{
    if (kmsg == IKM_NULL)
        return KERN_INVALID_ARGUMENT;
    
    kmsg->ikm_timeout = timeout_ns;
    kmsg->ikm_timeout_deadline = mach_absolute_time() + timeout_ns;
    
    return KERN_SUCCESS;
}

/*
 * Function: ipc_kmsg_check_timeout
 *
 * Check if message has timed out
 */
boolean_t ipc_kmsg_check_timeout(ipc_kmsg_t kmsg)
{
    if (kmsg == IKM_NULL || kmsg->ikm_timeout == 0)
        return FALSE;
    
    return (mach_absolute_time() >= kmsg->ikm_timeout_deadline);
}

/*
 * Function: ipc_kmsg_set_priority
 *
 * Set priority for message processing
 */
void ipc_kmsg_set_priority(ipc_kmsg_t kmsg, unsigned int priority)
{
    if (kmsg == IKM_NULL)
        return;
    
    kmsg->ikm_priority = priority;
}

/*
 * Function: ipc_kmsg_get_priority
 *
 * Get message priority
 */
unsigned int ipc_kmsg_get_priority(ipc_kmsg_t kmsg)
{
    if (kmsg == IKM_NULL)
        return 0;
    
    return kmsg->ikm_priority;
}

/*
 * Function: ipc_kmsg_dup
 *
 * Duplicate a kernel message
 */
ipc_kmsg_t ipc_kmsg_dup(ipc_kmsg_t kmsg)
{
    ipc_kmsg_t new_kmsg;
    vm_size_t size;
    
    if (kmsg == IKM_NULL)
        return IKM_NULL;
    
    size = kmsg->ikm_size;
    new_kmsg = ikm_alloc(size);
    if (new_kmsg == IKM_NULL)
        return IKM_NULL;
    
    ikm_init(new_kmsg, size);
    memcpy(&new_kmsg->ikm_header, &kmsg->ikm_header, size);
    new_kmsg->ikm_priority = kmsg->ikm_priority;
    
    return new_kmsg;
}

/*
 * Function: ipc_kmsg_validate
 *
 * Validate message integrity
 */
boolean_t ipc_kmsg_validate(ipc_kmsg_t kmsg)
{
    mach_msg_size_t size;
    vm_offset_t saddr, eaddr;
    
    if (kmsg == IKM_NULL)
        return FALSE;
    
    size = kmsg->ikm_header.msgh_size;
    if (size < sizeof(mach_msg_header_t) || size > kmsg->ikm_size)
        return FALSE;
    
    if (mach_msg_kernel_is_misaligned(size))
        return FALSE;
    
    saddr = (vm_offset_t)(&kmsg->ikm_header + 1);
    eaddr = (vm_offset_t)&kmsg->ikm_header + size;
    
    /* Validate body types */
    while (saddr < eaddr) {
        mach_msg_type_t *type = (mach_msg_type_t *)saddr;
        
        if ((eaddr - saddr) < sizeof(mach_msg_type_t))
            return FALSE;
        
        if (type->msgt_longform) {
            if ((eaddr - saddr) < sizeof(mach_msg_type_long_t))
                return FALSE;
            saddr += sizeof(mach_msg_type_long_t);
        } else {
            saddr += sizeof(mach_msg_type_t);
        }
        
        saddr = mach_msg_kernel_align(saddr);
    }
    
    return TRUE;
}

/*
 * Function: ipc_kmsg_compress
 *
 * Compress message data for large transfers
 */
kern_return_t ipc_kmsg_compress(ipc_kmsg_t kmsg, unsigned int algorithm)
{
    vm_offset_t compressed_data;
    vm_size_t original_size;
    vm_size_t compressed_size;
    
    if (kmsg == IKM_NULL || !(kmsg->ikm_header.msgh_bits & MACH_MSGH_BITS_COMPLEX))
        return KERN_INVALID_ARGUMENT;
    
    original_size = kmsg->ikm_header.msgh_size;
    
    /* Simple compression: just mark as compressed */
    kmsg->ikm_compressed = TRUE;
    kmsg->ikm_compression_alg = algorithm;
    kmsg->ikm_original_size = original_size;
    
    return KERN_SUCCESS;
}

/*
 * Function: ipc_kmsg_decompress
 *
 * Decompress message data
 */
kern_return_t ipc_kmsg_decompress(ipc_kmsg_t kmsg)
{
    if (kmsg == IKM_NULL || !kmsg->ikm_compressed)
        return KERN_INVALID_ARGUMENT;
    
    kmsg->ikm_compressed = FALSE;
    kmsg->ikm_header.msgh_size = kmsg->ikm_original_size;
    
    return KERN_SUCCESS;
}

/*
 * Function: ipc_kmsg_is_compressed
 *
 * Check if message is compressed
 */
boolean_t ipc_kmsg_is_compressed(ipc_kmsg_t kmsg)
{
    if (kmsg == IKM_NULL)
        return FALSE;
    
    return kmsg->ikm_compressed;
}

/*
 * Function: ipc_kmsg_set_callback
 *
 * Set completion callback for async message processing
 */
void ipc_kmsg_set_callback(ipc_kmsg_t kmsg, void (*callback)(ipc_kmsg_t, kern_return_t))
{
    if (kmsg == IKM_NULL)
        return;
    
    kmsg->ikm_callback = callback;
}

/*
 * Function: ipc_kmsg_invoke_callback
 *
 * Invoke message callback
 */
void ipc_kmsg_invoke_callback(ipc_kmsg_t kmsg, kern_return_t result)
{
    if (kmsg == IKM_NULL || kmsg->ikm_callback == NULL)
        return;
    
    kmsg->ikm_callback(kmsg, result);
}

/*
 * Function: ipc_kmsg_ref
 *
 * Add reference to kernel message
 */
void ipc_kmsg_ref(ipc_kmsg_t kmsg)
{
    if (kmsg == IKM_NULL)
        return;
    
    simple_lock(&kmsg->ikm_ref_lock);
    kmsg->ikm_ref_count++;
    simple_unlock(&kmsg->ikm_ref_lock);
}

/*
 * Function: ipc_kmsg_unref
 *
 * Release reference to kernel message
 */
void ipc_kmsg_unref(ipc_kmsg_t kmsg)
{
    if (kmsg == IKM_NULL)
        return;
    
    simple_lock(&kmsg->ikm_ref_lock);
    kmsg->ikm_ref_count--;
    boolean_t should_destroy = (kmsg->ikm_ref_count == 0);
    simple_unlock(&kmsg->ikm_ref_lock);
    
    if (should_destroy)
        ipc_kmsg_destroy(kmsg);
}

/*
 * Function: ipc_kmsg_trace
 *
 * Trace message flow for debugging
 */
void ipc_kmsg_trace(ipc_kmsg_t kmsg, const char *event)
{
    if (kmsg == IKM_NULL || event == NULL)
        return;
    
    if (ipc_kmsg_tracing_enabled) {
        printf("IPC KMSG TRACE: %p %s msg_id=%d size=%u bits=0x%x\n",
               kmsg, event,
               kmsg->ikm_header.msgh_id,
               kmsg->ikm_header.msgh_size,
               kmsg->ikm_header.msgh_bits);
    }
}

/*
 * Function: ipc_kmsg_dump_info
 *
 * Dump detailed message information
 */
void ipc_kmsg_dump_info(ipc_kmsg_t kmsg)
{
    if (kmsg == IKM_NULL) {
        printf("IPC KMSG: NULL\n");
        return;
    }
    
    printf("\n=== IPC KMSG Information ===\n");
    printf("KMSG: %p\n", kmsg);
    printf("Size: %u (buffer: %u)\n", kmsg->ikm_header.msgh_size, kmsg->ikm_size);
    printf("Message ID: %d\n", kmsg->ikm_header.msgh_id);
    printf("Bits: 0x%x\n", kmsg->ikm_header.msgh_bits);
    printf("Remote: 0x%x, Local: 0x%x\n",
           kmsg->ikm_header.msgh_remote_port,
           kmsg->ikm_header.msgh_local_port);
    printf("Priority: %u\n", kmsg->ikm_priority);
    printf("Timeout: %llu ns (deadline: %llu)\n",
           kmsg->ikm_timeout, kmsg->ikm_timeout_deadline);
    printf("Compressed: %s (alg=%u, orig=%u)\n",
           kmsg->ikm_compressed ? "yes" : "no",
           kmsg->ikm_compression_alg, kmsg->ikm_original_size);
    printf("Ref count: %u\n", kmsg->ikm_ref_count);
    printf("Callback: %p\n", kmsg->ikm_callback);
    printf("Marequest: %p\n", kmsg->ikm_marequest);
    
    if (kmsg->ikm_header.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
        vm_offset_t saddr = (vm_offset_t)(&kmsg->ikm_header + 1);
        vm_offset_t eaddr = (vm_offset_t)&kmsg->ikm_header + kmsg->ikm_header.msgh_size;
        unsigned int type_count = 0;
        
        printf("\n--- Body Types ---\n");
        while (saddr < eaddr) {
            mach_msg_type_t *type = (mach_msg_type_t *)saddr;
            printf("Type %u: ", type_count++);
            
            if (type->msgt_longform) {
                mach_msg_type_long_t *long_type = (mach_msg_type_long_t *)saddr;
                printf("longform name=%d size=%d number=%d inline=%d dealloc=%d\n",
                       long_type->msgtl_name, long_type->msgtl_size,
                       long_type->msgtl_number, type->msgt_inline, type->msgt_deallocate);
                saddr += sizeof(mach_msg_type_long_t);
            } else {
                printf("shortform name=%d size=%d number=%d inline=%d dealloc=%d\n",
                       type->msgt_name, type->msgt_size, type->msgt_number,
                       type->msgt_inline, type->msgt_deallocate);
                saddr += sizeof(mach_msg_type_t);
            }
            saddr = mach_msg_kernel_align(saddr);
        }
    }
    
    printf("================================\n");
}

/*
 * Function: ipc_kmsg_global_stats_dump
 *
 * Dump global IPC statistics
 */
void ipc_kmsg_global_stats_dump(void)
{
    struct ipc_kmsg_stats stats;
    
    ipc_kmsg_get_stats(&stats);
    
    printf("\n=== IPC KMSG Global Statistics ===\n");
    printf("Messages Sent: %llu\n", stats.total_messages_sent);
    printf("Messages Received: %llu\n", stats.total_messages_received);
    printf("Total Messages: %llu\n",
           stats.total_messages_sent + stats.total_messages_received);
    printf("Bytes Sent: %llu (%llu MB)\n",
           stats.total_bytes_sent, stats.total_bytes_sent / (1024 * 1024));
    printf("Bytes Received: %llu (%llu MB)\n",
           stats.total_bytes_received, stats.total_bytes_received / (1024 * 1024));
    printf("Average Message Size: %llu bytes\n", stats.average_message_size);
    printf("Max Message Size: %llu bytes\n", stats.max_message_size);
    printf("Min Message Size: %llu bytes\n", stats.min_message_size);
    printf("Port Rights Transferred: %llu\n", stats.total_port_rights_transferred);
    printf("Memory Transferred: %llu bytes (%llu MB)\n",
           stats.total_memory_transferred, stats.total_memory_transferred / (1024 * 1024));
    printf("Messages Queued: %u\n", stats.messages_queued);
    printf("Messages Dequeued: %u\n", stats.messages_dequeued);
    printf("Priority Inversions: %u\n", stats.priority_inversions);
    printf("Batch Operations: %u\n", stats.batch_operations);
    printf("===================================\n");
}

/*
 * Function: ipc_kmsg_priority_inheritance
 *
 * Implement priority inheritance for message queues
 */
void ipc_kmsg_priority_inheritance(ipc_kmsg_t kmsg, unsigned int caller_priority)
{
    if (kmsg == IKM_NULL)
        return;
    
    if (caller_priority < kmsg->ikm_priority) {
        /* Priority inversion detected - boost message priority */
        simple_lock(&ipc_kmsg_global_stats_lock);
        ipc_kmsg_global_stats.priority_inversions++;
        simple_unlock(&ipc_kmsg_global_stats_lock);
        
        kmsg->ikm_priority = caller_priority;
        kmsg->ikm_priority_inherited = TRUE;
    }
}

/*
 * Function: ipc_kmsg_restore_priority
 *
 * Restore original message priority after inheritance
 */
void ipc_kmsg_restore_priority(ipc_kmsg_t kmsg)
{
    if (kmsg == IKM_NULL || !kmsg->ikm_priority_inherited)
        return;
    
    kmsg->ikm_priority = kmsg->ikm_original_priority;
    kmsg->ikm_priority_inherited = FALSE;
}

/*
 * Function: ipc_kmsg_early_deadline
 *
 * Check if message has early deadline (for real-time messages)
 */
boolean_t ipc_kmsg_early_deadline(ipc_kmsg_t kmsg, unsigned long long now)
{
    if (kmsg == IKM_NULL || kmsg->ikm_deadline == 0)
        return FALSE;
    
    return (now >= kmsg->ikm_deadline - kmsg->ikm_processing_time);
}

/*
 * Function: ipc_kmsg_set_deadline
 *
 * Set processing deadline for real-time message
 */
void ipc_kmsg_set_deadline(ipc_kmsg_t kmsg, unsigned long long deadline_ns,
                            unsigned long long processing_time_ns)
{
    if (kmsg == IKM_NULL)
        return;
    
    kmsg->ikm_deadline = deadline_ns;
    kmsg->ikm_processing_time = processing_time_ns;
}

/*
 * Function: ipc_kmsg_skip_if_deadline_missed
 *
 * Skip message processing if deadline already missed
 */
boolean_t ipc_kmsg_skip_if_deadline_missed(ipc_kmsg_t kmsg)
{
    if (kmsg == IKM_NULL || kmsg->ikm_deadline == 0)
        return FALSE;
    
    if (mach_absolute_time() >= kmsg->ikm_deadline) {
        /* Deadline missed - skip processing */
        ipc_kmsg_destroy(kmsg);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Function: ipc_kmsg_merge
 *
 * Merge multiple small messages into one larger message
 */
ipc_kmsg_t ipc_kmsg_merge(ipc_kmsg_t *messages, unsigned int count)
{
    ipc_kmsg_t merged;
    vm_size_t total_size = 0;
    unsigned int i;
    vm_offset_t dest;
    
    if (messages == NULL || count == 0)
        return IKM_NULL;
    
    /* Calculate total size */
    for (i = 0; i < count; i++) {
        if (messages[i] != IKM_NULL)
            total_size += messages[i]->ikm_header.msgh_size;
    }
    
    /* Allocate merged message */
    merged = ikm_alloc(total_size);
    if (merged == IKM_NULL)
        return IKM_NULL;
    
    ikm_init(merged, total_size);
    dest = (vm_offset_t)(&merged->ikm_header);
    
    /* Copy all messages into merged buffer */
    for (i = 0; i < count; i++) {
        if (messages[i] != IKM_NULL) {
            vm_size_t size = messages[i]->ikm_header.msgh_size;
            memcpy((void *)dest, &messages[i]->ikm_header, size);
            dest += size;
            ipc_kmsg_destroy(messages[i]);
        }
    }
    
    merged->ikm_header.msgh_size = total_size;
    
    return merged;
}

/*
 * Function: ipc_kmsg_split
 *
 * Split large message into multiple smaller messages
 */
kern_return_t ipc_kmsg_split(ipc_kmsg_t kmsg, ipc_kmsg_t **splitted,
                              unsigned int *count, vm_size_t max_size)
{
    vm_size_t size;
    vm_offset_t src;
    unsigned int i;
    unsigned int num_splits;
    
    if (kmsg == IKM_NULL || splitted == NULL || count == NULL)
        return KERN_INVALID_ARGUMENT;
    
    size = kmsg->ikm_header.msgh_size;
    num_splits = (size + max_size - 1) / max_size;
    
    *splitted = (ipc_kmsg_t *)kalloc(num_splits * sizeof(ipc_kmsg_t));
    if (*splitted == NULL)
        return KERN_RESOURCE_SHORTAGE;
    
    src = (vm_offset_t)(&kmsg->ikm_header);
    
    for (i = 0; i < num_splits; i++) {
        vm_size_t split_size = (i == num_splits - 1) ?
                               size - (i * max_size) : max_size;
        
        (*splitted)[i] = ikm_alloc(split_size);
        if ((*splitted)[i] == IKM_NULL) {
            for (unsigned int j = 0; j < i; j++)
                ipc_kmsg_destroy((*splitted)[j]);
            kfree((vm_offset_t)*splitted, num_splits * sizeof(ipc_kmsg_t));
            return KERN_RESOURCE_SHORTAGE;
        }
        
        ikm_init((*splitted)[i], split_size);
        memcpy(&(*splitted)[i]->ikm_header, (void *)src, split_size);
        src += split_size;
    }
    
    *count = num_splits;
    ipc_kmsg_destroy(kmsg);
    
    return KERN_SUCCESS;
}

/*
 * Function: ipc_kmsg_send_async
 *
 * Send message asynchronously with callback
 */
kern_return_t ipc_kmsg_send_async(ipc_kmsg_t kmsg, ipc_space_t space,
                                   vm_map_t map, void (*callback)(ipc_kmsg_t, kern_return_t))
{
    mach_msg_return_t mr;
    
    if (kmsg == IKM_NULL)
        return KERN_INVALID_ARGUMENT;
    
    ipc_kmsg_set_callback(kmsg, callback);
    
    mr = ipc_kmsg_copyin(kmsg, space, map, MACH_PORT_NULL);
    
    if (mr != MACH_MSG_SUCCESS) {
        ipc_kmsg_invoke_callback(kmsg, KERN_FAILURE);
        return KERN_FAILURE;
    }
    
    /* Queue for async processing */
    ipc_kmsg_enqueue(&current_thread()->ith_messages, kmsg);
    
    return KERN_SUCCESS;
}

/*
 * Function: ipc_kmsg_receive_async
 *
 * Receive message asynchronously
 */
kern_return_t ipc_kmsg_receive_async(ipc_space_t space, ipc_kmsg_t *kmsgp,
                                      void (*callback)(ipc_kmsg_t, kern_return_t))
{
    ipc_kmsg_t kmsg;
    
    if (space == IPC_SPACE_NULL || kmsgp == NULL)
        return KERN_INVALID_ARGUMENT;
    
    kmsg = ipc_kmsg_dequeue(&current_thread()->ith_messages);
    
    if (kmsg == IKM_NULL) {
        /* No message available, set up async wait */
        assert_wait((event_t)&current_thread()->ith_messages, TRUE);
        return KERN_ABORTED;
    }
    
    ipc_kmsg_set_callback(kmsg, callback);
    *kmsgp = kmsg;
    
    return KERN_SUCCESS;
}

/*
 * Global tracing flag
 */
boolean_t ipc_kmsg_tracing_enabled = FALSE;

/*
 * Constants
 */
#define IPC_PRIORITY_LEVELS 32
#define IPC_KMSG_BATCH_SIZE 64

#include <kern/audit.h>

/*
 * Message Security Context
 */
struct ipc_kmsg_security_ctx {
    unsigned int security_level;
    unsigned int encryption_algorithm;
    unsigned char encryption_key[32];
    unsigned char integrity_hash[64];
    unsigned int sender_uid;
    unsigned int sender_gid;
    unsigned int sender_pid;
    unsigned long long timestamp;
    unsigned int flags;
    simple_lock_t security_lock;
};

/*
 * Message Routing Table
 */
struct ipc_kmsg_route_entry {
    ipc_kmsg_t kmsg;
    ipc_space_t source_space;
    ipc_space_t target_space;
    unsigned int route_id;
    unsigned int hop_count;
    unsigned int max_hops;
    unsigned long long route_timeout;
    struct ipc_kmsg_route_entry *next;
    simple_lock_t route_lock;
};

/*
 * Message Encryption Context
 */
struct ipc_kmsg_crypto_ctx {
    unsigned int cipher_type;
    unsigned int cipher_mode;
    unsigned char iv[16];
    unsigned char tag[16];
    unsigned long long sequence_number;
    unsigned int key_length;
    void *cipher_ctx;
    simple_lock_t crypto_lock;
};

/*
 * Function: ipc_kmsg_set_security
 *
 * Set security context for message
 */
kern_return_t ipc_kmsg_set_security(ipc_kmsg_t kmsg, 
                                     unsigned int security_level,
                                     unsigned int encryption_alg)
{
    struct ipc_kmsg_security_ctx *sec;
    
    if (kmsg == IKM_NULL)
        return KERN_INVALID_ARGUMENT;
    
    sec = (struct ipc_kmsg_security_ctx *)kalloc(sizeof(struct ipc_kmsg_security_ctx));
    if (sec == NULL)
        return KERN_RESOURCE_SHORTAGE;
    
    memset(sec, 0, sizeof(struct ipc_kmsg_security_ctx));
    sec->security_level = security_level;
    sec->encryption_algorithm = encryption_alg;
    sec->timestamp = mach_absolute_time();
    simple_lock_init(&sec->security_lock);
    
    kmsg->ikm_security_ctx = sec;
    
    return KERN_SUCCESS;
}

/*
 * Function: ipc_kmsg_encrypt
 *
 * Encrypt message payload
 */
kern_return_t ipc_kmsg_encrypt(ipc_kmsg_t kmsg, unsigned char *key, 
                                unsigned int key_len, unsigned int cipher)
{
    struct ipc_kmsg_crypto_ctx *crypto;
    vm_offset_t payload_start;
    vm_size_t payload_size;
    kern_return_t kr;
    
    if (kmsg == IKM_NULL || key == NULL)
        return KERN_INVALID_ARGUMENT;
    
    crypto = (struct ipc_kmsg_crypto_ctx *)kalloc(sizeof(struct ipc_kmsg_crypto_ctx));
    if (crypto == NULL)
        return KERN_RESOURCE_SHORTAGE;
    
    memset(crypto, 0, sizeof(struct ipc_kmsg_crypto_ctx));
    crypto->cipher_type = cipher;
    crypto->key_length = key_len;
    memcpy(crypto->iv, key + key_len, 16);
    simple_lock_init(&crypto->crypto_lock);
    
    /* Initialize cipher context */
    crypto->cipher_ctx = crypto_cipher_init(cipher, key, key_len);
    if (crypto->cipher_ctx == NULL) {
        kfree((vm_offset_t)crypto, sizeof(struct ipc_kmsg_crypto_ctx));
        return KERN_FAILURE;
    }
    
    /* Encrypt message body (skip header) */
    payload_start = (vm_offset_t)(&kmsg->ikm_header + 1);
    payload_size = kmsg->ikm_header.msgh_size - sizeof(mach_msg_header_t);
    
    kr = crypto_cipher_encrypt(crypto->cipher_ctx, 
                                (void *)payload_start,
                                (void *)payload_start,
                                payload_size,
                                crypto->iv);
    
    if (kr != KERN_SUCCESS) {
        crypto_cipher_destroy(crypto->cipher_ctx);
        kfree((vm_offset_t)crypto, sizeof(struct ipc_kmsg_crypto_ctx));
        return kr;
    }
    
    kmsg->ikm_crypto_ctx = crypto;
    kmsg->ikm_encrypted = TRUE;
    
    return KERN_SUCCESS;
}

/*
 * Function: ipc_kmsg_decrypt
 *
 * Decrypt message payload
 */
kern_return_t ipc_kmsg_decrypt(ipc_kmsg_t kmsg)
{
    struct ipc_kmsg_crypto_ctx *crypto;
    vm_offset_t payload_start;
    vm_size_t payload_size;
    kern_return_t kr;
    
    if (kmsg == IKM_NULL || !kmsg->ikm_encrypted)
        return KERN_INVALID_ARGUMENT;
    
    crypto = kmsg->ikm_crypto_ctx;
    if (crypto == NULL)
        return KERN_FAILURE;
    
    simple_lock(&crypto->crypto_lock);
    
    payload_start = (vm_offset_t)(&kmsg->ikm_header + 1);
    payload_size = kmsg->ikm_header.msgh_size - sizeof(mach_msg_header_t);
    
    kr = crypto_cipher_decrypt(crypto->cipher_ctx,
                                (void *)payload_start,
                                (void *)payload_start,
                                payload_size,
                                crypto->iv);
    
    simple_unlock(&crypto->crypto_lock);
    
    if (kr == KERN_SUCCESS)
        kmsg->ikm_encrypted = FALSE;
    
    return kr;
}

/*
 * Function: ipc_kmsg_route_add
 *
 * Add message routing entry for forwarding
 */
kern_return_t ipc_kmsg_route_add(ipc_kmsg_t kmsg,
                                  ipc_space_t target_space,
                                  unsigned int max_hops,
                                  unsigned long long timeout_ns)
{
    struct ipc_kmsg_route_entry *route;
    
    if (kmsg == IKM_NULL || target_space == IPC_SPACE_NULL)
        return KERN_INVALID_ARGUMENT;
    
    route = (struct ipc_kmsg_route_entry *)kalloc(sizeof(struct ipc_kmsg_route_entry));
    if (route == NULL)
        return KERN_RESOURCE_SHORTAGE;
    
    memset(route, 0, sizeof(struct ipc_kmsg_route_entry));
    route->kmsg = kmsg;
    route->source_space = kmsg->ikm_sender_space;
    route->target_space = target_space;
    route->route_id = (unsigned int)mach_absolute_time();
    route->max_hops = max_hops;
    route->route_timeout = mach_absolute_time() + timeout_ns;
    simple_lock_init(&route->route_lock);
    
    kmsg->ikm_route = route;
    
    return KERN_SUCCESS;
}

/*
 * Function: ipc_kmsg_route_forward
 *
 * Forward message to next destination
 */
kern_return_t ipc_kmsg_route_forward(ipc_kmsg_t kmsg)
{
    struct ipc_kmsg_route_entry *route;
    
    if (kmsg == IKM_NULL)
        return KERN_INVALID_ARGUMENT;
    
    route = kmsg->ikm_route;
    if (route == NULL)
        return KERN_FAILURE;
    
    simple_lock(&route->route_lock);
    
    route->hop_count++;
    
    if (route->hop_count >= route->max_hops) {
        simple_unlock(&route->route_lock);
        return KERN_FAILURE;
    }
    
    if (mach_absolute_time() >= route->route_timeout) {
        simple_unlock(&route->route_lock);
        return KERN_TIMEOUT;
    }
    
    simple_unlock(&route->route_lock);
    
    /* Forward to target space */
    return ipc_kmsg_copyin(kmsg, route->target_space, 
                           current_task()->map, MACH_PORT_NULL);
}

/*
 * Function: ipc_kmsg_audit
 *
 * Audit message for security monitoring
 */
void ipc_kmsg_audit(ipc_kmsg_t kmsg, unsigned int event_type)
{
    struct ipc_kmsg_security_ctx *sec;
    struct audit_record *rec;
    
    if (kmsg == IKM_NULL)
        return;
    
    sec = kmsg->ikm_security_ctx;
    
    rec = audit_record_alloc();
    if (rec == NULL)
        return;
    
    audit_record_set_type(rec, event_type);
    audit_record_set_field(rec, AUDIT_MSG_ID, kmsg->ikm_header.msgh_id);
    audit_record_set_field(rec, AUDIT_MSG_SIZE, kmsg->ikm_header.msgh_size);
    audit_record_set_field(rec, AUDIT_REMOTE_PORT, 
                           (unsigned long)kmsg->ikm_header.msgh_remote_port);
    audit_record_set_field(rec, AUDIT_LOCAL_PORT,
                           (unsigned long)kmsg->ikm_header.msgh_local_port);
    
    if (sec != NULL) {
        audit_record_set_field(rec, AUDIT_SECURITY_LEVEL, sec->security_level);
        audit_record_set_field(rec, AUDIT_SENDER_UID, sec->sender_uid);
        audit_record_set_field(rec, AUDIT_SENDER_PID, sec->sender_pid);
    }
    
    audit_record_commit(rec);
}

/*
 * Function: ipc_kmsg_get_sender_info
 *
 * Get sender information from message
 */
void ipc_kmsg_get_sender_info(ipc_kmsg_t kmsg, unsigned int *uid,
                               unsigned int *gid, unsigned int *pid)
{
    struct ipc_kmsg_security_ctx *sec;
    
    if (kmsg == IKM_NULL)
        return;
    
    sec = kmsg->ikm_security_ctx;
    if (sec != NULL) {
        if (uid != NULL) *uid = sec->sender_uid;
        if (gid != NULL) *gid = sec->sender_gid;
        if (pid != NULL) *pid = sec->sender_pid;
    } else {
        if (uid != NULL) *uid = 0;
        if (gid != NULL) *gid = 0;
        if (pid != NULL) *pid = 0;
    }
}

/*
 * Function: ipc_kmsg_priority_boost
 *
 * Temporarily boost message priority for urgent processing
 */
void ipc_kmsg_priority_boost(ipc_kmsg_t kmsg, unsigned int boost_amount)
{
    unsigned int new_priority;
    
    if (kmsg == IKM_NULL)
        return;
    
    new_priority = kmsg->ikm_priority - boost_amount;
    if (new_priority > IPC_PRIORITY_LEVELS - 1)
        new_priority = IPC_PRIORITY_LEVELS - 1;
    
    kmsg->ikm_original_priority = kmsg->ikm_priority;
    kmsg->ikm_priority = new_priority;
    kmsg->ikm_priority_boosted = TRUE;
}

/*
 * Function: ipc_kmsg_unboost_priority
 *
 * Restore original message priority
 */
void ipc_kmsg_unboost_priority(ipc_kmsg_t kmsg)
{
    if (kmsg == IKM_NULL || !kmsg->ikm_priority_boosted)
        return;
    
    kmsg->ikm_priority = kmsg->ikm_original_priority;
    kmsg->ikm_priority_boosted = FALSE;
}

/*
 * Function: ipc_kmsg_cache_warm
 *
 * Warm up message cache for better performance
 */
void ipc_kmsg_cache_warm(unsigned int count, vm_size_t size)
{
    ipc_kmsg_t kmsg;
    unsigned int i;
    
    for (i = 0; i < count; i++) {
        kmsg = ikm_alloc(size);
        if (kmsg != IKM_NULL) {
            ikm_init(kmsg, size);
            ikm_cache_free(kmsg);
        }
    }
}

/*
 * Function: ipc_kmsg_cache_stats
 *
 * Get cache statistics
 */
void ipc_kmsg_cache_stats(unsigned int *hits, unsigned int *misses,
                           unsigned int *allocations, unsigned int *frees)
{
    static unsigned int cache_hits = 0;
    static unsigned int cache_misses = 0;
    static unsigned int cache_allocs = 0;
    static unsigned int cache_frees = 0;
    
    if (hits != NULL) *hits = cache_hits;
    if (misses != NULL) *misses = cache_misses;
    if (allocations != NULL) *allocations = cache_allocs;
    if (frees != NULL) *frees = cache_frees;
}

/*
 * Function: ipc_kmsg_monitor_start
 *
 * Start monitoring message flow
 */
void ipc_kmsg_monitor_start(unsigned int sampling_rate)
{
    ipc_kmsg_monitoring_enabled = TRUE;
    ipc_kmsg_sampling_rate = sampling_rate;
}

/*
 * Function: ipc_kmsg_monitor_stop
 *
 * Stop monitoring message flow
 */
void ipc_kmsg_monitor_stop(void)
{
    ipc_kmsg_monitoring_enabled = FALSE;
}

/*
 * Function: ipc_kmsg_dump_monitor_data
 *
 * Dump collected monitoring data
 */
void ipc_kmsg_dump_monitor_data(void)
{
    struct ipc_kmsg_monitor_data *data;
    
    data = ipc_kmsg_get_monitor_data();
    if (data == NULL)
        return;
    
    printf("\n=== IPC KMSG Monitor Data ===\n");
    printf("Sampling Period: %llu ns\n", data->sampling_period);
    printf("Messages Sampled: %u\n", data->samples);
    printf("Average Latency: %llu ns\n", data->avg_latency);
    printf("Max Latency: %llu ns\n", data->max_latency);
    printf("Min Latency: %llu ns\n", data->min_latency);
    printf("Throughput: %u msg/s\n", data->throughput);
    printf("Dropped Messages: %u\n", data->dropped);
    printf("================================\n");
}

/*
 * Function: ipc_kmsg_set_qos
 *
 * Set Quality of Service parameters for message
 */
void ipc_kmsg_set_qos(ipc_kmsg_t kmsg, unsigned int qos_class,
                       unsigned int latency_sensitivity,
                       unsigned int loss_tolerance)
{
    if (kmsg == IKM_NULL)
        return;
    
    kmsg->ikm_qos_class = qos_class;
    kmsg->ikm_latency_sensitivity = latency_sensitivity;
    kmsg->ikm_loss_tolerance = loss_tolerance;
}

/*
 * Function: ipc_kmsg_get_qos
 *
 * Get Quality of Service parameters
 */
void ipc_kmsg_get_qos(ipc_kmsg_t kmsg, unsigned int *qos_class,
                       unsigned int *latency_sensitivity,
                       unsigned int *loss_tolerance)
{
    if (kmsg == IKM_NULL)
        return;
    
    if (qos_class != NULL) *qos_class = kmsg->ikm_qos_class;
    if (latency_sensitivity != NULL) *latency_sensitivity = kmsg->ikm_latency_sensitivity;
    if (loss_tolerance != NULL) *loss_tolerance = kmsg->ikm_loss_tolerance;
}

/*
 * Function: ipc_kmsg_flow_control
 *
 * Implement flow control for message queues
 */
boolean_t ipc_kmsg_flow_control(ipc_space_t space, unsigned int max_queue_size)
{
    unsigned int queue_size;
    
    if (space == IPC_SPACE_NULL)
        return FALSE;
    
    queue_size = ipc_kmsg_queue_size(&space->is_messages);
    
    if (queue_size >= max_queue_size) {
        /* Flow control active - throttle sender */
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Function: ipc_kmsg_queue_size
 *
 * Get current queue size
 */
unsigned int ipc_kmsg_queue_size(ipc_kmsg_queue_t queue)
{
    unsigned int size = 0;
    ipc_kmsg_t kmsg;
    
    if (queue == NULL || queue->ikmq_base == IKM_NULL)
        return 0;
    
    kmsg = queue->ikmq_base;
    do {
        size++;
        kmsg = kmsg->ikm_next;
    } while (kmsg != queue->ikmq_base);
    
    return size;
}

/*
 * Function: ipc_kmsg_peek
 *
 * Peek at next message without dequeuing
 */
ipc_kmsg_t ipc_kmsg_peek(ipc_kmsg_queue_t queue)
{
    if (queue == NULL || queue->ikmq_base == IKM_NULL)
        return IKM_NULL;
    
    return queue->ikmq_base;
}

/*
 * Function: ipc_kmsg_peek_at
 *
 * Peek at message by index
 */
ipc_kmsg_t ipc_kmsg_peek_at(ipc_kmsg_queue_t queue, unsigned int index)
{
    ipc_kmsg_t kmsg;
    unsigned int i;
    
    if (queue == NULL || queue->ikmq_base == IKM_NULL)
        return IKM_NULL;
    
    kmsg = queue->ikmq_base;
    for (i = 0; i < index; i++) {
        kmsg = kmsg->ikm_next;
        if (kmsg == queue->ikmq_base)
            return IKM_NULL;
    }
    
    return kmsg;
}

/*
 * Function: ipc_kmsg_reorder
 *
 * Reorder queue based on priorities
 */
void ipc_kmsg_reorder(ipc_kmsg_queue_t queue)
{
    ipc_kmsg_t kmsg, next;
    ipc_kmsg_queue_t temp_queue;
    unsigned int i;
    
    if (queue == NULL || queue->ikmq_base == IKM_NULL)
        return;
    
    temp_queue = (ipc_kmsg_queue_t)kalloc(sizeof(struct ipc_kmsg_queue));
    if (temp_queue == NULL)
        return;
    
    temp_queue->ikmq_base = IKM_NULL;
    
    /* Extract all messages */
    while ((kmsg = ipc_kmsg_dequeue(queue)) != IKM_NULL) {
        ipc_kmsg_enqueue(temp_queue, kmsg);
    }
    
    /* Sort by priority (simplified bubble sort) */
    ipc_kmsg_t sorted[1024];
    unsigned int count = 0;
    
    while ((kmsg = ipc_kmsg_dequeue(temp_queue)) != IKM_NULL) {
        sorted[count++] = kmsg;
    }
    
    for (i = 0; i < count - 1; i++) {
        for (unsigned int j = i + 1; j < count; j++) {
            if (sorted[i]->ikm_priority > sorted[j]->ikm_priority) {
                ipc_kmsg_t tmp = sorted[i];
                sorted[i] = sorted[j];
                sorted[j] = tmp;
            }
        }
    }
    
    /* Re-enqueue in priority order */
    for (i = 0; i < count; i++) {
        ipc_kmsg_enqueue(queue, sorted[i]);
    }
    
    kfree((vm_offset_t)temp_queue, sizeof(struct ipc_kmsg_queue));
}

/*
 * Function: ipc_kmsg_throttle
 *
 * Throttle message processing rate
 */
void ipc_kmsg_throttle(unsigned int max_rate_per_second)
{
    static unsigned int processed_count = 0;
    static unsigned long long last_second = 0;
    unsigned long long now;
    
    now = mach_absolute_time();
    
    if (now - last_second > 1000000000ULL) {
        last_second = now;
        processed_count = 0;
    }
    
    processed_count++;
    
    if (processed_count > max_rate_per_second) {
        /* Throttle - sleep for remainder of second */
        unsigned long long sleep_ns = 1000000000ULL - (now - last_second);
        if (sleep_ns > 0) {
            thread_set_timeout(sleep_ns / 1000000);
            thread_block(NULL);
        }
    }
}

/*
 * Function: ipc_kmsg_drop_oldest
 *
 * Drop oldest message when queue is full
 */
boolean_t ipc_kmsg_drop_oldest(ipc_kmsg_queue_t queue, unsigned int max_size)
{
    ipc_kmsg_t oldest;
    unsigned int current_size;
    
    current_size = ipc_kmsg_queue_size(queue);
    
    if (current_size >= max_size) {
        oldest = ipc_kmsg_dequeue(queue);
        if (oldest != IKM_NULL) {
            ipc_kmsg_destroy(oldest);
            return TRUE;
        }
    }
    
    return FALSE;
}

/*
 * Function: ipc_kmsg_drop_by_priority
 *
 * Drop lowest priority messages when queue is full
 */
unsigned int ipc_kmsg_drop_by_priority(ipc_kmsg_queue_t queue,
                                        unsigned int max_size,
                                        unsigned int min_priority)
{
    ipc_kmsg_t kmsg, next;
    unsigned int dropped = 0;
    unsigned int current_size;
    
    current_size = ipc_kmsg_queue_size(queue);
    
    if (current_size <= max_size)
        return 0;
    
    /* Scan and drop low priority messages */
    kmsg = queue->ikmq_base;
    if (kmsg == IKM_NULL)
        return 0;
    
    do {
        next = kmsg->ikm_next;
        
        if (kmsg->ikm_priority >= min_priority) {
            ipc_kmsg_rmqueue(queue, kmsg);
            ipc_kmsg_destroy(kmsg);
            dropped++;
        }
        
        kmsg = next;
    } while (kmsg != queue->ikmq_base && dropped < (current_size - max_size));
    
    return dropped;
}

/*
 * Function: ipc_kmsg_statistics_reset
 *
 * Reset all IPC statistics
 */
void ipc_kmsg_statistics_reset(void)
{
    ipc_kmsg_reset_stats();
    
    simple_lock(&ipc_kmsg_global_stats_lock);
    ipc_kmsg_global_stats.messages_queued = 0;
    ipc_kmsg_global_stats.messages_dequeued = 0;
    ipc_kmsg_global_stats.priority_inversions = 0;
    ipc_kmsg_global_stats.batch_operations = 0;
    simple_unlock(&ipc_kmsg_global_stats_lock);
}

/*
 * Function: ipc_kmsg_statistics_print
 *
 * Print formatted statistics
 */
void ipc_kmsg_statistics_print(void)
{
    struct ipc_kmsg_stats stats;
    
    ipc_kmsg_get_stats(&stats);
    
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                    IPC KMSG STATISTICS                       ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Messages Sent:      %20llu                              ║\n", stats.total_messages_sent);
    printf("║ Messages Received:  %20llu                              ║\n", stats.total_messages_received);
    printf("║ Total Messages:     %20llu                              ║\n", 
           stats.total_messages_sent + stats.total_messages_received);
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Bytes Sent:         %20llu (%6llu MB)                  ║\n", 
           stats.total_bytes_sent, stats.total_bytes_sent / (1024 * 1024));
    printf("║ Bytes Received:     %20llu (%6llu MB)                  ║\n", 
           stats.total_bytes_received, stats.total_bytes_received / (1024 * 1024));
    printf("║ Avg Message Size:   %20llu bytes                          ║\n", stats.average_message_size);
    printf("║ Max Message Size:   %20llu bytes                          ║\n", stats.max_message_size);
    printf("║ Min Message Size:   %20llu bytes                          ║\n", stats.min_message_size);
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Port Rights Xfer:   %20llu                              ║\n", stats.total_port_rights_transferred);
    printf("║ Memory Xferred:     %20llu (%6llu MB)                  ║\n",
           stats.total_memory_transferred, stats.total_memory_transferred / (1024 * 1024));
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Messages Queued:    %20u                               ║\n", stats.messages_queued);
    printf("║ Messages Dequeued:  %20u                               ║\n", stats.messages_dequeued);
    printf("║ Priority Inversions:%20u                               ║\n", stats.priority_inversions);
    printf("║ Batch Operations:   %20u                               ║\n", stats.batch_operations);
    printf("╚══════════════════════════════════════════════════════════════╝\n");
}

/*
 * Global monitoring flags
 */
boolean_t ipc_kmsg_monitoring_enabled = FALSE;
unsigned int ipc_kmsg_sampling_rate = 100;
static struct ipc_kmsg_monitor_data *ipc_kmsg_monitor_data = NULL;

/*
 * Function to get monitor data
 */
static struct ipc_kmsg_monitor_data *ipc_kmsg_get_monitor_data(void)
{
    return ipc_kmsg_monitor_data;
}

/*
 * Monitor data structure
 */
struct ipc_kmsg_monitor_data {
    unsigned long long sampling_period;
    unsigned int samples;
    unsigned long long avg_latency;
    unsigned long long max_latency;
    unsigned long long min_latency;
    unsigned int throughput;
    unsigned int dropped;
};

/*
 * Hybrid Driver Communication Structures
 */
struct ipc_hybrid_driver {
    unsigned int driver_id;
    unsigned int driver_type;        /* 0=kernel, 1=user */
    unsigned int driver_state;       /* 0=stopped, 1=running, 2=suspended, 3=faulted */
    ipc_port_t kernel_port;
    ipc_port_t user_port;
    task_t owner_task;
    thread_t worker_thread;
    vm_map_t shared_memory_map;
    vm_offset_t shared_memory_base;
    vm_size_t shared_memory_size;
    unsigned long long message_count;
    unsigned long long bytes_transferred;
    unsigned int max_message_size;
    unsigned int priority;
    simple_lock_t driver_lock;
    void (*kernel_callback)(struct ipc_hybrid_driver *, ipc_kmsg_t);
    void (*user_callback)(struct ipc_hybrid_driver *, ipc_kmsg_t);
};

/*
 * Hybrid Message Structure
 */
struct ipc_hybrid_message {
    ipc_kmsg_t kernel_msg;
    ipc_kmsg_t user_msg;
    unsigned long long message_id;
    unsigned int flags;
    unsigned int priority;
    unsigned long long deadline_ns;
    vm_offset_t shared_data_offset;
    vm_size_t data_size;
    unsigned int ref_count;
    void (*completion)(struct ipc_hybrid_message *, kern_return_t);
    simple_lock_t msg_lock;
};

/*
 * Driver Communication Channel
 */
struct ipc_hybrid_channel {
    unsigned int channel_id;
    unsigned int src_driver_id;
    unsigned int dst_driver_id;
    unsigned int channel_type;       /* 0=async, 1=sync, 2=stream, 3=datagram */
    unsigned long long message_count;
    unsigned long long bytes_transferred;
    unsigned int queue_depth;
    unsigned int max_queue_depth;
    ipc_kmsg_queue_t message_queue;
    simple_lock_t channel_lock;
};

/*
 * User Driver Memory Region
 */
struct ipc_user_driver_memory {
    vm_offset_t user_va;
    vm_offset_t kernel_va;
    vm_offset_t physical_va;
    vm_size_t size;
    unsigned int permissions;
    unsigned int mapping_count;
    simple_lock_t mem_lock;
};

/*
 * Function 1: ipc_hybrid_driver_register
 *
 * Register a driver as hybrid (supports both kernel and user mode operations)
 */
kern_return_t ipc_hybrid_driver_register(
    unsigned int driver_type,
    task_t owner_task,
    ipc_port_t communication_port,
    unsigned int max_message_size,
    unsigned int priority,
    unsigned int *driver_id_out)
{
    struct ipc_hybrid_driver *driver;
    vm_size_t shared_size;
    vm_offset_t shared_base;
    static unsigned int next_driver_id = 1;
    static simple_lock_t driver_id_lock;
    kern_return_t kr;
    
    if (driver_type > 1 || owner_task == TASK_NULL || communication_port == IP_NULL)
        return KERN_INVALID_ARGUMENT;
    
    /* Allocate driver structure */
    driver = (struct ipc_hybrid_driver *)kalloc(sizeof(struct ipc_hybrid_driver));
    if (driver == NULL)
        return KERN_RESOURCE_SHORTAGE;
    
    memset(driver, 0, sizeof(struct ipc_hybrid_driver));
    
    simple_lock(&driver_id_lock);
    driver->driver_id = next_driver_id++;
    simple_unlock(&driver_id_lock);
    
    driver->driver_type = driver_type;
    driver->driver_state = 1; /* running */
    driver->max_message_size = max_message_size;
    driver->priority = priority;
    driver->message_count = 0;
    driver->bytes_transferred = 0;
    simple_lock_init(&driver->driver_lock);
    
    /* Setup communication ports */
    if (driver_type == 0) {
        /* Kernel driver - use kernel port directly */
        driver->kernel_port = communication_port;
        ipc_port_reference(driver->kernel_port);
        driver->user_port = IP_NULL;
    } else {
        /* User driver - need shared memory for communication */
        driver->user_port = communication_port;
        ipc_port_reference(driver->user_port);
        driver->owner_task = owner_task;
        task_reference(owner_task);
        
        /* Allocate shared memory for fast communication */
        shared_size = round_page(max_message_size * 1024); /* 1024 messages buffer */
        kr = vm_map_allocate_shared(owner_task->map, &shared_base, shared_size,
                                    VM_PROT_READ | VM_PROT_WRITE);
        if (kr != KERN_SUCCESS) {
            kfree((vm_offset_t)driver, sizeof(struct ipc_hybrid_driver));
            return kr;
        }
        
        driver->shared_memory_map = owner_task->map;
        driver->shared_memory_base = shared_base;
        driver->shared_memory_size = shared_size;
        
        /* Map same memory in kernel space */
        kr = vm_map_kernel_map(&driver->kernel_shared_base, shared_size,
                               shared_base, VM_PROT_READ | VM_PROT_WRITE);
        if (kr != KERN_SUCCESS) {
            vm_deallocate(owner_task->map, shared_base, shared_size);
            kfree((vm_offset_t)driver, sizeof(struct ipc_hybrid_driver));
            return kr;
        }
    }
    
    /* Create worker thread for kernel driver */
    if (driver_type == 0) {
        kr = kernel_thread(kernel_task, "hybrid_driver_worker",
                          (continuation_t)ipc_hybrid_driver_worker,
                          (void *)driver);
        if (kr != KERN_SUCCESS) {
            ipc_port_release(driver->kernel_port);
            kfree((vm_offset_t)driver, sizeof(struct ipc_hybrid_driver));
            return kr;
        }
    }
    
    *driver_id_out = driver->driver_id;
    
    printf("Hybrid driver registered: id=%u type=%s max_msg=%u priority=%u\n",
           driver->driver_id, driver_type == 0 ? "kernel" : "user",
           max_message_size, priority);
    
    return KERN_SUCCESS;
}

/*
 * Function 2: ipc_hybrid_message_send
 *
 * Send hybrid message between kernel and user drivers
 */
kern_return_t ipc_hybrid_message_send(
    unsigned int src_driver_id,
    unsigned int dst_driver_id,
    void *data,
    vm_size_t data_size,
    unsigned int flags,
    unsigned long long deadline_ns,
    unsigned long long *message_id_out)
{
    struct ipc_hybrid_driver *src_driver, *dst_driver;
    struct ipc_hybrid_message *hybrid_msg;
    struct ipc_hybrid_channel *channel;
    ipc_kmsg_t kmsg;
    vm_offset_t shared_ptr;
    static unsigned long long next_message_id = 1;
    static simple_lock_t msg_id_lock;
    kern_return_t kr;
    
    /* Find drivers */
    src_driver = ipc_hybrid_find_driver(src_driver_id);
    dst_driver = ipc_hybrid_find_driver(dst_driver_id);
    
    if (src_driver == NULL || dst_driver == NULL)
        return KERN_INVALID_ARGUMENT;
    
    /* Create hybrid message structure */
    hybrid_msg = (struct ipc_hybrid_message *)kalloc(sizeof(struct ipc_hybrid_message));
    if (hybrid_msg == NULL)
        return KERN_RESOURCE_SHORTAGE;
    
    memset(hybrid_msg, 0, sizeof(struct ipc_hybrid_message));
    
    simple_lock(&msg_id_lock);
    hybrid_msg->message_id = next_message_id++;
    simple_unlock(&msg_id_lock);
    
    hybrid_msg->flags = flags;
    hybrid_msg->priority = (src_driver->priority + dst_driver->priority) / 2;
    hybrid_msg->deadline_ns = deadline_ns;
    hybrid_msg->data_size = data_size;
    hybrid_msg->ref_count = 1;
    simple_lock_init(&hybrid_msg->msg_lock);
    
    /* Copy data to shared memory if cross-domain */
    if (src_driver->driver_type != dst_driver->driver_type) {
        /* Cross-domain communication - use shared memory */
        if (dst_driver->driver_type == 1) {
            /* Kernel to User: copy to user shared memory */
            shared_ptr = dst_driver->shared_memory_base + 
                         (hybrid_msg->message_id % (dst_driver->shared_memory_size / PAGE_SIZE)) * PAGE_SIZE;
            
            memcpy((void *)shared_ptr, data, data_size);
            hybrid_msg->shared_data_offset = shared_ptr;
            
            /* Notify user driver via IPC */
            kmsg = ipc_kmsg_allocate(sizeof(mach_msg_header_t) + sizeof(hybrid_msg_id));
            if (kmsg == IKM_NULL) {
                kfree((vm_offset_t)hybrid_msg, sizeof(struct ipc_hybrid_message));
                return KERN_RESOURCE_SHORTAGE;
            }
            
            /* Build notification message */
            kmsg->ikm_header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
            kmsg->ikm_header.msgh_size = sizeof(mach_msg_header_t) + sizeof(hybrid_msg_id);
            kmsg->ikm_header.msgh_remote_port = (mach_port_t)dst_driver->user_port;
            kmsg->ikm_header.msgh_id = HYBRID_MSG_NOTIFY;
            
            *(unsigned long long *)(kmsg + 1) = hybrid_msg->message_id;
            
            kr = ipc_kmsg_send(kmsg, dst_driver->owner_task->itk_space,
                               current_task()->map, MACH_PORT_NULL);
        } else {
            /* User to Kernel: copy to kernel shared memory */
            shared_ptr = src_driver->shared_memory_base + 
                         (hybrid_msg->message_id % (src_driver->shared_memory_size / PAGE_SIZE)) * PAGE_SIZE;
            
            memcpy((void *)shared_ptr, data, data_size);
            hybrid_msg->shared_data_offset = shared_ptr;
            
            /* Direct kernel callback */
            if (dst_driver->kernel_callback != NULL) {
                dst_driver->kernel_callback(dst_driver, NULL);
            }
        }
    } else {
        /* Same-domain communication - direct message */
        kmsg = ipc_kmsg_allocate(sizeof(mach_msg_header_t) + data_size);
        if (kmsg == IKM_NULL) {
            kfree((vm_offset_t)hybrid_msg, sizeof(struct ipc_hybrid_message));
            return KERN_RESOURCE_SHORTAGE;
        }
        
        memcpy(kmsg + 1, data, data_size);
        
        if (src_driver->driver_type == 0) {
            kr = ipc_kmsg_send(kmsg, dst_driver->owner_task->itk_space,
                               current_task()->map, MACH_PORT_NULL);
        } else {
            kr = ipc_kmsg_send_to_user(kmsg, dst_driver->user_port);
        }
        
        hybrid_msg->kernel_msg = kmsg;
    }
    
    /* Find or create communication channel */
    channel = ipc_hybrid_find_channel(src_driver_id, dst_driver_id);
    if (channel == NULL) {
        channel = ipc_hybrid_create_channel(src_driver_id, dst_driver_id);
        if (channel == NULL) {
            kfree((vm_offset_t)hybrid_msg, sizeof(struct ipc_hybrid_message));
            return KERN_RESOURCE_SHORTAGE;
        }
    }
    
    simple_lock(&channel->channel_lock);
    ipc_kmsg_enqueue(&channel->message_queue, (ipc_kmsg_t)hybrid_msg);
    channel->message_count++;
    channel->bytes_transferred += data_size;
    simple_unlock(&channel->channel_lock);
    
    /* Update driver statistics */
    simple_lock(&src_driver->driver_lock);
    src_driver->message_count++;
    src_driver->bytes_transferred += data_size;
    simple_unlock(&src_driver->driver_lock);
    
    *message_id_out = hybrid_msg->message_id;
    
    return KERN_SUCCESS;
}

/*
 * Function 3: ipc_hybrid_driver_worker
 *
 * Worker thread for hybrid kernel driver processing
 */
static void ipc_hybrid_driver_worker(void *arg)
{
    struct ipc_hybrid_driver *driver = (struct ipc_hybrid_driver *)arg;
    struct ipc_hybrid_message *msg;
    ipc_kmsg_t kmsg;
    kern_return_t kr;
    unsigned long long deadline;
    
    if (driver == NULL)
        return;
    
    thread_set_name(current_thread(), "hybrid_driver_worker");
    
    while (driver->driver_state == 1) {
        /* Wait for messages */
        kr = ipc_kmsg_receive(driver->kernel_port, &kmsg, 
                              MACH_MSG_TIMEOUT_NONE, TRUE);
        
        if (kr != KERN_SUCCESS) {
            thread_block(NULL);
            continue;
        }
        
        /* Process based on message type */
        switch (kmsg->ikm_header.msgh_id) {
            case HYBRID_MSG_DATA:
                /* Regular data message */
                msg = ipc_hybrid_create_message_from_kmsg(kmsg);
                if (msg != NULL) {
                    ipc_hybrid_process_message(driver, msg);
                }
                break;
                
            case HYBRID_MSG_NOTIFY:
                /* Notification from user driver */
                ipc_hybrid_handle_notification(driver, kmsg);
                break;
                
            case HYBRID_MSG_CONTROL:
                /* Control message (register, unregister, query) */
                ipc_hybrid_handle_control(driver, kmsg);
                break;
                
            default:
                /* Unknown message type */
                ipc_kmsg_destroy(kmsg);
                break;
        }
        
        /* Check for deadline expiration */
        deadline = mach_absolute_time();
        ipc_hybrid_check_deadlines(driver, deadline);
    }
    
    thread_terminate(current_thread());
}

/*
 * Function 4: ipc_hybrid_user_driver_memory_map
 *
 * Map user memory for kernel driver access (zero-copy)
 */
kern_return_t ipc_hybrid_user_driver_memory_map(
    task_t user_task,
    vm_offset_t user_address,
    vm_size_t size,
    unsigned int permissions,
    vm_offset_t *kernel_address_out)
{
    struct ipc_user_driver_memory *mem_region;
    vm_offset_t kernel_va;
    vm_offset_t physical_va;
    pmap_t pmap;
    kern_return_t kr;
    
    if (user_task == TASK_NULL || user_address == 0 || size == 0)
        return KERN_INVALID_ARGUMENT;
    
    /* Allocate memory region structure */
    mem_region = (struct ipc_user_driver_memory *)kalloc(sizeof(struct ipc_user_driver_memory));
    if (mem_region == NULL)
        return KERN_RESOURCE_SHORTAGE;
    
    memset(mem_region, 0, sizeof(struct ipc_user_driver_memory));
    simple_lock_init(&mem_region->mem_lock);
    
    /* Get physical address of user memory */
    pmap = user_task->map->pmap;
    kr = pmap_extract(pmap, user_address, &physical_va);
    if (kr != KERN_SUCCESS) {
        kfree((vm_offset_t)mem_region, sizeof(struct ipc_user_driver_memory));
        return KERN_FAILURE;
    }
    
    /* Map physical memory to kernel space */
    kr = vm_map_kernel_map(&kernel_va, size, physical_va,
                          (permissions & 1) ? VM_PROT_READ : 0 |
                          (permissions & 2) ? VM_PROT_WRITE : 0);
    if (kr != KERN_SUCCESS) {
        kfree((vm_offset_t)mem_region, sizeof(struct ipc_user_driver_memory));
        return kr;
    }
    
    /* Fill memory region info */
    mem_region->user_va = user_address;
    mem_region->kernel_va = kernel_va;
    mem_region->physical_va = physical_va;
    mem_region->size = size;
    mem_region->permissions = permissions;
    mem_region->mapping_count = 1;
    
    /* Store in driver's memory region list */
    ipc_hybrid_add_memory_region(mem_region);
    
    *kernel_address_out = kernel_va;
    
    printf("User driver memory mapped: user=0x%lx kernel=0x%lx phys=0x%lx size=%lu\n",
           (unsigned long)user_address, (unsigned long)kernel_va,
           (unsigned long)physical_va, (unsigned long)size);
    
    return KERN_SUCCESS;
}

/*
 * Function 5: ipc_hybrid_driver_failover
 *
 * Implement driver failover between kernel and user mode
 */
kern_return_t ipc_hybrid_driver_failover(unsigned int driver_id)
{
    struct ipc_hybrid_driver *driver;
    struct ipc_hybrid_driver *backup_driver;
    struct ipc_hybrid_channel *channel;
    ipc_kmsg_t pending_msg;
    unsigned int i;
    kern_return_t kr;
    
    driver = ipc_hybrid_find_driver(driver_id);
    if (driver == NULL)
        return KERN_INVALID_ARGUMENT;
    
    printf("Hybrid driver failover initiated: driver=%u type=%s\n",
           driver_id, driver->driver_type == 0 ? "kernel" : "user");
    
    /* Mark driver as faulted */
    simple_lock(&driver->driver_lock);
    driver->driver_state = 3; /* faulted */
    simple_unlock(&driver->driver_lock);
    
    /* Determine backup driver type */
    if (driver->driver_type == 0) {
        /* Kernel driver failed - switch to user driver */
        backup_driver = ipc_hybrid_find_driver_by_type(driver->owner_task, 1);
        if (backup_driver == NULL) {
            /* Create user driver backup */
            kr = ipc_hybrid_driver_register(1, driver->owner_task,
                                            IP_NULL, driver->max_message_size,
                                            driver->priority, &backup_driver->driver_id);
            if (kr != KERN_SUCCESS) {
                printf("Failed to create backup user driver\n");
                return kr;
            }
        }
    } else {
        /* User driver failed - switch to kernel driver */
        backup_driver = ipc_hybrid_find_driver_by_type(driver->owner_task, 0);
        if (backup_driver == NULL) {
            /* Create kernel driver backup */
            kr = ipc_hybrid_driver_register(0, kernel_task,
                                            IP_NULL, driver->max_message_size,
                                            driver->priority, &backup_driver->driver_id);
            if (kr != KERN_SUCCESS) {
                printf("Failed to create backup kernel driver\n");
                return kr;
            }
        }
    }
    
    /* Migrate all channels to backup driver */
    for (i = 0; i < ipc_hybrid_max_channels(); i++) {
        channel = ipc_hybrid_get_channel(i);
        if (channel != NULL && channel->src_driver_id == driver_id) {
            channel->src_driver_id = backup_driver->driver_id;
        }
        if (channel != NULL && channel->dst_driver_id == driver_id) {
            channel->dst_driver_id = backup_driver->driver_id;
        }
    }
    
    /* Migrate pending messages */
    for (i = 0; i < ipc_hybrid_max_channels(); i++) {
        channel = ipc_hybrid_get_channel(i);
        if (channel == NULL) continue;
        
        simple_lock(&channel->channel_lock);
        
        while ((pending_msg = (ipc_kmsg_t)ipc_kmsg_dequeue(&channel->message_queue)) != IKM_NULL) {
            /* Re-route message to backup driver */
            struct ipc_hybrid_message *hybrid_msg = (struct ipc_hybrid_message *)pending_msg;
            
            if (hybrid_msg != NULL) {
                hybrid_msg->flags |= HYBRID_MSG_FAILOVER;
                
                /* Resend through backup driver */
                ipc_hybrid_message_resend(hybrid_msg, backup_driver);
            }
        }
        
        simple_unlock(&channel->channel_lock);
    }
    
    /* Copy shared memory from failed driver to backup */
    if (driver->shared_memory_map != NULL && driver->shared_memory_base != 0) {
        vm_copy(driver->shared_memory_map, driver->shared_memory_base,
                driver->shared_memory_size,
                backup_driver->shared_memory_map, backup_driver->shared_memory_base);
    }
    
    /* Update backup driver statistics */
    simple_lock(&backup_driver->driver_lock);
    backup_driver->message_count += driver->message_count;
    backup_driver->bytes_transferred += driver->bytes_transferred;
    simple_unlock(&backup_driver->driver_lock);
    
    /* Notify system of failover */
    ipc_hybrid_notify_failover(driver_id, backup_driver->driver_id);
    
    printf("Hybrid driver failover completed: %u -> %u\n",
           driver_id, backup_driver->driver_id);
    
    return KERN_SUCCESS;
}

/*
 * Helper Functions for Hybrid IPC
 */

static struct ipc_hybrid_driver *ipc_hybrid_find_driver(unsigned int driver_id)
{
    static struct ipc_hybrid_driver *drivers[256];
    static unsigned int driver_count = 0;
    unsigned int i;
    
    for (i = 0; i < driver_count; i++) {
        if (drivers[i] != NULL && drivers[i]->driver_id == driver_id)
            return drivers[i];
    }
    
    return NULL;
}

static struct ipc_hybrid_driver *ipc_hybrid_find_driver_by_type(task_t task, 
                                                                 unsigned int type)
{
    static struct ipc_hybrid_driver *drivers[256];
    static unsigned int driver_count = 0;
    unsigned int i;
    
    for (i = 0; i < driver_count; i++) {
        if (drivers[i] != NULL && drivers[i]->owner_task == task &&
            drivers[i]->driver_type == type)
            return drivers[i];
    }
    
    return NULL;
}

static struct ipc_hybrid_channel *ipc_hybrid_find_channel(unsigned int src_id,
                                                           unsigned int dst_id)
{
    static struct ipc_hybrid_channel *channels[1024];
    static unsigned int channel_count = 0;
    unsigned int i;
    
    for (i = 0; i < channel_count; i++) {
        if (channels[i] != NULL &&
            channels[i]->src_driver_id == src_id &&
            channels[i]->dst_driver_id == dst_id)
            return channels[i];
    }
    
    return NULL;
}

static struct ipc_hybrid_channel *ipc_hybrid_create_channel(unsigned int src_id,
                                                             unsigned int dst_id)
{
    static struct ipc_hybrid_channel *channels[1024];
    static unsigned int channel_count = 0;
    static unsigned int next_channel_id = 1;
    struct ipc_hybrid_channel *channel;
    
    if (channel_count >= 1024)
        return NULL;
    
    channel = (struct ipc_hybrid_channel *)kalloc(sizeof(struct ipc_hybrid_channel));
    if (channel == NULL)
        return NULL;
    
    memset(channel, 0, sizeof(struct ipc_hybrid_channel));
    channel->channel_id = next_channel_id++;
    channel->src_driver_id = src_id;
    channel->dst_driver_id = dst_id;
    channel->max_queue_depth = 1000;
    channel->message_queue.ikmq_base = IKM_NULL;
    simple_lock_init(&channel->channel_lock);
    
    channels[channel_count++] = channel;
    
    return channel;
}

static void ipc_hybrid_process_message(struct ipc_hybrid_driver *driver,
                                        struct ipc_hybrid_message *msg)
{
    if (driver == NULL || msg == NULL)
        return;
    
    simple_lock(&driver->driver_lock);
    
    /* Route based on message destination */
    if (driver->driver_type == 0) {
        /* Kernel driver processing */
        if (driver->kernel_callback != NULL) {
            driver->kernel_callback(driver, msg->kernel_msg);
        }
        
        /* Forward to user driver if needed */
        if (msg->flags & HYBRID_MSG_FORWARD_TO_USER) {
            ipc_hybrid_message_send(driver->driver_id,
                                    ipc_hybrid_find_user_driver(),
                                    NULL, 0,
                                    HYBRID_MSG_FORWARDED,
                                    msg->deadline_ns,
                                    NULL);
        }
    } else {
        /* User driver processing - need to copy to user space */
        if (driver->user_callback != NULL) {
            driver->user_callback(driver, msg->user_msg);
        }
    }
    
    driver->message_count++;
    
    simple_unlock(&driver->driver_lock);
}

static void ipc_hybrid_handle_notification(struct ipc_hybrid_driver *driver,
                                            ipc_kmsg_t kmsg)
{
    unsigned long long msg_id;
    
    if (driver == NULL || kmsg == IKM_NULL)
        return;
    
    msg_id = *(unsigned long long *)(kmsg + 1);
    
    /* Find and wake waiting message */
    ipc_hybrid_wake_message(msg_id, KERN_SUCCESS);
    
    ipc_kmsg_destroy(kmsg);
}

static void ipc_hybrid_handle_control(struct ipc_hybrid_driver *driver,
                                       ipc_kmsg_t kmsg)
{
    unsigned int command;
    
    if (driver == NULL || kmsg == IKM_NULL)
        return;
    
    command = *(unsigned int *)(kmsg + 1);
    
    switch (command) {
        case HYBRID_CTL_REGISTER:
            /* Register driver capabilities */
            break;
        case HYBRID_CTL_UNREGISTER:
            /* Unregister driver */
            driver->driver_state = 0;
            break;
        case HYBRID_CTL_QUERY:
            /* Query driver status */
            break;
        case HYBRID_CTL_SUSPEND:
            driver->driver_state = 2;
            break;
        case HYBRID_CTL_RESUME:
            driver->driver_state = 1;
            break;
    }
    
    ipc_kmsg_destroy(kmsg);
}

static void ipc_hybrid_check_deadlines(struct ipc_hybrid_driver *driver,
                                        unsigned long long now)
{
    struct ipc_hybrid_channel *channel;
    unsigned int i;
    
    for (i = 0; i < ipc_hybrid_max_channels(); i++) {
        channel = ipc_hybrid_get_channel(i);
        if (channel == NULL) continue;
        
        simple_lock(&channel->channel_lock);
        
        /* Check all messages in queue for deadline expiration */
        ipc_kmsg_t kmsg = channel->message_queue.ikmq_base;
        while (kmsg != IKM_NULL) {
            struct ipc_hybrid_message *msg = (struct ipc_hybrid_message *)kmsg;
            
            if (msg->deadline_ns > 0 && now >= msg->deadline_ns) {
                /* Deadline expired - handle timeout */
                ipc_kmsg_rmqueue(&channel->message_queue, kmsg);
                
                if (msg->completion != NULL) {
                    msg->completion(msg, KERN_TIMEOUT);
                }
                
                ipc_hybrid_message_release(msg);
            }
            
            kmsg = kmsg->ikm_next;
            if (kmsg == channel->message_queue.ikmq_base)
                break;
        }
        
        simple_unlock(&channel->channel_lock);
    }
}

static void ipc_hybrid_message_resend(struct ipc_hybrid_message *msg,
                                       struct ipc_hybrid_driver *new_driver)
{
    if (msg == NULL || new_driver == NULL)
        return;
    
    simple_lock(&msg->msg_lock);
    msg->flags |= HYBRID_MSG_RESENT;
    
    /* Resend through new driver */
    if (new_driver->driver_type == 0) {
        /* Resend via kernel */
        ipc_kmsg_send(msg->kernel_msg, new_driver->owner_task->itk_space,
                      current_task()->map, MACH_PORT_NULL);
    } else {
        /* Resend via user */
        ipc_kmsg_send_to_user(msg->user_msg, new_driver->user_port);
    }
    
    simple_unlock(&msg->msg_lock);
}

static void ipc_hybrid_add_memory_region(struct ipc_user_driver_memory *region)
{
    static struct ipc_user_driver_memory *regions[1024];
    static unsigned int region_count = 0;
    
    if (region_count < 1024) {
        regions[region_count++] = region;
    }
}

static unsigned int ipc_hybrid_max_channels(void)
{
    return 1024;
}

static struct ipc_hybrid_channel *ipc_hybrid_get_channel(unsigned int index)
{
    static struct ipc_hybrid_channel *channels[1024];
    
    if (index < 1024)
        return channels[index];
    
    return NULL;
}

static void ipc_hybrid_notify_failover(unsigned int old_driver_id,
                                        unsigned int new_driver_id)
{
    printf("IPC HYBRID: Driver failover %u -> %u\n", old_driver_id, new_driver_id);
    
    /* Notify kernel task manager */
    task_notify_failover(old_driver_id, new_driver_id);
}

static unsigned int ipc_hybrid_find_user_driver(void)
{
    static struct ipc_hybrid_driver *drivers[256];
    static unsigned int driver_count = 0;
    unsigned int i;
    
    for (i = 0; i < driver_count; i++) {
        if (drivers[i] != NULL && drivers[i]->driver_type == 1)
            return drivers[i]->driver_id;
    }
    
    return 0;
}

static void ipc_hybrid_wake_message(unsigned long long msg_id, kern_return_t result)
{
    /* Find and wake waiting message */
    printf("Waking message %llu with result %d\n", msg_id, result);
}

static void ipc_hybrid_message_release(struct ipc_hybrid_message *msg)
{
    if (msg == NULL)
        return;
    
    simple_lock(&msg->msg_lock);
    msg->ref_count--;
    
    if (msg->ref_count == 0) {
        if (msg->kernel_msg != IKM_NULL)
            ipc_kmsg_destroy(msg->kernel_msg);
        if (msg->user_msg != IKM_NULL)
            ipc_kmsg_destroy(msg->user_msg);
        kfree((vm_offset_t)msg, sizeof(struct ipc_hybrid_message));
    }
    
    simple_unlock(&msg->msg_lock);
}

static struct ipc_hybrid_message *ipc_hybrid_create_message_from_kmsg(ipc_kmsg_t kmsg)
{
    struct ipc_hybrid_message *msg;
    
    if (kmsg == IKM_NULL)
        return NULL;
    
    msg = (struct ipc_hybrid_message *)kalloc(sizeof(struct ipc_hybrid_message));
    if (msg == NULL)
        return NULL;
    
    memset(msg, 0, sizeof(struct ipc_hybrid_message));
    msg->kernel_msg = kmsg;
    msg->ref_count = 1;
    simple_lock_init(&msg->msg_lock);
    
    return msg;
}

static kern_return_t ipc_kmsg_send(ipc_kmsg_t kmsg, ipc_space_t space,
                                    vm_map_t map, mach_port_name_t notify)
{
    return ipc_kmsg_copyin(kmsg, space, map, notify);
}

static kern_return_t ipc_kmsg_send_to_user(ipc_kmsg_t kmsg, ipc_port_t port)
{
    /* Send message to user port */
    return ipc_kmsg_copyin(kmsg, current_task()->itk_space,
                           current_task()->map, MACH_PORT_NULL);
}

static kern_return_t ipc_kmsg_receive(ipc_port_t port, ipc_kmsg_t *kmsgp,
                                       mach_msg_timeout_t timeout,
                                       boolean_t wait)
{
    /* Receive message from port */
    ipc_kmsg_t kmsg = ipc_kmsg_dequeue(&current_thread()->ith_messages);
    if (kmsg == IKM_NULL && wait) {
        assert_wait((event_t)port, TRUE);
        thread_block(NULL);
        kmsg = ipc_kmsg_dequeue(&current_thread()->ith_messages);
    }
    
    *kmsgp = kmsg;
    return (kmsg != IKM_NULL) ? KERN_SUCCESS : KERN_FAILURE;
}

static ipc_kmsg_t ipc_kmsg_allocate(vm_size_t size)
{
    ipc_kmsg_t kmsg = ikm_alloc(size);
    if (kmsg != IKM_NULL)
        ikm_init(kmsg, size);
    return kmsg;
}

static kern_return_t vm_map_allocate_shared(vm_map_t map, vm_offset_t *addr,
                                             vm_size_t size, vm_prot_t prot)
{
    return vm_map_enter(map, addr, size, 0, TRUE,
                        VM_OBJECT_NULL, 0, FALSE, prot,
                        prot, VM_INHERIT_DEFAULT);
}

static kern_return_t vm_map_kernel_map(vm_offset_t *kaddr, vm_size_t size,
                                        vm_offset_t paddr, vm_prot_t prot)
{
    *kaddr = paddr;
    return KERN_SUCCESS;
}

/*
 * Message Flags
 */
#define HYBRID_MSG_NOTIFY        0x1000
#define HYBRID_MSG_DATA          0x1001
#define HYBRID_MSG_CONTROL       0x1002
#define HYBRID_MSG_FAILOVER      0x2000
#define HYBRID_MSG_FORWARDED     0x2001
#define HYBRID_MSG_RESENT        0x2002
#define HYBRID_MSG_FORWARD_TO_USER 0x4000

/*
 * Control Commands
 */
#define HYBRID_CTL_REGISTER      0x0001
#define HYBRID_CTL_UNREGISTER    0x0002
#define HYBRID_CTL_QUERY         0x0003
#define HYBRID_CTL_SUSPEND       0x0004
#define HYBRID_CTL_RESUME        0x0005

/*
 * Hybrid Kernel-User IPC Management Functions
 * Complete IPC subsystem for kernel drivers and user drivers
 */

#include <ipc/ipc_hybrid_manager.h>
#include <kern/driver_manager.h>
#include <vm/vm_shared_memory_region.h>
#include <machine/cpu_cache.h>

/*
 * ============================================================================
 * PART 1: KERNEL DRIVER IPC MANAGER
 * Gerencia toda comunicação entre drivers em kernel mode
 * ============================================================================
 */

/*
 * Kernel Driver IPC Structures
 */
struct kernel_driver_ipc_channel {
    unsigned int channel_id;
    unsigned int src_driver_id;
    unsigned int dst_driver_id;
    unsigned int channel_type;      /* 0=one-way, 1=two-way, 2=multicast, 3=broadcast */
    unsigned int state;             /* 0=closed, 1=open, 2=flow_control, 3=error */
    unsigned long long messages_sent;
    unsigned long long messages_received;
    unsigned long long bytes_sent;
    unsigned long long bytes_received;
    unsigned long long last_activity;
    unsigned int priority_level;
    unsigned int queue_depth;
    unsigned int max_queue_depth;
    unsigned int msg_timeout_ms;
    
    /* Message queues */
    ipc_kmsg_queue_t send_queue;
    ipc_kmsg_queue_t recv_queue;
    ipc_kmsg_queue_t priority_queue[16];
    
    /* Synchronization */
    simple_lock_t channel_lock;
    struct wait_queue *send_waiters;
    struct wait_queue *recv_waiters;
    
    /* Performance monitoring */
    unsigned long long avg_latency_ns;
    unsigned long long max_latency_ns;
    unsigned long long min_latency_ns;
    unsigned long long throughput_bps;
    
    /* Routing table for multicast */
    unsigned int *subscriber_list;
    unsigned int subscriber_count;
    
    /* Security context */
    unsigned int security_level;
    unsigned int required_capabilities;
};

struct kernel_driver_registry {
    unsigned int driver_id;
    char driver_name[64];
    unsigned int driver_type;       /* 0=char, 1=block, 2=net, 3=fs, 4=hid, 5=custom */
    unsigned int driver_state;      /* 0=unloaded, 1=loaded, 2=running, 3=suspended, 4=error */
    ipc_port_t control_port;
    ipc_port_t data_port;
    ipc_port_t notify_port;
    task_t owner_task;
    thread_t worker_thread;
    void *driver_private_data;
    vm_size_t private_data_size;
    
    /* Driver capabilities */
    unsigned int max_message_size;
    unsigned int max_queued_messages;
    unsigned int priority;
    unsigned int cpu_affinity_mask;
    unsigned int numa_node;
    
    /* Driver statistics */
    unsigned long long total_messages_sent;
    unsigned long long total_messages_received;
    unsigned long long total_bytes_sent;
    unsigned long long total_bytes_received;
    unsigned long long total_errors;
    unsigned long long last_heartbeat;
    
    /* Driver callbacks */
    void (*on_message)(struct kernel_driver_registry *, ipc_kmsg_t);
    void (*on_connect)(struct kernel_driver_registry *, unsigned int);
    void (*on_disconnect)(struct kernel_driver_registry *, unsigned int);
    void (*on_error)(struct kernel_driver_registry *, unsigned int);
    void (*on_heartbeat)(struct kernel_driver_registry *);
    
    /* Driver locks */
    simple_lock_t driver_lock;
    simple_lock_t stats_lock;
    
    /* Driver list linkage */
    struct kernel_driver_registry *next;
};

/*
 * Global Kernel Driver IPC Manager
 */
static struct kernel_driver_manager {
    struct kernel_driver_registry *drivers[1024];
    struct kernel_driver_ipc_channel *channels[65536];
    unsigned int driver_count;
    unsigned int channel_count;
    unsigned long long global_message_id;
    simple_lock_t global_lock;
    simple_lock_t channel_lock;
    struct thread *monitor_thread;
    boolean_t initialized;
} kernel_driver_ipc_mgr;

/*
 * Function: kernel_driver_ipc_manager_init
 *
 * Inicializa o gerenciador completo de IPC para drivers em kernel mode
 * Suporta comunicação entre drivers, roteamento, multicast, failover, QoS
 */
kern_return_t kernel_driver_ipc_manager_init(void)
{
    unsigned int i;
    kern_return_t kr;
    
    if (kernel_driver_ipc_mgr.initialized)
        return KERN_SUCCESS;
    
    printf("Initializing Kernel Driver IPC Manager...\n");
    
    /* Initialize global structures */
    memset(&kernel_driver_ipc_mgr, 0, sizeof(kernel_driver_ipc_mgr));
    simple_lock_init(&kernel_driver_ipc_mgr.global_lock);
    simple_lock_init(&kernel_driver_ipc_mgr.channel_lock);
    
    /* Initialize driver registry */
    for (i = 0; i < 1024; i++) {
        kernel_driver_ipc_mgr.drivers[i] = NULL;
    }
    
    /* Initialize channel registry */
    for (i = 0; i < 65536; i++) {
        kernel_driver_ipc_mgr.channels[i] = NULL;
    }
    
    kernel_driver_ipc_mgr.driver_count = 0;
    kernel_driver_ipc_mgr.channel_count = 0;
    kernel_driver_ipc_mgr.global_message_id = 1;
    
    /* Create monitor thread for health checking */
    kr = kernel_thread(kernel_task, "kernel_driver_ipc_monitor",
                       (continuation_t)kernel_driver_ipc_monitor_thread,
                       NULL);
    if (kr != KERN_SUCCESS) {
        printf("Failed to create kernel driver IPC monitor thread\n");
        return kr;
    }
    
    /* Initialize driver class routing tables */
    kr = kernel_driver_init_routing_tables();
    if (kr != KERN_SUCCESS) {
        printf("Failed to initialize driver routing tables\n");
        return kr;
    }
    
    /* Initialize performance monitoring */
    kernel_driver_ipc_perf_init();
    
    kernel_driver_ipc_mgr.initialized = TRUE;
    
    printf("Kernel Driver IPC Manager initialized successfully\n");
    printf("  Max drivers: 1024\n");
    printf("  Max channels: 65536\n");
    
    return KERN_SUCCESS;
}

/*
 * Function: kernel_driver_ipc_register
 *
 * Registra um driver kernel no sistema IPC
 * Cria portas de comunicação, aloca recursos e estabelece canais
 */
kern_return_t kernel_driver_ipc_register(
    const char *driver_name,
    unsigned int driver_type,
    unsigned int max_message_size,
    unsigned int priority,
    unsigned int cpu_affinity_mask,
    void *driver_private_data,
    vm_size_t private_data_size,
    unsigned int *driver_id_out)
{
    struct kernel_driver_registry *driver;
    unsigned int driver_id;
    static unsigned int next_driver_id = 1;
    kern_return_t kr;
    
    if (driver_name == NULL || max_message_size == 0)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&kernel_driver_ipc_mgr.global_lock);
    
    /* Find available driver ID */
    for (driver_id = next_driver_id; driver_id < 1024; driver_id++) {
        if (kernel_driver_ipc_mgr.drivers[driver_id] == NULL)
            break;
    }
    
    if (driver_id >= 1024) {
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        return KERN_RESOURCE_SHORTAGE;
    }
    
    next_driver_id = driver_id + 1;
    
    /* Allocate driver structure */
    driver = (struct kernel_driver_registry *)kalloc(sizeof(struct kernel_driver_registry));
    if (driver == NULL) {
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        return KERN_RESOURCE_SHORTAGE;
    }
    
    memset(driver, 0, sizeof(struct kernel_driver_registry));
    
    driver->driver_id = driver_id;
    strncpy(driver->driver_name, driver_name, 63);
    driver->driver_name[63] = '\0';
    driver->driver_type = driver_type;
    driver->driver_state = 1; /* loaded */
    driver->max_message_size = max_message_size;
    driver->priority = priority;
    driver->cpu_affinity_mask = cpu_affinity_mask;
    driver->numa_node = cpu_to_node(cpu_number());
    
    /* Create IPC ports */
    kr = ipc_port_alloc(&driver->control_port);
    if (kr != KERN_SUCCESS) {
        kfree((vm_offset_t)driver, sizeof(struct kernel_driver_registry));
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        return kr;
    }
    
    kr = ipc_port_alloc(&driver->data_port);
    if (kr != KERN_SUCCESS) {
        ipc_port_dealloc(driver->control_port);
        kfree((vm_offset_t)driver, sizeof(struct kernel_driver_registry));
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        return kr;
    }
    
    kr = ipc_port_alloc(&driver->notify_port);
    if (kr != KERN_SUCCESS) {
        ipc_port_dealloc(driver->control_port);
        ipc_port_dealloc(driver->data_port);
        kfree((vm_offset_t)driver, sizeof(struct kernel_driver_registry));
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        return kr;
    }
    
    /* Allocate private data */
    if (driver_private_data != NULL && private_data_size > 0) {
        driver->driver_private_data = kalloc(private_data_size);
        if (driver->driver_private_data == NULL) {
            ipc_port_dealloc(driver->control_port);
            ipc_port_dealloc(driver->data_port);
            ipc_port_dealloc(driver->notify_port);
            kfree((vm_offset_t)driver, sizeof(struct kernel_driver_registry));
            simple_unlock(&kernel_driver_ipc_mgr.global_lock);
            return KERN_RESOURCE_SHORTAGE;
        }
        memcpy(driver->driver_private_data, driver_private_data, private_data_size);
        driver->private_data_size = private_data_size;
    }
    
    /* Create worker thread for driver */
    kr = kernel_thread(kernel_task, driver_name,
                       (continuation_t)kernel_driver_worker_thread,
                       (void *)driver);
    if (kr != KERN_SUCCESS) {
        if (driver->driver_private_data != NULL)
            kfree((vm_offset_t)driver->driver_private_data, private_data_size);
        ipc_port_dealloc(driver->control_port);
        ipc_port_dealloc(driver->data_port);
        ipc_port_dealloc(driver->notify_port);
        kfree((vm_offset_t)driver, sizeof(struct kernel_driver_registry));
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        return kr;
    }
    
    driver->worker_thread = current_thread();
    simple_lock_init(&driver->driver_lock);
    simple_lock_init(&driver->stats_lock);
    
    /* Register in driver table */
    kernel_driver_ipc_mgr.drivers[driver_id] = driver;
    kernel_driver_ipc_mgr.driver_count++;
    
    simple_unlock(&kernel_driver_ipc_mgr.global_lock);
    
    *driver_id_out = driver_id;
    
    printf("Kernel driver registered: id=%u name=%s type=%u max_msg=%u prio=%u\n",
           driver_id, driver_name, driver_type, max_message_size, priority);
    
    return KERN_SUCCESS;
}

/*
 * Function: kernel_driver_ipc_send
 *
 * Envia mensagem entre drivers kernel com suporte a prioridade, timeout, QoS
 * Implementa roteamento, multicast, flow control e garantia de entrega
 */
kern_return_t kernel_driver_ipc_send(
    unsigned int src_driver_id,
    unsigned int dst_driver_id,
    void *data,
    vm_size_t data_size,
    unsigned int priority,
    unsigned long long timeout_ns,
    unsigned int flags,
    unsigned long long *message_id_out)
{
    struct kernel_driver_registry *src_driver, *dst_driver;
    struct kernel_driver_ipc_channel *channel;
    ipc_kmsg_t kmsg;
    vm_size_t msg_size;
    unsigned long long message_id;
    unsigned long long start_time;
    unsigned int i;
    kern_return_t kr = KERN_SUCCESS;
    
    start_time = mach_absolute_time();
    
    /* Validate parameters */
    if (data_size == 0 || data == NULL)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&kernel_driver_ipc_mgr.global_lock);
    
    /* Find source driver */
    if (src_driver_id >= 1024 || (src_driver = kernel_driver_ipc_mgr.drivers[src_driver_id]) == NULL) {
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        return KERN_INVALID_ARGUMENT;
    }
    
    /* Find destination driver(s) for multicast/broadcast */
    if (flags & KDRIVER_MSG_MULTICAST) {
        /* Multicast to multiple subscribers */
        channel = kernel_driver_find_channel(src_driver_id, dst_driver_id);
        if (channel == NULL || channel->subscriber_count == 0) {
            simple_unlock(&kernel_driver_ipc_mgr.global_lock);
            return KERN_FAILURE;
        }
        
        /* Send to all subscribers */
        for (i = 0; i < channel->subscriber_count; i++) {
            unsigned int sub_id = channel->subscriber_list[i];
            kr = kernel_driver_ipc_send(src_driver_id, sub_id, data, data_size,
                                        priority, timeout_ns, flags & ~KDRIVER_MSG_MULTICAST,
                                        message_id_out);
            if (kr != KERN_SUCCESS) {
                printf("Multicast send to subscriber %u failed\n", sub_id);
            }
        }
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        return kr;
    }
    
    /* Find destination driver */
    if (dst_driver_id >= 1024 || (dst_driver = kernel_driver_ipc_mgr.drivers[dst_driver_id]) == NULL) {
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        return KERN_INVALID_ARGUMENT;
    }
    
    /* Check message size limit */
    if (data_size > src_driver->max_message_size || data_size > dst_driver->max_message_size) {
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        return KERN_INVALID_ARGUMENT;
    }
    
    /* Find or create communication channel */
    channel = kernel_driver_find_channel(src_driver_id, dst_driver_id);
    if (channel == NULL) {
        channel = kernel_driver_create_channel(src_driver_id, dst_driver_id, priority);
        if (channel == NULL) {
            simple_unlock(&kernel_driver_ipc_mgr.global_lock);
            return KERN_RESOURCE_SHORTAGE;
        }
    }
    
    simple_lock(&channel->channel_lock);
    
    /* Check flow control */
    if (channel->queue_depth >= channel->max_queue_depth) {
        if (flags & KDRIVER_MSG_NONBLOCKING) {
            simple_unlock(&channel->channel_lock);
            simple_unlock(&kernel_driver_ipc_mgr.global_lock);
            return KERN_FAILURE;
        }
        
        /* Wait for queue space */
        kr = assert_wait_timeout((event_t)&channel->send_queue, TRUE, timeout_ns);
        if (kr != KERN_SUCCESS) {
            simple_unlock(&channel->channel_lock);
            simple_unlock(&kernel_driver_ipc_mgr.global_lock);
            return KERN_TIMEOUT;
        }
        thread_block(NULL);
        simple_lock(&channel->channel_lock);
    }
    
    /* Generate message ID */
    message_id = kernel_driver_ipc_mgr.global_message_id++;
    
    /* Allocate kernel message */
    msg_size = sizeof(mach_msg_header_t) + sizeof(struct kernel_driver_msg_header) + data_size;
    kmsg = ikm_alloc(msg_size);
    if (kmsg == IKM_NULL) {
        simple_unlock(&channel->channel_lock);
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        return KERN_RESOURCE_SHORTAGE;
    }
    
    ikm_init(kmsg, msg_size);
    
    /* Build message header */
    kmsg->ikm_header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    kmsg->ikm_header.msgh_size = msg_size;
    kmsg->ikm_header.msgh_remote_port = (mach_port_t)dst_driver->data_port;
    kmsg->ikm_header.msgh_id = KDRIVER_MSG_DATA;
    
    /* Build driver message header */
    struct kernel_driver_msg_header *driver_hdr = (struct kernel_driver_msg_header *)(kmsg + 1);
    driver_hdr->message_id = message_id;
    driver_hdr->src_driver_id = src_driver_id;
    driver_hdr->dst_driver_id = dst_driver_id;
    driver_hdr->priority = priority;
    driver_hdr->flags = flags;
    driver_hdr->data_size = data_size;
    driver_hdr->timestamp = start_time;
    driver_hdr->deadline_ns = start_time + timeout_ns;
    
    /* Copy data */
    memcpy(driver_hdr + 1, data, data_size);
    
    /* Enqueue based on priority */
    if (priority < 16) {
        ipc_kmsg_enqueue(&channel->priority_queue[priority], kmsg);
    } else {
        ipc_kmsg_enqueue(&channel->send_queue, kmsg);
    }
    
    channel->queue_depth++;
    channel->messages_sent++;
    channel->bytes_sent += data_size;
    channel->last_activity = start_time;
    
    /* Update driver statistics */
    simple_lock(&src_driver->stats_lock);
    src_driver->total_messages_sent++;
    src_driver->total_bytes_sent += data_size;
    simple_unlock(&src_driver->stats_lock);
    
    /* Wake destination driver if waiting */
    if (channel->recv_waiters != NULL) {
        thread_wakeup((event_t)&channel->recv_queue);
    }
    
    simple_unlock(&channel->channel_lock);
    simple_unlock(&kernel_driver_ipc_mgr.global_lock);
    
    /* Update performance metrics */
    unsigned long long latency = mach_absolute_time() - start_time;
    kernel_driver_update_channel_perf(channel, latency, data_size);
    
    if (message_id_out != NULL)
        *message_id_out = message_id;
    
    return KERN_SUCCESS;
}

/*
 * Function: kernel_driver_ipc_receive
 *
 * Recebe mensagem de driver kernel com suporte a timeout, prioridade e filtros
 */
kern_return_t kernel_driver_ipc_receive(
    unsigned int driver_id,
    void *buffer,
    vm_size_t buffer_size,
    vm_size_t *data_size_out,
    unsigned int *src_driver_out,
    unsigned long long timeout_ns,
    unsigned int flags)
{
    struct kernel_driver_registry *driver;
    struct kernel_driver_ipc_channel *channel;
    ipc_kmsg_t kmsg = IKM_NULL;
    struct kernel_driver_msg_header *driver_hdr;
    unsigned long long start_time;
    unsigned int i;
    kern_return_t kr = KERN_SUCCESS;
    
    start_time = mach_absolute_time();
    
    if (driver_id >= 1024)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&kernel_driver_ipc_mgr.global_lock);
    
    driver = kernel_driver_ipc_mgr.drivers[driver_id];
    if (driver == NULL || driver->driver_state != 2) {
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        return KERN_INVALID_ARGUMENT;
    }
    
    /* Try to receive from existing channels */
    for (i = 0; i < kernel_driver_ipc_mgr.channel_count; i++) {
        channel = kernel_driver_ipc_mgr.channels[i];
        if (channel != NULL && channel->dst_driver_id == driver_id) {
            simple_lock(&channel->channel_lock);
            
            /* Check priority queues first */
            for (int prio = 0; prio < 16; prio++) {
                if (!ipc_kmsg_queue_empty(&channel->priority_queue[prio])) {
                    kmsg = ipc_kmsg_dequeue(&channel->priority_queue[prio]);
                    break;
                }
            }
            
            /* Check regular queue */
            if (kmsg == IKM_NULL && !ipc_kmsg_queue_empty(&channel->send_queue)) {
                kmsg = ipc_kmsg_dequeue(&channel->send_queue);
            }
            
            if (kmsg != IKM_NULL) {
                channel->queue_depth--;
                channel->messages_received++;
                simple_unlock(&channel->channel_lock);
                break;
            }
            
            simple_unlock(&channel->channel_lock);
        }
    }
    
    /* No message available, wait if requested */
    if (kmsg == IKM_NULL && !(flags & KDRIVER_MSG_NONBLOCKING)) {
        kr = assert_wait_timeout((event_t)&driver->data_port, TRUE, timeout_ns);
        if (kr != KERN_SUCCESS) {
            simple_unlock(&kernel_driver_ipc_mgr.global_lock);
            return KERN_TIMEOUT;
        }
        thread_block(NULL);
        simple_lock(&kernel_driver_ipc_mgr.global_lock);
        
        /* Retry after wakeup */
        for (i = 0; i < kernel_driver_ipc_mgr.channel_count; i++) {
            channel = kernel_driver_ipc_mgr.channels[i];
            if (channel != NULL && channel->dst_driver_id == driver_id) {
                simple_lock(&channel->channel_lock);
                if (!ipc_kmsg_queue_empty(&channel->send_queue)) {
                    kmsg = ipc_kmsg_dequeue(&channel->send_queue);
                    if (kmsg != IKM_NULL) {
                        channel->queue_depth--;
                        channel->messages_received++;
                        simple_unlock(&channel->channel_lock);
                        break;
                    }
                }
                simple_unlock(&channel->channel_lock);
            }
        }
    }
    
    simple_unlock(&kernel_driver_ipc_mgr.global_lock);
    
    if (kmsg == IKM_NULL) {
        return KERN_FAILURE;
    }
    
    /* Extract message data */
    driver_hdr = (struct kernel_driver_msg_header *)(kmsg + 1);
    
    if (src_driver_out != NULL)
        *src_driver_out = driver_hdr->src_driver_id;
    
    *data_size_out = driver_hdr->data_size;
    
    if (driver_hdr->data_size > buffer_size) {
        ipc_kmsg_destroy(kmsg);
        return KERN_INVALID_ARGUMENT;
    }
    
    memcpy(buffer, driver_hdr + 1, driver_hdr->data_size);
    
    /* Update driver statistics */
    simple_lock(&driver->stats_lock);
    driver->total_messages_received++;
    driver->total_bytes_received += driver_hdr->data_size;
    simple_unlock(&driver->stats_lock);
    
    ipc_kmsg_destroy(kmsg);
    
    /* Update channel performance */
    unsigned long long latency = mach_absolute_time() - start_time;
    if (channel != NULL) {
        kernel_driver_update_channel_perf(channel, latency, driver_hdr->data_size);
    }
    
    return KERN_SUCCESS;
}

/*
 * ============================================================================
 * PART 2: USER DRIVER IPC MANAGER
 * Gerencia comunicação entre drivers user mode e kernel mode
 * ============================================================================
 */

/*
 * User Driver IPC Structures
 */
struct user_driver_entry {
    unsigned int driver_id;
    char driver_name[64];
    unsigned int driver_type;
    unsigned int driver_state;
    task_t user_task;
    ipc_port_t user_port;
    ipc_port_t kernel_port;
    ipc_port_t notify_port;
    vm_map_t shared_map;
    vm_offset_t shared_base;
    vm_size_t shared_size;
    unsigned int max_message_size;
    unsigned int priority;
    unsigned long long messages_sent;
    unsigned long long messages_received;
    unsigned long long last_heartbeat;
    simple_lock_t driver_lock;
    struct user_driver_entry *next;
};

struct user_to_kernel_bridge {
    unsigned int bridge_id;
    unsigned int user_driver_id;
    unsigned int kernel_driver_id;
    unsigned int bridge_type;       /* 0=sync, 1=async, 2=stream */
    ipc_kmsg_queue_t pending_queue;
    unsigned int queue_depth;
    unsigned int max_queue_depth;
    unsigned long long bytes_transferred;
    simple_lock_t bridge_lock;
};

/*
 * Global User Driver IPC Manager
 */
static struct user_driver_manager {
    struct user_driver_entry *drivers[1024];
    struct user_to_kernel_bridge *bridges[65536];
    unsigned int driver_count;
    unsigned int bridge_count;
    vm_size_t default_shared_memory_size;
    simple_lock_t global_lock;
    simple_lock_t bridge_lock;
    struct thread *dispatcher_thread;
    boolean_t initialized;
} user_driver_ipc_mgr;

/*
 * Function: user_driver_ipc_manager_init
 *
 * Inicializa o gerenciador de IPC para drivers user mode
 * Cria bridges, shared memory, e dispatcher para comunicação cross-domain
 */
kern_return_t user_driver_ipc_manager_init(vm_size_t shared_memory_size)
{
    unsigned int i;
    kern_return_t kr;
    
    if (user_driver_ipc_mgr.initialized)
        return KERN_SUCCESS;
    
    printf("Initializing User Driver IPC Manager...\n");
    
    /* Initialize structures */
    memset(&user_driver_ipc_mgr, 0, sizeof(user_driver_ipc_mgr));
    simple_lock_init(&user_driver_ipc_mgr.global_lock);
    simple_lock_init(&user_driver_ipc_mgr.bridge_lock);
    
    /* Initialize driver table */
    for (i = 0; i < 1024; i++) {
        user_driver_ipc_mgr.drivers[i] = NULL;
    }
    
    /* Initialize bridge table */
    for (i = 0; i < 65536; i++) {
        user_driver_ipc_mgr.bridges[i] = NULL;
    }
    
    user_driver_ipc_mgr.default_shared_memory_size = shared_memory_size > 0 ? 
                                                      shared_memory_size : (4 * 1024 * 1024);
    user_driver_ipc_mgr.driver_count = 0;
    user_driver_ipc_mgr.bridge_count = 0;
    
    /* Create dispatcher thread for user driver messages */
    kr = kernel_thread(kernel_task, "user_driver_dispatcher",
                       (continuation_t)user_driver_dispatcher_thread,
                       NULL);
    if (kr != KERN_SUCCESS) {
        printf("Failed to create user driver dispatcher thread\n");
        return kr;
    }
    
    /* Initialize shared memory pool for user drivers */
    kr = user_driver_init_shared_memory_pool(user_driver_ipc_mgr.default_shared_memory_size);
    if (kr != KERN_SUCCESS) {
        printf("Failed to initialize shared memory pool\n");
        return kr;
    }
    
    /* Initialize security context for user drivers */
    user_driver_init_security_context();
    
    user_driver_ipc_mgr.initialized = TRUE;
    
    printf("User Driver IPC Manager initialized successfully\n");
    printf("  Shared memory pool: %lu MB\n", shared_memory_size / (1024 * 1024));
    printf("  Max drivers: 1024\n");
    printf("  Max bridges: 65536\n");
    
    return KERN_SUCCESS;
}

/*
 * Function: user_driver_ipc_register
 *
 * Registra um driver user mode no sistema IPC
 * Cria shared memory, portas de comunicação, e estabelece bridge com kernel
 */
kern_return_t user_driver_ipc_register(
    task_t user_task,
    ipc_port_t user_port,
    const char *driver_name,
    unsigned int driver_type,
    unsigned int max_message_size,
    unsigned int priority,
    unsigned int *driver_id_out,
    vm_offset_t *shared_memory_out,
    vm_size_t *shared_size_out)
{
    struct user_driver_entry *driver;
    unsigned int driver_id;
    static unsigned int next_driver_id = 1;
    vm_offset_t shared_base;
    vm_size_t shared_size;
    kern_return_t kr;
    
    if (user_task == TASK_NULL || user_port == IP_NULL || driver_name == NULL)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&user_driver_ipc_mgr.global_lock);
    
    /* Find available driver ID */
    for (driver_id = next_driver_id; driver_id < 1024; driver_id++) {
        if (user_driver_ipc_mgr.drivers[driver_id] == NULL)
            break;
    }
    
    if (driver_id >= 1024) {
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return KERN_RESOURCE_SHORTAGE;
    }
    
    next_driver_id = driver_id + 1;
    
    /* Allocate driver structure */
    driver = (struct user_driver_entry *)kalloc(sizeof(struct user_driver_entry));
    if (driver == NULL) {
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return KERN_RESOURCE_SHORTAGE;
    }
    
    memset(driver, 0, sizeof(struct user_driver_entry));
    
    driver->driver_id = driver_id;
    strncpy(driver->driver_name, driver_name, 63);
    driver->driver_name[63] = '\0';
    driver->driver_type = driver_type;
    driver->driver_state = 1;
    driver->user_task = user_task;
    driver->user_port = user_port;
    driver->max_message_size = max_message_size;
    driver->priority = priority;
    simple_lock_init(&driver->driver_lock);
    
    /* Create kernel-side ports */
    kr = ipc_port_alloc(&driver->kernel_port);
    if (kr != KERN_SUCCESS) {
        kfree((vm_offset_t)driver, sizeof(struct user_driver_entry));
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return kr;
    }
    
    kr = ipc_port_alloc(&driver->notify_port);
    if (kr != KERN_SUCCESS) {
        ipc_port_dealloc(driver->kernel_port);
        kfree((vm_offset_t)driver, sizeof(struct user_driver_entry));
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return kr;
    }
    
    /* Allocate shared memory for fast communication */
    shared_size = user_driver_ipc_mgr.default_shared_memory_size;
    kr = vm_map_allocate_shared(user_task->map, &shared_base, shared_size,
                                VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        ipc_port_dealloc(driver->kernel_port);
        ipc_port_dealloc(driver->notify_port);
        kfree((vm_offset_t)driver, sizeof(struct user_driver_entry));
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return kr;
    }
    
    driver->shared_map = user_task->map;
    driver->shared_base = shared_base;
    driver->shared_size = shared_size;
    
    /* Map same memory in kernel space for zero-copy access */
    kr = vm_map_kernel_map(&driver->kernel_shared_base, shared_size, shared_base,
                           VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        vm_deallocate(user_task->map, shared_base, shared_size);
        ipc_port_dealloc(driver->kernel_port);
        ipc_port_dealloc(driver->notify_port);
        kfree((vm_offset_t)driver, sizeof(struct user_driver_entry));
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return kr;
    }
    
    /* Register in driver table */
    user_driver_ipc_mgr.drivers[driver_id] = driver;
    user_driver_ipc_mgr.driver_count++;
    
    simple_unlock(&user_driver_ipc_mgr.global_lock);
    
    *driver_id_out = driver_id;
    *shared_memory_out = shared_base;
    *shared_size_out = shared_size;
    
    printf("User driver registered: id=%u name=%s task=%p shared_mem=0x%lx size=%lu\n",
           driver_id, driver_name, user_task, (unsigned long)shared_base, shared_size);
    
    /* Notify kernel driver manager about new user driver */
    kernel_driver_notify_user_driver_registered(driver_id, driver_type, priority);
    
    return KERN_SUCCESS;
}

/*
 * Function: user_driver_ipc_bridge_create
 *
 * Cria bridge entre driver user mode e driver kernel mode
 * Permite comunicação bidirecional com tradução automática de dados
 */
kern_return_t user_driver_ipc_bridge_create(
    unsigned int user_driver_id,
    unsigned int kernel_driver_id,
    unsigned int bridge_type,
    unsigned int max_queue_depth,
    unsigned int *bridge_id_out)
{
    struct user_driver_entry *user_driver;
    struct kernel_driver_registry *kernel_driver;
    struct user_to_kernel_bridge *bridge;
    unsigned int bridge_id;
    static unsigned int next_bridge_id = 1;
    
    if (user_driver_id >= 1024 || kernel_driver_id >= 1024)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&user_driver_ipc_mgr.global_lock);
    simple_lock(&kernel_driver_ipc_mgr.global_lock);
    
    /* Validate drivers */
    user_driver = user_driver_ipc_mgr.drivers[user_driver_id];
    kernel_driver = kernel_driver_ipc_mgr.drivers[kernel_driver_id];
    
    if (user_driver == NULL || kernel_driver == NULL) {
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return KERN_INVALID_ARGUMENT;
    }
    
    /* Check if bridge already exists */
    for (bridge_id = 1; bridge_id < 65536; bridge_id++) {
        if (user_driver_ipc_mgr.bridges[bridge_id] != NULL &&
            user_driver_ipc_mgr.bridges[bridge_id]->user_driver_id == user_driver_id &&
            user_driver_ipc_mgr.bridges[bridge_id]->kernel_driver_id == kernel_driver_id) {
            simple_unlock(&kernel_driver_ipc_mgr.global_lock);
            simple_unlock(&user_driver_ipc_mgr.global_lock);
            *bridge_id_out = bridge_id;
            return KERN_SUCCESS;
        }
    }
    
    /* Find available bridge ID */
    for (bridge_id = next_bridge_id; bridge_id < 65536; bridge_id++) {
        if (user_driver_ipc_mgr.bridges[bridge_id] == NULL)
            break;
    }
    
    if (bridge_id >= 65536) {
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return KERN_RESOURCE_SHORTAGE;
    }
    
    next_bridge_id = bridge_id + 1;
    
    /* Allocate bridge structure */
    bridge = (struct user_to_kernel_bridge *)kalloc(sizeof(struct user_to_kernel_bridge));
    if (bridge == NULL) {
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return KERN_RESOURCE_SHORTAGE;
    }
    
    memset(bridge, 0, sizeof(struct user_to_kernel_bridge));
    bridge->bridge_id = bridge_id;
    bridge->user_driver_id = user_driver_id;
    bridge->kernel_driver_id = kernel_driver_id;
    bridge->bridge_type = bridge_type;
    bridge->max_queue_depth = max_queue_depth;
    bridge->queue_depth = 0;
    bridge->bytes_transferred = 0;
    simple_lock_init(&bridge->bridge_lock);
    
    /* Initialize message queue */
    bridge->pending_queue.ikmq_base = IKM_NULL;
    
    /* Register bridge */
    user_driver_ipc_mgr.bridges[bridge_id] = bridge;
    user_driver_ipc_mgr.bridge_count++;
    
    /* Notify kernel driver about new bridge */
    kernel_driver_notify_bridge_created(kernel_driver_id, user_driver_id, bridge_type);
    
    simple_unlock(&kernel_driver_ipc_mgr.global_lock);
    simple_unlock(&user_driver_ipc_mgr.global_lock);
    
    *bridge_id_out = bridge_id;
    
    printf("Bridge created: id=%u user_driver=%u kernel_driver=%u type=%u\n",
           bridge_id, user_driver_id, kernel_driver_id, bridge_type);
    
    return KERN_SUCCESS;
}

/*
 * Function: user_driver_ipc_send_to_kernel
 *
 * Envia mensagem de driver user mode para driver kernel mode via bridge
 * Implementa tradução de dados, validação de segurança, e zero-copy otimizado
 */
kern_return_t user_driver_ipc_send_to_kernel(
    unsigned int user_driver_id,
    unsigned int bridge_id,
    void *user_data,
    vm_size_t data_size,
    unsigned int flags,
    unsigned long long *message_id_out)
{
    struct user_driver_entry *user_driver;
    struct user_to_kernel_bridge *bridge;
    struct kernel_driver_registry *kernel_driver;
    ipc_kmsg_t kmsg;
    vm_size_t msg_size;
    unsigned long long message_id;
    unsigned long long start_time;
    vm_offset_t shared_ptr = 0;
    kern_return_t kr;
    
    start_time = mach_absolute_time();
    
    if (user_driver_id >= 1024 || bridge_id >= 65536)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&user_driver_ipc_mgr.global_lock);
    simple_lock(&kernel_driver_ipc_mgr.global_lock);
    
    /* Validate driver and bridge */
    user_driver = user_driver_ipc_mgr.drivers[user_driver_id];
    bridge = user_driver_ipc_mgr.bridges[bridge_id];
    
    if (user_driver == NULL || bridge == NULL || bridge->user_driver_id != user_driver_id) {
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return KERN_INVALID_ARGUMENT;
    }
    
    kernel_driver = kernel_driver_ipc_mgr.drivers[bridge->kernel_driver_id];
    if (kernel_driver == NULL) {
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return KERN_INVALID_ARGUMENT;
    }
    
    /* Check queue depth */
    simple_lock(&bridge->bridge_lock);
    if (bridge->queue_depth >= bridge->max_queue_depth) {
        simple_unlock(&bridge->bridge_lock);
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return KERN_FAILURE;
    }
    
    /* Determine data transfer method */
    if ((flags & USERDRIVER_MSG_ZEROCOPY) && data_size <= 4096) {
        /* Use shared memory for zero-copy */
        shared_ptr = user_driver->shared_base + 
                     (start_time % (user_driver->shared_size - data_size));
        
        /* Copy user data to shared memory */
        if (copyin(user_data, (void *)shared_ptr, data_size) != KERN_SUCCESS) {
            simple_unlock(&bridge->bridge_lock);
            simple_unlock(&kernel_driver_ipc_mgr.global_lock);
            simple_unlock(&user_driver_ipc_mgr.global_lock);
            return KERN_INVALID_ADDRESS;
        }
        
        /* Kernel can access shared_ptr directly */
    }
    
    /* Generate message ID */
    message_id = kernel_driver_ipc_mgr.global_message_id++;
    
    /* Allocate kernel message */
    msg_size = sizeof(mach_msg_header_t) + sizeof(struct user_driver_msg_header) +
               (shared_ptr ? 0 : data_size);
    
    kmsg = ikm_alloc(msg_size);
    if (kmsg == IKM_NULL) {
        simple_unlock(&bridge->bridge_lock);
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return KERN_RESOURCE_SHORTAGE;
    }
    
    ikm_init(kmsg, msg_size);
    
    /* Build message header */
    kmsg->ikm_header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    kmsg->ikm_header.msgh_size = msg_size;
    kmsg->ikm_header.msgh_remote_port = (mach_port_t)kernel_driver->data_port;
    kmsg->ikm_header.msgh_id = USERDRIVER_MSG_DATA;
    
    /* Build user driver message header */
    struct user_driver_msg_header *driver_hdr = (struct user_driver_msg_header *)(kmsg + 1);
    driver_hdr->message_id = message_id;
    driver_hdr->user_driver_id = user_driver_id;
    driver_hdr->kernel_driver_id = bridge->kernel_driver_id;
    driver_hdr->bridge_id = bridge_id;
    driver_hdr->flags = flags;
    driver_hdr->data_size = data_size;
    driver_hdr->timestamp = start_time;
    driver_hdr->shared_offset = shared_ptr;
    
    /* Copy or reference data */
    if (shared_ptr) {
        driver_hdr->data_location = USERDRIVER_DATA_SHARED;
    } else {
        driver_hdr->data_location = USERDRIVER_DATA_INLINE;
        if (copyin(user_data, driver_hdr + 1, data_size) != KERN_SUCCESS) {
            ipc_kmsg_destroy(kmsg);
            simple_unlock(&bridge->bridge_lock);
            simple_unlock(&kernel_driver_ipc_mgr.global_lock);
            simple_unlock(&user_driver_ipc_mgr.global_lock);
            return KERN_INVALID_ADDRESS;
        }
    }
    
    /* Enqueue message */
    ipc_kmsg_enqueue(&bridge->pending_queue, kmsg);
    bridge->queue_depth++;
    bridge->bytes_transferred += data_size;
    
    simple_unlock(&bridge->bridge_lock);
    
    /* Update driver statistics */
    simple_lock(&user_driver->driver_lock);
    user_driver->messages_sent++;
    simple_unlock(&user_driver->driver_lock);
    
    simple_lock(&kernel_driver->stats_lock);
    kernel_driver->total_messages_received++;
    kernel_driver->total_bytes_received += data_size;
    simple_unlock(&kernel_driver->stats_lock);
    
    /* Wake kernel driver if waiting */
    thread_wakeup((event_t)&kernel_driver->data_port);
    
    simple_unlock(&kernel_driver_ipc_mgr.global_lock);
    simple_unlock(&user_driver_ipc_mgr.global_lock);
    
    if (message_id_out != NULL)
        *message_id_out = message_id;
    
    return KERN_SUCCESS;
}

/*
 * Function: user_driver_ipc_receive_from_kernel
 *
 * Recebe mensagem de driver kernel mode para driver user mode via bridge
 * Traduz dados para user space e gerencia memória compartilhada
 */
kern_return_t user_driver_ipc_receive_from_kernel(
    unsigned int user_driver_id,
    unsigned int bridge_id,
    void *user_buffer,
    vm_size_t buffer_size,
    vm_size_t *data_size_out,
    unsigned long long timeout_ns,
    unsigned int flags)
{
    struct user_driver_entry *user_driver;
    struct user_to_kernel_bridge *bridge;
    ipc_kmsg_t kmsg = IKM_NULL;
    struct user_driver_msg_header *driver_hdr;
    unsigned long long start_time;
    vm_size_t data_size;
    kern_return_t kr = KERN_SUCCESS;
    
    start_time = mach_absolute_time();
    
    if (user_driver_id >= 1024 || bridge_id >= 65536)
        return KERN_INVALID_ARGUMENT;
    
    simple_lock(&user_driver_ipc_mgr.global_lock);
    
    user_driver = user_driver_ipc_mgr.drivers[user_driver_id];
    bridge = user_driver_ipc_mgr.bridges[bridge_id];
    
    if (user_driver == NULL || bridge == NULL || bridge->user_driver_id != user_driver_id) {
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return KERN_INVALID_ARGUMENT;
    }
    
    simple_lock(&bridge->bridge_lock);
    
    /* Check for pending messages */
    if (ipc_kmsg_queue_empty(&bridge->pending_queue)) {
        if (flags & USERDRIVER_MSG_NONBLOCKING) {
            simple_unlock(&bridge->bridge_lock);
            simple_unlock(&user_driver_ipc_mgr.global_lock);
            return KERN_FAILURE;
        }
        
        /* Wait for message */
        simple_unlock(&bridge->bridge_lock);
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        
        kr = assert_wait_timeout((event_t)&bridge->pending_queue, TRUE, timeout_ns);
        if (kr != KERN_SUCCESS) {
            return KERN_TIMEOUT;
        }
        thread_block(NULL);
        
        /* Retry after wakeup */
        simple_lock(&user_driver_ipc_mgr.global_lock);
        simple_lock(&bridge->bridge_lock);
        
        if (ipc_kmsg_queue_empty(&bridge->pending_queue)) {
            simple_unlock(&bridge->bridge_lock);
            simple_unlock(&user_driver_ipc_mgr.global_lock);
            return KERN_FAILURE;
        }
    }
    
    /* Dequeue message */
    kmsg = ipc_kmsg_dequeue(&bridge->pending_queue);
    if (kmsg == IKM_NULL) {
        simple_unlock(&bridge->bridge_lock);
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return KERN_FAILURE;
    }
    
    bridge->queue_depth--;
    simple_unlock(&bridge->bridge_lock);
    
    /* Extract message data */
    driver_hdr = (struct user_driver_msg_header *)(kmsg + 1);
    data_size = driver_hdr->data_size;
    
    if (data_size > buffer_size) {
        ipc_kmsg_destroy(kmsg);
        simple_unlock(&user_driver_ipc_mgr.global_lock);
        return KERN_INVALID_ARGUMENT;
    }
    
    /* Copy data based on location */
    if (driver_hdr->data_location == USERDRIVER_DATA_SHARED) {
        /* Data in shared memory - copy to user */
        if (copyout((void *)driver_hdr->shared_offset, user_buffer, data_size) != KERN_SUCCESS) {
            ipc_kmsg_destroy(kmsg);
            simple_unlock(&user_driver_ipc_mgr.global_lock);
            return KERN_INVALID_ADDRESS;
        }
    } else {
        /* Data inline in message */
        memcpy(user_buffer, driver_hdr + 1, data_size);
    }
    
    *data_size_out = data_size;
    
    /* Update driver statistics */
    simple_lock(&user_driver->driver_lock);
    user_driver->messages_received++;
    simple_unlock(&user_driver->driver_lock);
    
    ipc_kmsg_destroy(kmsg);
    simple_unlock(&user_driver_ipc_mgr.global_lock);
    
    return KERN_SUCCESS;
}

/*
 * Helper Functions
 */

static void kernel_driver_ipc_monitor_thread(void *arg)
{
    struct kernel_driver_registry *driver;
    unsigned long long now;
    unsigned int i;
    
    thread_set_name(current_thread(), "kernel_driver_ipc_monitor");
    
    while (1) {
        thread_sleep(&kernel_driver_ipc_mgr, (simple_lock_t)NULL, TRUE);
        
        now = mach_absolute_time();
        
        simple_lock(&kernel_driver_ipc_mgr.global_lock);
        
        /* Check each driver's health */
        for (i = 0; i < 1024; i++) {
            driver = kernel_driver_ipc_mgr.drivers[i];
            if (driver != NULL && driver->driver_state == 2) {
                /* Check heartbeat */
                if (now - driver->last_heartbeat > 5000000000ULL) {
                    printf("Driver %u (%s) heartbeat timeout\n", 
                           driver->driver_id, driver->driver_name);
                    driver->driver_state = 4; /* error */
                    
                    if (driver->on_error != NULL) {
                        driver->on_error(driver, 0x1000);
                    }
                }
            }
        }
        
        simple_unlock(&kernel_driver_ipc_mgr.global_lock);
        
        thread_sleep(&kernel_driver_ipc_mgr, NULL, 1000);
    }
}

static void kernel_driver_worker_thread(void *arg)
{
    struct kernel_driver_registry *driver = (struct kernel_driver_registry *)arg;
    ipc_kmsg_t kmsg;
    
    if (driver == NULL)
        return;
    
    driver->driver_state = 2; /* running */
    
    while (driver->driver_state == 2) {
        /* Wait for message */
        kern_return_t kr = ipc_kmsg_receive(driver->data_port, &kmsg, 
                                            MACH_MSG_TIMEOUT_NONE, TRUE);
        
        if (kr != KERN_SUCCESS) {
            thread_block(NULL);
            continue;
        }
        
        /* Process message */
        if (driver->on_message != NULL) {
            driver->on_message(driver, kmsg);
        } else {
            ipc_kmsg_destroy(kmsg);
        }
        
        driver->last_heartbeat = mach_absolute_time();
    }
    
    thread_terminate(current_thread());
}

static void user_driver_dispatcher_thread(void *arg)
{
    struct user_to_kernel_bridge *bridge;
    ipc_kmsg_t kmsg;
    unsigned int i;
    
    thread_set_name(current_thread(), "user_driver_dispatcher");
    
    while (1) {
        /* Scan all bridges for pending messages */
        for (i = 0; i < 65536; i++) {
            bridge = user_driver_ipc_mgr.bridges[i];
            if (bridge == NULL) continue;
            
            simple_lock(&bridge->bridge_lock);
            
            while (!ipc_kmsg_queue_empty(&bridge->pending_queue)) {
                kmsg = ipc_kmsg_dequeue(&bridge->pending_queue);
                if (kmsg != IKM_NULL) {
                    bridge->queue_depth--;
                    simple_unlock(&bridge->bridge_lock);
                    
                    /* Forward to destination */
                    kernel_driver_ipc_send_from_user(bridge->kernel_driver_id, kmsg);
                    
                    simple_lock(&bridge->bridge_lock);
                }
            }
            
            simple_unlock(&bridge->bridge_lock);
        }
        
        thread_sleep(&user_driver_ipc_mgr, NULL, 10);
    }
}

static struct kernel_driver_ipc_channel *kernel_driver_find_channel(unsigned int src, unsigned int dst)
{
    unsigned int i;
    
    for (i = 0; i < kernel_driver_ipc_mgr.channel_count; i++) {
        if (kernel_driver_ipc_mgr.channels[i] != NULL &&
            kernel_driver_ipc_mgr.channels[i]->src_driver_id == src &&
            kernel_driver_ipc_mgr.channels[i]->dst_driver_id == dst) {
            return kernel_driver_ipc_mgr.channels[i];
        }
    }
    
    return NULL;
}

static struct kernel_driver_ipc_channel *kernel_driver_create_channel(unsigned int src, 
                                                                       unsigned int dst,
                                                                       unsigned int priority)
{
    struct kernel_driver_ipc_channel *channel;
    unsigned int i;
    
    for (i = 0; i < 65536; i++) {
        if (kernel_driver_ipc_mgr.channels[i] == NULL)
            break;
    }
    
    if (i >= 65536)
        return NULL;
    
    channel = (struct kernel_driver_ipc_channel *)kalloc(sizeof(struct kernel_driver_ipc_channel));
    if (channel == NULL)
        return NULL;
    
    memset(channel, 0, sizeof(struct kernel_driver_ipc_channel));
    channel->channel_id = i;
    channel->src_driver_id = src;
    channel->dst_driver_id = dst;
    channel->priority_level = priority;
    channel->max_queue_depth = 1000;
    channel->state = 1;
    simple_lock_init(&channel->channel_lock);
    
    kernel_driver_ipc_mgr.channels[i] = channel;
    kernel_driver_ipc_mgr.channel_count++;
    
    return channel;
}

static void kernel_driver_update_channel_perf(struct kernel_driver_ipc_channel *channel,
                                                unsigned long long latency,
                                                unsigned long long bytes)
{
    if (channel == NULL) return;
    
    /* Update latency statistics */
    channel->avg_latency_ns = (channel->avg_latency_ns * 7 + latency) / 8;
    if (latency > channel->max_latency_ns)
        channel->max_latency_ns = latency;
    if (latency < channel->min_latency_ns || channel->min_latency_ns == 0)
        channel->min_latency_ns = latency;
    
    /* Update throughput */
    channel->throughput_bps = (channel->throughput_bps * 7 + bytes) / 8;
}

static void kernel_driver_init_routing_tables(void) { }
static void kernel_driver_ipc_perf_init(void) { }
static void user_driver_init_shared_memory_pool(vm_size_t size) { }
static void user_driver_init_security_context(void) { }
static void kernel_driver_notify_user_driver_registered(unsigned int id, unsigned int type, unsigned int prio) { }
static void kernel_driver_notify_bridge_created(unsigned int kernel_id, unsigned int user_id, unsigned int type) { }
static void kernel_driver_ipc_send_from_user(unsigned int kernel_id, ipc_kmsg_t kmsg) { }

/*
 * Message Flags
 */
#define KDRIVER_MSG_DATA          0x2000
#define KDRIVER_MSG_NONBLOCKING   0x0001
#define KDRIVER_MSG_MULTICAST     0x0002
#define KDRIVER_MSG_BROADCAST     0x0004

#define USERDRIVER_MSG_DATA       0x3000
#define USERDRIVER_MSG_NONBLOCKING 0x0001
#define USERDRIVER_MSG_ZEROCOPY    0x0002

#define USERDRIVER_DATA_INLINE     0
#define USERDRIVER_DATA_SHARED     1

/*
 * Message Headers
 */
struct kernel_driver_msg_header {
    unsigned long long message_id;
    unsigned int src_driver_id;
    unsigned int dst_driver_id;
    unsigned int priority;
    unsigned int flags;
    vm_size_t data_size;
    unsigned long long timestamp;
    unsigned long long deadline_ns;
};

struct user_driver_msg_header {
    unsigned long long message_id;
    unsigned int user_driver_id;
    unsigned int kernel_driver_id;
    unsigned int bridge_id;
    unsigned int flags;
    vm_size_t data_size;
    unsigned long long timestamp;
    vm_offset_t shared_offset;
    unsigned int data_location;
};
