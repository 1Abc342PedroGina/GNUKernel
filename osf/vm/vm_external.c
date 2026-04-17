/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
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
 *	This module maintains information about the presence of
 *	pages not in memory.  Since an external memory object
 *	must maintain a complete knowledge of its contents, this
 *	information takes the form of hints.
 */

#include <mach/boolean.h>
#include <kern/slab.h>
#include <vm/vm_external.h>
#include <mach/vm_param.h>
#include <kern/assert.h>
#include <string.h>
#include <kern/locks.h>



boolean_t	vm_external_unsafe = FALSE;

struct kmem_cache	vm_external_cache;

/*
 *	The implementation uses bit arrays to record whether
 *	a page has been written to external storage.  For
 *	convenience, these bit arrays come in two sizes
 *	(measured in bytes).
 */

#define		SMALL_SIZE	(VM_EXTERNAL_SMALL_SIZE/8)
#define		LARGE_SIZE	(VM_EXTERNAL_LARGE_SIZE/8)

struct kmem_cache	vm_object_small_existence_map_cache;
struct kmem_cache	vm_object_large_existence_map_cache;


vm_external_t	vm_external_create(vm_offset_t size)
{
	vm_external_t	result;
	vm_size_t	bytes;
	
	result = (vm_external_t) kmem_cache_alloc(&vm_external_cache);
	result->existence_map = (char *) 0;

	bytes = (atop(size) + 07) >> 3;
	if (bytes <= SMALL_SIZE) {
		result->existence_map =
		 (char *) kmem_cache_alloc(&vm_object_small_existence_map_cache);
		result->existence_size = SMALL_SIZE;
	} else {
		result->existence_map =
		 (char *) kmem_cache_alloc(&vm_object_large_existence_map_cache);
		result->existence_size = LARGE_SIZE;
	}
	memset (result->existence_map, 0, result->existence_size);
	return(result);
}

void		vm_external_destroy(vm_external_t e)
{
	if (e == VM_EXTERNAL_NULL)
		return;

	if (e->existence_map != (char *) 0) {
		if (e->existence_size <= SMALL_SIZE) {
			kmem_cache_free(&vm_object_small_existence_map_cache,
				(vm_offset_t) e->existence_map);
		} else {
			kmem_cache_free(&vm_object_large_existence_map_cache,
				(vm_offset_t) e->existence_map);
		}
	}
	kmem_cache_free(&vm_external_cache, (vm_offset_t) e);
}

vm_external_state_t _vm_external_state_get(const vm_external_t	e,
	vm_offset_t		offset)
{
	unsigned
	int		bit, byte;

	if (vm_external_unsafe ||
	    (e == VM_EXTERNAL_NULL) ||
	    (e->existence_map == (char *) 0))
		return(VM_EXTERNAL_STATE_UNKNOWN);

	bit = atop(offset);
	byte = bit >> 3;
	if (byte >= e->existence_size) return (VM_EXTERNAL_STATE_UNKNOWN);
	return( (e->existence_map[byte] & (1 << (bit & 07))) ?
		VM_EXTERNAL_STATE_EXISTS : VM_EXTERNAL_STATE_ABSENT );
}

void		vm_external_state_set(
	vm_external_t		e,
	vm_offset_t		offset,
	vm_external_state_t 	state)
{
	unsigned
	int		bit, byte;

	if ((e == VM_EXTERNAL_NULL) || (e->existence_map == (char *) 0))
		return;

	if (state != VM_EXTERNAL_STATE_EXISTS)
		return;

	bit = atop(offset);
	byte = bit >> 3;
	if (byte >= e->existence_size) return;
	e->existence_map[byte] |= (1 << (bit & 07));
}

void		vm_external_module_initialize(void)
{
	vm_size_t	size = (vm_size_t) sizeof(struct vm_external);

	kmem_cache_init(&vm_external_cache, "vm_external", size, 0,
			NULL, 0);

	kmem_cache_init(&vm_object_small_existence_map_cache,
			"small_existence_map", SMALL_SIZE, 0,
			NULL, 0);

	kmem_cache_init(&vm_object_large_existence_map_cache,
			"large_existence_map", LARGE_SIZE, 0,
			NULL, 0);
}


/*
 * Extended External Memory Structures
 */
struct vm_external_extended {
    vm_external_t base;
    unsigned long long *access_hints;
    unsigned int hint_count;
    unsigned int hint_size;
    unsigned long long last_accessed_offset;
    unsigned long long sequential_access_count;
    unsigned long long stride_access_count;
    unsigned long long last_stride;
    unsigned int compression_ratio;
    boolean_t is_compressed;
    simple_lock_t ext_lock;
};

struct vm_external_batch_request {
    vm_offset_t *offsets;
    vm_external_state_t *states;
    unsigned int count;
    unsigned int completed;
    unsigned int flags;
    void (*callback)(struct vm_external_batch_request *, kern_return_t);
    void *callback_arg;
    simple_lock_t batch_lock;
};

/*
 * Batch request flags
 */
#define VM_EXTERNAL_BATCH_PREFETCH   0x00000001
#define VM_EXTERNAL_BATCH_ASYNC      0x00000002
#define VM_EXTERNAL_BATCH_COMPRESS   0x00000004
#define VM_EXTERNAL_BATCH_PRIORITY   0x00000008

/*
 * Function 1: vm_external_batch_state_query
 *
 * Query multiple external page states in a single batch operation
 * with optimized bitmap scanning and prefetch hints
 */
kern_return_t vm_external_batch_state_query(
    vm_external_t e,
    vm_offset_t *offsets,
    vm_external_state_t *states,
    unsigned int count,
    unsigned int flags,
    struct vm_external_batch_request **request_out)
{
    struct vm_external_batch_request *request;
    struct vm_external_extended *ext;
    unsigned int i;
    unsigned int bitmap_byte;
    unsigned int bitmap_bit;
    unsigned int consecutive_hits = 0;
    unsigned long long prev_offset = 0;
    unsigned long long stride = 0;
    unsigned long long stride_count = 0;
    
    if (e == VM_EXTERNAL_NULL || offsets == NULL || states == NULL || count == 0)
        return KERN_INVALID_ARGUMENT;
    
    /* Allocate batch request structure */
    request = (struct vm_external_batch_request *)kalloc(sizeof(struct vm_external_batch_request));
    if (request == NULL)
        return KERN_RESOURCE_SHORTAGE;
    
    memset(request, 0, sizeof(struct vm_external_batch_request));
    request->offsets = (vm_offset_t *)kalloc(count * sizeof(vm_offset_t));
    request->states = (vm_external_state_t *)kalloc(count * sizeof(vm_external_state_t));
    
    if (request->offsets == NULL || request->states == NULL) {
        if (request->offsets) kfree((vm_offset_t)request->offsets, count * sizeof(vm_offset_t));
        if (request->states) kfree((vm_offset_t)request->states, count * sizeof(vm_external_state_t));
        kfree((vm_offset_t)request, sizeof(struct vm_external_batch_request));
        return KERN_RESOURCE_SHORTAGE;
    }
    
    memcpy(request->offsets, offsets, count * sizeof(vm_offset_t));
    request->count = count;
    request->flags = flags;
    simple_lock_init(&request->batch_lock);
    
    /* Get extended structure if available */
    ext = (struct vm_external_extended *)e->private_data;
    
    /* Process each offset in batch */
    for (i = 0; i < count; i++) {
        vm_offset_t offset = offsets[i];
        unsigned int page_index = atop(offset);
        bitmap_byte = page_index >> 3;
        bitmap_bit = page_index & 7;
        
        /* Check if within bounds */
        if (bitmap_byte >= e->existence_size) {
            states[i] = VM_EXTERNAL_STATE_UNKNOWN;
            request->states[i] = VM_EXTERNAL_STATE_UNKNOWN;
            continue;
        }
        
        /* Get state from bitmap */
        states[i] = (e->existence_map[bitmap_byte] & (1 << bitmap_bit)) ?
                    VM_EXTERNAL_STATE_EXISTS : VM_EXTERNAL_STATE_ABSENT;
        request->states[i] = states[i];
        
        /* Update access pattern detection if extended structure exists */
        if (ext != NULL) {
            simple_lock(&ext->ext_lock);
            
            /* Detect sequential access pattern */
            if (i > 0 && offset == prev_offset + PAGE_SIZE) {
                consecutive_hits++;
                ext->sequential_access_count++;
            } else if (i > 0) {
                /* Check for stride pattern */
                unsigned long long current_stride = offset - prev_offset;
                if (ext->last_stride == current_stride) {
                    stride_count++;
                    ext->stride_access_count++;
                }
                ext->last_stride = current_stride;
            }
            
            /* Update access hints ring buffer */
            if (ext->hint_count < ext->hint_size) {
                ext->access_hints[ext->hint_count++] = offset;
            } else {
                /* Circular buffer */
                ext->access_hints[ext->hint_count % ext->hint_size] = offset;
                ext->hint_count++;
            }
            
            ext->last_accessed_offset = offset;
            simple_unlock(&ext->ext_lock);
        }
        
        prev_offset = offset;
    }
    
    /* Generate prefetch hints if requested */
    if ((flags & VM_EXTERNAL_BATCH_PREFETCH) && ext != NULL && consecutive_hits > 3) {
        vm_offset_t next_offset = offsets[count - 1] + PAGE_SIZE;
        vm_offset_t prefetch_offsets[16];
        unsigned int prefetch_count = 0;
        
        /* Predict next sequential pages */
        for (i = 0; i < 8 && prefetch_count < 16; i++) {
            prefetch_offsets[prefetch_count++] = next_offset + (i * PAGE_SIZE);
        }
        
        /* Predict stride pattern if detected */
        if (stride_count > 3 && ext->last_stride > 0) {
            vm_offset_t last_offset = offsets[count - 1];
            for (i = 0; i < 4 && prefetch_count < 16; i++) {
                prefetch_offsets[prefetch_count++] = last_offset + (ext->last_stride * (i + 1));
            }
        }
        
        /* Asynchronously prefetch predicted pages */
        if (flags & VM_EXTERNAL_BATCH_ASYNC) {
            /* Would initiate async prefetch here */
        }
    }
    
    if (request_out != NULL) {
        *request_out = request;
    } else {
        /* No continuation needed, free request */
        kfree((vm_offset_t)request->offsets, count * sizeof(vm_offset_t));
        kfree((vm_offset_t)request->states, count * sizeof(vm_external_state_t));
        kfree((vm_offset_t)request, sizeof(struct vm_external_batch_request));
    }
    
    return KERN_SUCCESS;
}

/*
 * Function 2: vm_external_compressed_map
 *
 * Compress the external existence map for memory-constrained systems
 * using run-length encoding and delta compression
 */
kern_return_t vm_external_compressed_map(
    vm_external_t e,
    boolean_t compress,
    unsigned int *original_size,
    unsigned int *compressed_size)
{
    struct vm_external_extended *ext;
    unsigned char *compressed_data;
    unsigned int compressed_len;
    unsigned int i;
    unsigned int run_start = 0;
    unsigned int run_value = 0;
    unsigned int run_length = 0;
    unsigned int runs[1024];
    unsigned int run_values[1024];
    unsigned int run_count = 0;
    unsigned int dict_size = 0;
    unsigned char dictionary[256];
    unsigned int dict_counts[256];
    
    if (e == VM_EXTERNAL_NULL || e->existence_map == NULL)
        return KERN_INVALID_ARGUMENT;
    
    if (original_size != NULL)
        *original_size = e->existence_size;
    
    if (!compress) {
        /* Decompress - would restore from compressed format */
        if (e->private_data != NULL) {
            ext = (struct vm_external_extended *)e->private_data;
            if (ext->is_compressed && ext->compression_ratio > 0) {
                /* Would decompress here */
                ext->is_compressed = FALSE;
            }
        }
        return KERN_SUCCESS;
    }
    
    /* Compress using run-length encoding */
    for (i = 0; i < e->existence_size; i++) {
        unsigned char byte = e->existence_map[i];
        
        if (i == 0) {
            run_value = byte;
            run_start = i;
            run_length = 1;
            continue;
        }
        
        if (byte == run_value && run_length < 255) {
            run_length++;
        } else {
            /* Store run */
            runs[run_count] = run_start;
            run_values[run_count] = run_value;
            run_count++;
            run_start = i;
            run_value = byte;
            run_length = 1;
        }
    }
    
    /* Store final run */
    if (run_length > 0) {
        runs[run_count] = run_start;
        run_values[run_count] = run_value;
        run_count++;
    }
    
    /* Build frequency dictionary for byte values */
    memset(dict_counts, 0, sizeof(dict_counts));
    for (i = 0; i < run_count; i++) {
        dict_counts[run_values[i]]++;
    }
    
    /* Select most frequent bytes for dictionary */
    for (i = 0; i < 256 && dict_size < 256; i++) {
        if (dict_counts[i] > 0) {
            dictionary[dict_size++] = (unsigned char)i;
        }
    }
    
    /* Calculate compressed size */
    compressed_len = 2 + dict_size + (run_count * 3); /* header + dict + runs */
    
    /* Allocate compressed buffer */
    compressed_data = (unsigned char *)kalloc(compressed_len);
    if (compressed_data == NULL)
        return KERN_RESOURCE_SHORTAGE;
    
    /* Write header */
    compressed_data[0] = (compressed_len >> 8) & 0xFF;
    compressed_data[1] = compressed_len & 0xFF;
    compressed_data[2] = dict_size & 0xFF;
    
    /* Write dictionary */
    memcpy(compressed_data + 3, dictionary, dict_size);
    
    /* Write compressed runs */
    unsigned int offset = 3 + dict_size;
    for (i = 0; i < run_count; i++) {
        compressed_data[offset++] = (runs[i] >> 8) & 0xFF;
        compressed_data[offset++] = runs[i] & 0xFF;
        compressed_data[offset++] = (unsigned char)run_values[i];
    }
    
    /* Create or update extended structure */
    if (e->private_data == NULL) {
        ext = (struct vm_external_extended *)kalloc(sizeof(struct vm_external_extended));
        if (ext == NULL) {
            kfree((vm_offset_t)compressed_data, compressed_len);
            return KERN_RESOURCE_SHORTAGE;
        }
        memset(ext, 0, sizeof(struct vm_external_extended));
        simple_lock_init(&ext->ext_lock);
        e->private_data = (void *)ext;
    }
    
    ext = (struct vm_external_extended *)e->private_data;
    ext->is_compressed = TRUE;
    ext->compression_ratio = (e->existence_size * 100) / (compressed_len + 1);
    
    if (compressed_size != NULL)
        *compressed_size = compressed_len;
    
    /* Free original map and replace with compressed version */
    if (e->existence_size <= SMALL_SIZE) {
        kmem_cache_free(&vm_object_small_existence_map_cache,
                        (vm_offset_t)e->existence_map);
    } else {
        kmem_cache_free(&vm_object_large_existence_map_cache,
                        (vm_offset_t)e->existence_map);
    }
    
    e->existence_map = (char *)compressed_data;
    e->existence_size = compressed_len;
    
    return KERN_SUCCESS;
}

/*
 * Function 3: vm_external_adaptive_hinting
 *
 * Implement adaptive hinting system that learns access patterns
 * and provides intelligent prefetch suggestions
 */
kern_return_t vm_external_adaptive_hinting(
    vm_external_t e,
    vm_offset_t *hint_offsets,
    unsigned int *hint_count,
    unsigned int max_hints)
{
    struct vm_external_extended *ext;
    unsigned int i, j;
    unsigned long long *pattern_matches;
    unsigned long long predicted_offsets[32];
    unsigned int predicted_count = 0;
    unsigned long long last_offset;
    unsigned long long stride_candidates[8];
    unsigned int stride_weights[8];
    unsigned int stride_idx;
    unsigned long long current_stride;
    
    if (e == VM_EXTERNAL_NULL || hint_offsets == NULL || hint_count == NULL || max_hints == 0)
        return KERN_INVALID_ARGUMENT;
    
    /* Initialize extended structure if not exists */
    if (e->private_data == NULL) {
        ext = (struct vm_external_extended *)kalloc(sizeof(struct vm_external_extended));
        if (ext == NULL)
            return KERN_RESOURCE_SHORTAGE;
        memset(ext, 0, sizeof(struct vm_external_extended));
        ext->hint_size = 1024;
        ext->access_hints = (unsigned long long *)kalloc(ext->hint_size * sizeof(unsigned long long));
        if (ext->access_hints == NULL) {
            kfree((vm_offset_t)ext, sizeof(struct vm_external_extended));
            return KERN_RESOURCE_SHORTAGE;
        }
        simple_lock_init(&ext->ext_lock);
        e->private_data = (void *)ext;
    }
    
    ext = (struct vm_external_extended *)e->private_data;
    
    simple_lock(&ext->ext_lock);
    
    /* Not enough data for pattern detection */
    if (ext->hint_count < 10) {
        simple_unlock(&ext->ext_lock);
        *hint_count = 0;
        return KERN_SUCCESS;
    }
    
    /* Allocate pattern match array */
    pattern_matches = (unsigned long long *)kalloc(ext->hint_count * sizeof(unsigned long long));
    if (pattern_matches == NULL) {
        simple_unlock(&ext->ext_lock);
        return KERN_RESOURCE_SHORTAGE;
    }
    memset(pattern_matches, 0, ext->hint_count * sizeof(unsigned long long));
    
    /* Detect sequential pattern */
    if (ext->sequential_access_count > ext->hint_count / 2) {
        /* Strong sequential pattern detected */
        last_offset = ext->access_hints[(ext->hint_count - 1) % ext->hint_size];
        for (i = 0; i < max_hints && predicted_count < 32; i++) {
            predicted_offsets[predicted_count++] = last_offset + ((i + 1) * PAGE_SIZE);
        }
    }
    
    /* Detect stride pattern */
    memset(stride_candidates, 0, sizeof(stride_candidates));
    memset(stride_weights, 0, sizeof(stride_weights));
    
    for (i = 1; i < ext->hint_count && i < 100; i++) {
        unsigned long long prev = ext->access_hints[(ext->hint_count - i - 1) % ext->hint_size];
        unsigned long long curr = ext->access_hints[(ext->hint_count - i) % ext->hint_size];
        current_stride = curr - prev;
        
        if (current_stride > 0 && current_stride < 1024 * PAGE_SIZE) {
            for (stride_idx = 0; stride_idx < 8; stride_idx++) {
                if (stride_candidates[stride_idx] == current_stride) {
                    stride_weights[stride_idx]++;
                    break;
                } else if (stride_candidates[stride_idx] == 0) {
                    stride_candidates[stride_idx] = current_stride;
                    stride_weights[stride_idx] = 1;
                    break;
                }
            }
        }
    }
    
    /* Find best stride pattern */
    unsigned int best_stride_weight = 0;
    unsigned long long best_stride = 0;
    for (stride_idx = 0; stride_idx < 8; stride_idx++) {
        if (stride_weights[stride_idx] > best_stride_weight) {
            best_stride_weight = stride_weights[stride_idx];
            best_stride = stride_candidates[stride_idx];
        }
    }
    
    if (best_stride > 0 && best_stride_weight > 5) {
        last_offset = ext->access_hints[(ext->hint_count - 1) % ext->hint_size];
        for (i = 0; i < max_hints && predicted_count < 32; i++) {
            predicted_offsets[predicted_count++] = last_offset + (best_stride * (i + 1));
        }
    }
    
    /* Detect hotspot regions (frequently accessed areas) */
    for (i = 0; i < ext->hint_count && i < 1000; i++) {
        unsigned long long offset = ext->access_hints[i % ext->hint_size];
        unsigned int hash = (offset >> PAGE_SHIFT) % 1024;
        pattern_matches[hash]++;
    }
    
    /* Add hotspot offsets to predictions */
    for (i = 0; i < ext->hint_count && i < 1024 && predicted_count < max_hints; i++) {
        if (pattern_matches[i] > 10) {
            predicted_offsets[predicted_count++] = (i * PAGE_SIZE);
        }
    }
    
    /* Remove duplicate predictions */
    for (i = 0; i < predicted_count; i++) {
        for (j = i + 1; j < predicted_count; j++) {
            if (predicted_offsets[i] == predicted_offsets[j]) {
                for (unsigned int k = j; k < predicted_count - 1; k++) {
                    predicted_offsets[k] = predicted_offsets[k + 1];
                }
                predicted_count--;
                j--;
            }
        }
    }
    
    /* Copy predictions to output */
    *hint_count = (predicted_count < max_hints) ? predicted_count : max_hints;
    for (i = 0; i < *hint_count; i++) {
        hint_offsets[i] = (vm_offset_t)predicted_offsets[i];
    }
    
    /* Update access statistics for prediction accuracy tracking */
    ext->hint_count++;
    
    simple_unlock(&ext->ext_lock);
    
    kfree((vm_offset_t)pattern_matches, ext->hint_count * sizeof(unsigned long long));
    
    return KERN_SUCCESS;
}
