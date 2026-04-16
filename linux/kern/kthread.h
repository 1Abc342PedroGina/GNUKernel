#ifndef KERN_KTHREAD_H
#define KERN_KTHREAD_H

/* SPDX License Indentifier:GPL-2.0-or-later */

#include <sys/queue.h>

struct kthread_q {
	SIMPLEQ_ENTRY(kthread_q) kq_q;
	void (*kq_func)(void *);
	void *kq_arg;
};

#endif
