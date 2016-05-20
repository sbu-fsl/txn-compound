/**
 * Copyright (C) Stony Brook University 2016
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef __TC_HELPER_H__
#define __TC_HELPER_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "tc_api.h"
#include "common_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A counter of function calling statistics.
 */
struct tc_func_counter {
	const char *name;
	uint32_t calls;      /* # of calls (or RPCs) */
	uint32_t failures;   /* # of failures of the calls */
	uint64_t micro_ops;  /* # of operations (or RPC bytes) */
	uint64_t time_ns;    /* the total time in calling these functions */
	struct tc_func_counter *next;
};

void tc_register_counter(struct tc_func_counter *tfc);

void tc_iterate_counters(bool (*tfc_reader)(struct tc_func_counter *tfc,
					    void *arg),
			 void *arg);

#define TC_COUNTER_OUTPUT_INTERVAL 5

#define TC_DECLARE_COUNTER(nm)                                                 \
	struct timespec nm##_start_tm;                                         \
	struct timespec nm##_stop_tm;                                          \
	static struct tc_func_counter nm##_tc_counter = { .name = #nm,         \
							  .calls = 0,          \
							  .micro_ops = 0,      \
							  .time_ns = 0,        \
							  .next = NULL, };     \
	tc_register_counter(&nm##_tc_counter)

#define TC_START_COUNTER(nm)                                                   \
	now(&nm##_start_tm);                                                   \
	__sync_fetch_and_add(&nm##_tc_counter.calls, 1)

#define TC_STOP_COUNTER(nm, ops, succeed)                                      \
	do {                                                                   \
		now(&nm##_stop_tm);                                            \
		if (succeed) {                                                 \
			__sync_fetch_and_add(&nm##_tc_counter.micro_ops, ops); \
			__sync_fetch_and_add(                                  \
			    &nm##_tc_counter.time_ns,                          \
			    timespec_diff(&nm##_start_tm, &nm##_stop_tm));     \
		} else {                                                       \
			__sync_fetch_and_add(&nm##_tc_counter.failures, 1);    \
		}                                                              \
	} while (false)

/**
 * Free an array of tc_iovec.
 */
void free_iovec(struct tc_iovec *iovec, int count);

char *get_tc_config_file(char *buf, int buf_size);

/**
 * Compare the data contents of two arrays of tc_iovec.
 *
 * Return whether the two arrays have the same contents.
 */
bool compare_content(struct tc_iovec *iovec1, struct tc_iovec *iovec2,
		     int count);

struct file_handle *new_file_handle(size_t fh_len, char *fh_val);

void del_file_handle(struct file_handle *fh);

void tc_copy_attrs(const struct tc_attrs *src, struct tc_attrs *dst);

bool tc_cmp_file(const tc_file *tcf1, const tc_file *tcf2);

#ifdef __cplusplus
}
#endif

#endif // __TC_HELPER_H__
