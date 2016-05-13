/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Stony Brook University 2016
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * A very simple session slot table for NFSv4.1 client.
 */

#ifndef __TC_NFS4_SESSION_SLOTS_H__
#define __TC_NFS4_SESSION_SLOTS_H__

#include <pthread.h>
#include <stdbool.h>

#include "abstract_atomic.h"
#include "common_types.h"

#define SESSION_SLOT_TABLE_CAPACITY 128

struct session_slot_table {
	pthread_mutex_t mutex;   /* protect used_slots */
	pthread_cond_t slot_cv;  /* to wait for slots */
	/**
	 * A slotid is an index; each elements in slots is a sequenceid4.
	 */
	uint32_t slots[SESSION_SLOT_TABLE_CAPACITY];
	uint32_t highest_used_slotid_plus1; /* highest outstanding slotid + 1*/
	uint32_t server_highest_slotid;     /* highest slot server allows */
	uint32_t target_highest_slotid;     /* target hightest server desires */
        bitset_t *free_slots;               /* bitset of free slots */
};

struct session_slot_table *new_session_slot_table();

/**
 * Not thread-safe; should not be called concurrently.
 */
void del_session_slot_table(struct session_slot_table **sst);

/**
 * Allocate a session slot to use.  When no slot is available, it puts the
 * calling thread to sleep until a slot becomes available.
 *
 * It is called before a compound.  It is thread-safe.
 *
 * Return a slotid.
 */
int alloc_session_slot(struct session_slot_table *sst, uint32_t *sequence,
		       uint32_t *highest_slotid);

/**
 * Free the session slot specified by the "slotid".  It is thread-safe.
 *
 * @slotid: slotid to be freed.
 * @server_highest: the highest slot ID the server will accept
 * @target_highest: the target_highest_slotid server desires
 * @sent: whether a RPC has been sent to server or not.  It is false when RPC
 * fail to initiate the RPC.
 */
void free_session_slot(struct session_slot_table *sst, int slotid,
		       uint32_t server_highest, uint32_t target_highest,
		       bool sent);

static inline uint32_t get_slot_sequence(struct session_slot_table *sst,
					 int slotid)
{
	assert(slotid < SESSION_SLOT_TABLE_CAPACITY);
	return atomic_fetch_uint32_t(sst->slots + slotid);
}

#endif  /* __TC_NFS4_SESSION_SLOTS_H__ */
