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

#include "session_slots.h"

// number of bits per word
#define NBITSPW (sizeof(int) * 8)

struct session_slot_table *new_session_slot_table()
{
        int i;
	struct session_slot_table *sst;

	sst = malloc(sizeof(*sst));
	if (!sst) {
		return NULL;
	}

	sst->free_slots = new_bitset(SESSION_SLOT_TABLE_CAPACITY);
	if (!sst->free_slots) {
		free(sst);
		return NULL;
	}
	bs_set_all(sst->free_slots);

        for (i = 0; i < SESSION_SLOT_TABLE_CAPACITY; ++i) {
                sst->slots[i] = 1;
        }

	pthread_mutex_init(&sst->mutex, NULL);
	pthread_cond_init(&sst->slot_cv, NULL);
        sst->highest_used_slotid_plus1 = 0;
	sst->server_highest_slotid = SESSION_SLOT_TABLE_CAPACITY - 1;
	sst->target_highest_slotid = SESSION_SLOT_TABLE_CAPACITY - 1;

	return sst;
}

void del_session_slot_table(struct session_slot_table **sst)
{
	if (*sst) {
		assert((*sst)->highest_used_slotid_plus1 == 0);
		del_bitset((*sst)->free_slots);
		free(*sst);
		*sst = NULL;
	}
}

int alloc_session_slot(struct session_slot_table *sst, uint32_t *sequence,
		       uint32_t *highest_slotid)
{
	int pos;
	int slotid = -1;
	static const int N = sizeof(int) * 8;

	pthread_mutex_lock(&sst->mutex);
	slotid = bs_ffs(sst->free_slots);
	while (slotid == -1 || slotid > sst->target_highest_slotid) {
		// wait until a slot becomes available
		pthread_cond_wait(&sst->slot_cv, &sst->mutex);
		slotid = bs_ffs(sst->free_slots);
	}
	bs_reset(sst->free_slots, slotid);
	if (slotid >= sst->highest_used_slotid_plus1) {
		sst->highest_used_slotid_plus1 = slotid + 1;
	}
	*sequence = sst->slots[slotid];
	*highest_slotid = sst->highest_used_slotid_plus1 - 1;
	pthread_mutex_unlock(&sst->mutex);

	return slotid; /* slotid index starts from 0 instead of 1 */
}

void free_session_slot(struct session_slot_table *sst, int slotid,
		       uint32_t server_highest, uint32_t target_highest,
		       bool sent)
{
	pthread_mutex_lock(&sst->mutex);
	assert(!bs_get(sst->free_slots, slotid));
	bs_set(sst->free_slots, slotid);
	if (slotid + 1 == sst->highest_used_slotid_plus1) {
		int s = slotid - 1;
		while (s >= 0 && bs_get(sst->free_slots, s))
			--s;
		sst->highest_used_slotid_plus1 = s + 1;
	}
	if (sent) {
		assert(server_highest + 1 >= sst->highest_used_slotid_plus1);
		sst->server_highest_slotid = server_highest;
		sst->target_highest_slotid = target_highest;
		/* increment sequenceid */
		atomic_inc_uint32_t(sst->slots + slotid);
	}
	if (slotid <= target_highest) {
		pthread_cond_signal(&sst->slot_cv);
	}
	pthread_mutex_unlock(&sst->mutex);
}
