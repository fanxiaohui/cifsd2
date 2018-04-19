/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <linux/slab.h>

#include "inode_cache.h"

static struct cifsd_cache inode_cache;

static void cifsd_inode_free(struct work_struct *work)
{
	struct cifsd_inode *ino = container_of(work,
					       struct cifsd_inode,
					       free_work);

	cifsd_cache_remove(&inode_cache, CIFSD_INODE_LOOKUP_KEY(ino));
	kfree(ino->stream_name);
	kfree(ino);
}

static void __destructor_fn(void *val)
{
	struct cifsd_inode *ino = (struct cifsd_inode *)val;

	schedule_work(&ino->free_work);
}

static void *cifsd_inode_get(struct cifsd_inode *ino)
{
	if (!atomic_inc_not_zero(&ino->i_refcount))
		return NULL;
        return ino;
}

void cifsd_inode_put(struct cifsd_inode *ino)
{
	if (!atomic_dec_and_test(&ino->i_refcount))
		return;
	__destructor_fn(ino);
}

static void *__lookup_fn(void *val)
{
	struct cifsd_inode *ino = (struct cifsd_inode *)val;

	if (!ino->i_inode)
		return NULL;
	return cifsd_inode_get(ino);
}

int cifsd_inode_cache_insert(struct cifsd_inode *ino)
{
	return cifsd_cache_insert(&inode_cache,
				  CIFSD_INODE_LOOKUP_KEY(ino),
				  ino);
}

int cifsd_inode_cache_remove(struct cifsd_inode *ino)
{
	return cifsd_cache_remove(&inode_cache,
				  CIFSD_INODE_LOOKUP_KEY(ino));
}

struct cifsd_inode *cifsd_inode_cache_lookup(unsigned long key)
{
	return cifsd_cache_lookup(&inode_cache, key);
}

struct cifsd_inode *cifsd_inode_alloc(unsigned long key)
{
	struct cifsd_inode *ino;

	ino = cifsd_cache_lookup(&inode_cache, key);
	if (ino)
		return ino;

	ino = kzalloc(sizeof(struct cifsd_inode), GFP_KERNEL);
	if (!ino)
		return NULL;

	spin_lock_init(&ino->i_lock);
	atomic_set(&ino->i_refcount, 1);
	atomic_set(&ino->i_op_count, 0);
	INIT_LIST_HEAD(&ino->i_fp_list);
	INIT_WORK(&ino->free_work, cifsd_inode_free);

	if (cifsd_cache_insert(&inode_cache, key, ino)) {
		kfree(ino);
		ino = cifsd_cache_lookup(&inode_cache, key);
	}

	if (!ino) {
		WARN_ON(1);
		return NULL;
	}

	return ino;
}

int cifsd_inode_cache_init(void)
{
	cifsd_cache_init(&inode_cache,
			__lookup_fn,
			__destructor_fn);
	return 0;
}

void cifsd_inode_cache_destroy(void)
{
	cifsd_cache_destroy(&inode_cache);
}
