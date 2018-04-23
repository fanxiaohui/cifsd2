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

#include "cache.h"
#include "file_cache.h"

static struct cifsd_cache file_cache;

static void cifsd_file_free(struct work_struct *work)
{
	struct cifsd_file *filp = container_of(work,
					      struct cifsd_file,
					      free_work);

	cifsd_cache_remove(&file_cache, CIFSD_FILE_LOOKUP_KEY(filp));
	kfree(filp->stream_name);
	kfree(filp);
}

static void __destructor_fn(void *val)
{
	struct cifsd_file *filp = (struct cifsd_file *)val;

	schedule_work(&filp->free_work);
}

static void *cifsd_file_get(struct cifsd_file *filp)
{
	if (!atomic_inc_not_zero(&filp->i_refcount))
		return NULL;
        return filp;
}

void cifsd_file_put(struct cifsd_file *filp)
{
	if (!atomic_dec_and_test(&filp->i_refcount))
		return;
	__destructor_fn(filp);
}

static void *__lookup_fn(void *val)
{
	struct cifsd_file *filp = (struct cifsd_file *)val;

	if (!filp->i_file)
		return NULL;
	return cifsd_file_get(filp);
}

int cifsd_file_cache_insert(struct cifsd_file *filp)
{
	return cifsd_cache_insert(&file_cache,
				  CIFSD_file_LOOKUP_KEY(filp),
				  filp);
}

int cifsd_file_cache_remove(struct cifsd_file *filp)
{
	return cifsd_cache_remove(&file_cache,
				  CIFSD_file_LOOKUP_KEY(filp));
}

struct cifsd_file *cifsd_file_cache_lookup(unsigned long key)
{
	return cifsd_cache_lookup(&file_cache, key);
}

struct cifsd_file *cifsd_file_alloc(unsigned long key)
{
	struct cifsd_file *filp;

	filp = cifsd_cache_lookup(&file_cache, key);
	if (filp)
		return filp;

	filp = kzalloc(sizeof(struct cifsd_file), GFP_KERNEL);
	if (!filp)
		return NULL;

	spin_lock_init(&filp->i_lock);
	atomic_set(&filp->i_refcount, 1);
	atomic_set(&filp->i_op_count, 0);
	INIT_LIST_HEAD(&filp->i_fp_list);
	INIT_WORK(&filp->free_work, cifsd_file_free);

	if (cifsd_cache_insert(&file_cache, key, filp)) {
		kfree(filp);
		filp = cifsd_cache_lookup(&file_cache, key);
	}

	if (!filp) {
		WARN_ON(1);
		return NULL;
	}

	return filp;
}

int cifsd_file_cache_init(void)
{
	cifsd_cache_init(&file_cache,
			__lookup_fn,
			__destructor_fn);
	return 0;
}

void cifsd_file_cache_destroy(void)
{
	cifsd_cache_destroy(&file_cache);
}
