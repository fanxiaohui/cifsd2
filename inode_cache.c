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

#include "file_cache.h"
#include "inode_cache.h"

static struct cifsd_cache inode_cache;

static void __cifsd_inode_free(struct rcu_head *rcu_head)
{
	struct cifsd_inode_ *ci = container_of(rcu_head,
					       struct cifsd_inode_,
					       __free_work);

	kfree(ci->i_stream_name);
	kfree(ci);
}

static void __destructor_fn(void *val)
{
	struct cifsd_inode_ *ci = (struct cifsd_inode_ *)val;

	call_rcu(&ci->__free_work, __cifsd_inode_free);
}

static void *__cifsd_inode_get(struct cifsd_inode_ *ci)
{
	if (!atomic_inc_not_zero(&ci->__refcount))
		return NULL;
        return ci;
}

void cifsd_inode_put(struct cifsd_inode_ *ci)
{
	if (!atomic_dec_and_test(&ci->__refcount))
		return;

	cifsd_cache_remove(&inode_cache, CIFSD_INODE_LOOKUP_KEY(ci));
	__destructor_fn(ci);
}

static void *__lookup_fn(void *val)
{
	struct cifsd_inode_ *ci = (struct cifsd_inode_ *)val;

	if (!ci->i_inode)
		return NULL;
	return __cifsd_inode_get(ci);
}

struct cifsd_inode_ *cifsd_inode_cache_lookup(unsigned long key)
{
	return cifsd_cache_lookup(&inode_cache, key);
}

static int __cifsd_inode_open(struct cifsd_inode_ *ci,
			      struct cifsd_file_ *filp)
{
	if (!__cifsd_inode_get(ci))
		return -EINVAL;

	spin_lock(&ci->i_lock);
	list_add(&filp->f_ci_list, &ci->i_fp_list);
	if (!ci->i_inode)
		ci->i_inode = CIFSD_FILE_VFS_INODE(filp);
	spin_unlock(&ci->i_lock);

	if (!ci->i_stream_name && filp->is_stream) {
		char *str = kstrdup(filp->stream.name, GFP_KERNEL);

		if (!str) {
			cifsd_inode_put(ci);
			return -EINVAL;
		}
		spin_lock(&ci->i_lock);
		ci->i_stream_name = str;
		spin_unlock(&ci->i_lock);
	}
	return 0;
}

struct cifsd_inode_ *cifsd_inode_open(struct cifsd_file_ *filp)
{
	struct cifsd_inode_ *ci;
	unsigned long key = (unsigned long)CIFSD_FILE_VFS_INODE(filp);

	ci = cifsd_cache_lookup(&inode_cache, key);
	if (ci) {
		if (__cifsd_inode_open(ci, filp))
			return NULL;
		return ci;
	}

	ci = kzalloc(sizeof(struct cifsd_inode_), GFP_KERNEL);
	if (!ci)
		return NULL;

	spin_lock_init(&ci->i_lock);
	atomic_set(&ci->__refcount, 1);
	atomic_set(&ci->i_op_count, 0);
	INIT_LIST_HEAD(&ci->i_fp_list);
	INIT_LIST_HEAD(&ci->i_op_list);

	if (cifsd_cache_insert(&inode_cache, key, ci)) {
		kfree(ci);
		ci = cifsd_cache_lookup(&inode_cache, key);
	}

	if (!ci) {
		WARN_ON(1);
		return NULL;
	}

	__cifsd_inode_open(ci, filp);
	return ci;
}

void cifsd_inode_close(struct cifsd_file_ *filp)
{
	spin_lock(&CIFSD_FILE_INODE(filp)->i_lock);
	list_del(&filp->f_ci_list);
	spin_unlock(&CIFSD_FILE_INODE(filp)->i_lock);

	cifsd_inode_put(CIFSD_FILE_INODE(filp));
}

void cifsd_inode_set_unlinnk_on_close(struct cifsd_file_ *filp)
{
	struct cifsd_inode_ *ci = CIFSD_FILE_INODE(filp);

	if (atomic_read(&ci->__refcount) == 1)
		ci->i_flags |= CIFSD_INODE_UNLINK_ON_CLOSE;
}

bool cifsd_inode_unlink_on_close(struct cifsd_file_ *filp)
{
	struct cifsd_inode_ *ci = CIFSD_FILE_INODE(filp);

	return ci->i_flags & CIFSD_INODE_UNLINK_ON_CLOSE ||
		ci->i_flags & CIFSD_FILE_UNLINK_ON_CLOSE;
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
