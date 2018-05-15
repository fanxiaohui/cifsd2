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

#include "cache.h"
#include "file_cache.h"
#include "inode_cache.h"
#include "buffer_pool.h"

#include "export.h"
#include "oplock.h"

static struct cifsd_cache file_cache;

static void cifsd_file_free(struct work_struct *work)
{
	struct cifsd_file_ *filp = container_of(work,
					       struct cifsd_file_,
					       __free_work);
	struct file *vfs_filp;

	if (filp->symlink_filp)
		vfs_filp = filp->symlink_filp;

	kfree(filp->stream.name);
	kfree(filp);
	filp_close(vfs_filp, (struct files_struct *)vfs_filp);
}

static void __cache_destructor_fn(void *val)
{
	struct cifsd_file_ *filp = (struct cifsd_file_ *)val;

	schedule_work(&filp->__free_work);
}

static void __hash_destructor_fn(struct hlist_node *node)
{
	struct cifsd_file_ *filp = container_of(node,
					       struct cifsd_file_,
					       lookup_hash);
	cifsd_file_put(filp);
}

static void *cifsd_file_get(struct cifsd_file_ *filp)
{
	if (!atomic_inc_not_zero(&filp->__refcount))
		return NULL;
        return filp;
}

void cifsd_file_put(struct cifsd_file_ *filp)
{
	if (!atomic_dec_and_test(&filp->__refcount))
		return;
	__cache_destructor_fn(filp);
}

static void *__cache_lookup_fn(void *val)
{
	struct cifsd_file_ *filp = (struct cifsd_file_ *)val;

	if (!filp->f_filp)
		return NULL;
	return cifsd_file_get(filp);
}

static int __hash_lookup_fn(struct hlist_node *node, unsigned long id)
{
	return 0;
}

int cifsd_add_to_local_file_cache(struct cifsd_file_ *filp)
{
	return 0;
}

int cifsd_add_to_global_file_cache(struct cifsd_file_ *filp)
{
	return 0;
}

struct cifsd_file_ *cifsd_file_cache_lookup(struct cifsd_sess *sess,
					    unsigned long key)
{
	return NULL;
}

struct cifsd_file_ *cifsd_file_open(struct file *file)
{
	struct cifsd_file_ *filp;
	struct cifsd_inode *inode;

	filp = cifsd_alloc_file_struct();
	if (!filp)
		return NULL;

	atomic_set(&filp->__refcount, 1);
	INIT_WORK(&filp->__free_work, cifsd_file_free);

	inode = cifsd_inode_open(filp);
	if (!inode) {
		WARN_ON(1);
		cifsd_free_file_struct(filp);
		return NULL;
	}

	filp->f_filp = file;
	filp->f_inode = inode;
	return filp;
}

void cifsd_file_close(struct cifsd_file_ *filp)
{
	//close_id_del_oplock(filp);

	cifsd_inode_close(filp);
	cifsd_file_put(filp);
}

int cifsd_local_file_cache_init(struct cifsd_sess *sess)
{
	int ret = cifsd_cache_init(&sess->file_cache.cache,
				   __cache_lookup_fn,
				   __cache_destructor_fn);
	if (ret)
		return ret;

	return cifsd_hash_init(&sess->file_cache.hash,
				7,
				CIFSD_FILE_UID_SIZE,
				__hash_lookup_fn,
				__hash_destructor_fn);
}

void cifsd_local_file_cache_destroy(struct cifsd_sess *sess)
{
	cifsd_cache_destroy(&sess->file_cache.cache);
	cifsd_hash_destroy(&sess->file_cache.hash);
}

int cifsd_global_file_cache_init(void)
{
	return cifsd_cache_init(&file_cache,
				__cache_lookup_fn,
				__cache_destructor_fn);
}

void cifsd_global_file_cache_destroy(void)
{
	cifsd_cache_destroy(&file_cache);
}
