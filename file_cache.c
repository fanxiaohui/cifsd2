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

#include "oplock.h"

static struct cifsd_cache file_cache;

static void cifsd_file_free(struct work_struct *work)
{
	struct cifsd_file *filp = container_of(work,
					       struct cifsd_file,
					       __free_work);

	kfree(filp->stream.name);
	kfree(filp);
}

static void __destructor_fn(void *val)
{
	struct cifsd_file *filp = (struct cifsd_file *)val;

	schedule_work(&filp->__free_work);
}

static void *cifsd_file_get(struct cifsd_file *filp)
{
	if (!atomic_inc_not_zero(&filp->__refcount))
		return NULL;
        return filp;
}

void cifsd_file_put(struct cifsd_file *filp)
{
	if (!atomic_dec_and_test(&filp->__refcount))
		return;
	__destructor_fn(filp);
}

static void *__lookup_fn(void *val)
{
	struct cifsd_file *filp = (struct cifsd_file *)val;

	if (!filp->f_filp)
		return NULL;
	return cifsd_file_get(filp);
}

int cifsd_file_cache_insert(struct cifsd_file *filp)
{
	return 0;
}

struct cifsd_file *cifsd_file_cache_lookup(unsigned long key)
{
	return NULL;
}

struct cifsd_file *cifsd_file_open(struct file *file)
{
	struct cifsd_file *filp;
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

void cifsd_file_close(struct cifsd_file *filp)
{
	struct file *vfs_filp;

	if (filp->symlink_filp)
		vfs_filp = filp->symlink_filp;

	close_id_del_oplock(filp);

	cifsd_inode_close(filp);
	cifsd_file_put(filp);
	filp_close(vfs_filp, (struct files_struct *)vfs_filp);
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
