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

#ifndef __CIFSD_INODE_CACHE_H__
#define __CIFSD_INODE_CACHE_H__

#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/rcupdate.h>

#include "cache.h"

#define CIFSD_INODE_UNLINK_ON_CLOSE	(1 << 0)
#define CIFSD_FILE_UNLINK_ON_CLOSE	(1 << 1)
#define CIFSD_INODE_UNLINK_ON_CLOSE_STREAM	(1 << 2)

struct cifsd_inode_ {
	struct inode		*i_inode;
	spinlock_t		i_lock;

	atomic_t		i_op_count;
	unsigned int		i_flags;
	struct list_head	i_fp_list;
	struct list_head	i_op_list;
	char			*i_stream_name;

	atomic_t		__refcount;
	struct rcu_head		__free_work;
};

#define CIFSD_INODE_LOOKUP_KEY(i)	((unsigned long)(i)->i_inode)

struct cifsd_inode_ *cifsd_inode_cache_lookup(unsigned long key);

void cifsd_inode_put(struct cifsd_inode_ *ci);

struct cifsd_file_;
struct cifsd_inode_ *cifsd_inode_open(struct cifsd_file_ *filp);
void cifsd_inode_close(struct cifsd_file_ *filp);

void cifsd_inode_set_unlinnk_on_close(struct cifsd_file_ *filp);
bool cifsd_inode_unlink_on_close(struct cifsd_file_ *filp);

int cifsd_inode_cache_init(void);
void cifsd_inode_cache_destroy(void);

#endif /* __CIFSD_INODE_CACHE_H__ */
