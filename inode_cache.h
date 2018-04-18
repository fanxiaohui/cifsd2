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

#include "cache.h"

struct cifsd_inode {
	struct inode		*inode;
	spinlock_t		i_lock;

	atomic_t		i_count;
	atomic_t		i_op_count;
	unsigned int		i_flags;
	struct list_head	i_fp_list;
	char			*stream_name;
};

#endif /* __CIFSD_INODE_CACHE_H__ */
