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

#ifndef __CIFDS_IDA_MANAGEMENT_H__
#define __CIFDS_IDA_MANAGEMENT_H__

#include <linux/slab.h>
#include <linux/idr.h>

struct cifsd_ida {
	struct ida	map;
	int		start;
};

static struct cifsd_ida *cifsd_ida_alloc(int start)
{
	struct cifsd_ida *ida;
	
	ida = kmalloc(sizeof(struct cifsd_ida), GFP_KERNEL);
	if (!ida)
		return NULL;

	ida->start = start;
	ida_init(&ida->map);
	return ida;
}

static void cifsd_ida_free(struct cifsd_ida *ida)
{
	ida_destroy(&ida->map);
	kfree(ida);
}

static int cifds_acquire_next_smb1_id(struct cifsd_ida *ida)
{
	return ida_simple_get(&ida->map, ida->start, 0xFFFF, GFP_KERNEL);
}

static int cifds_acquire_next_smb2_id(struct cifsd_ida *ida)
{
	return ida_simple_get(&ida->map, 0xFFFF + 1, 0, GFP_KERNEL);
}

static void cifds_release_id(struct cifsd_ida *ida, int id)
{
	ida_simple_remove(&ida->map, id);
}
#endif /* __CIFSD_IDA_MANAGEMENT_H__ */
