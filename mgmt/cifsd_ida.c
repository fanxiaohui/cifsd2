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

#include "cifsd_ida.h"

struct cifsd_ida *cifsd_ida_alloc(void)
{
	struct cifsd_ida *ida;
	
	ida = kmalloc(sizeof(struct cifsd_ida), GFP_KERNEL);
	if (!ida)
		return NULL;

	ida_init(&ida->map);
	return ida;
}

void cifsd_ida_free(struct cifsd_ida *ida)
{
	ida_destroy(&ida->map);
	kfree(ida);
}

static inline int __acquire_id(struct cifsd_ida *ida, int from, int to)
{
	return ida_simple_get(&ida->map, from, to, GFP_KERNEL);
}

int cifds_acquire_smb1_tid(struct cifsd_ida *ida)
{
	return __acquire_id(ida, 0, 0xFFFF);
}

int cifds_acquire_smb2_tid(struct cifsd_ida *ida)
{
	return __acquire_id(ida, 0xFFFF + 1, 0);
}

int cifds_acquire_smb1_uid(struct cifsd_ida *ida)
{
	return __acquire_id(ida, 1, 0xFFFE);
}

int cifds_acquire_smb2_uid(struct cifsd_ida *ida)
{
	return __acquire_id(ida, 0xFFFF + 1, 0);
}

int cifds_acquire_id(struct cifsd_ida *ida)
{
	return __acquire_id(ida, 0, 0);
}

void cifds_release_id(struct cifsd_ida *ida, int id)
{
	ida_simple_remove(&ida->map, id);
}
