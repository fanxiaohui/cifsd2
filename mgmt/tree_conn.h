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

#ifndef __TREE_CONNECT_MANAGEMENT_H__
#define __TREE_CONNECT_MANAGEMENT_H__

#include <linux/hashtable.h>

struct cifsd_share_config;
struct cifsd_user;

struct cifsd_tree_connect {
	unsigned int			id;

	unsigned int			flags;
	struct cifsd_share_config	*share_conf;
	struct cifsd_user		*user;

	struct list_head		list;
};

struct cifsd_sess;

enum CIFSD_TREE_CONN_STATUS cifsd_tree_conn_connect(struct cifsd_sess *sess,
						    char *share_name,
						    int protocol);

int cifsd_tree_conn_disconnect(struct cifsd_tree_connect *tree_conn);

struct cifsd_tree_connect *cifsd_tree_conn_lookup(struct cifsd_sess *sess,
						  unsigned int id);

#endif /* __TREE_CONNECT_MANAGEMENT_H__ */
