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

#include <linux/list.h>
#include <linux/slab.h>

#include "tree_conn.h"
#include "user.h"
#include "share.h"
#include "../buffer_pool.h"
#include "../transport_ipc.h"
#include "../transport_tcp.h"

#include "../export.h" /* FIXME */
#include "../cifsd_server.h" /* FIXME */

int cifsd_tree_conn_connect(struct cifsd_sess *sess,
			    char *share_name,
			    int protocol)
{
	struct cifsd_tree_connect_response *resp = NULL;
	struct cifsd_share_config *sc = NULL;
	struct cifsd_tree_connect *tree_conn = NULL;
	struct sockaddr *peer_addr;
	int ret;

	sc = cifsd_share_config_get(share_name);
	if (!sc)
		return -EINVAL;

	tree_conn = cifsd_alloc(sizeof(struct cifsd_tree_connect));
	if (!tree_conn) {
		ret = -ENOMEM;
		goto out_error;
	}

	peer_addr = CIFSD_TCP_PEER_SOCKADDR(sess->conn);
	resp = cifsd_ipc_tree_connect_request(protocol,
					      sess->user->name,
					      sc->name,
					      peer_addr);
	if (!resp) {
		ret = -EINVAL;
		goto out_error;
	}

	ret = resp->status;

	if (ret == CIFSD_TREE_CONN_STATUS_NOMEM)
		goto out_error;

	if (ret == CIFSD_TREE_CONN_STATUS_NO_SHARE)
		goto out_error;

	if (ret == CIFSD_TREE_CONN_STATUS_TOO_MANY_CONNS)
		goto out_error;

	if (ret == CIFSD_TREE_CONN_STATUS_HOST_DENIED)
		goto out_error;

	if (ret == CIFSD_TREE_CONN_STATUS_NO_USER)
		goto out_error;

	if (ret == CIFSD_TREE_CONN_STATUS_INVALID_USER)
		goto out_error;

	if (ret == CIFSD_TREE_CONN_STATUS_CONN_EXIST)
		goto out_error;

	if (ret == CIFSD_TREE_CONN_STATUS_ERROR)
		goto out_error;

	tree_conn->flags = resp->connection_flags;
	tree_conn->id = resp->connection_id;
	tree_conn->user = sess->user;
	tree_conn->share_conf = sc;

	list_add(&tree_conn->list, &sess->tcon_list);

	cifsd_free(resp);
	return ret;

out_error:
	if (sc)
		cifsd_share_config_put(sc);
	cifsd_free(resp);
	return ret;
}

int cifsd_tree_conn_disconnect(struct cifsd_tree_connect *tree_conn)
{
	int ret;
	
	ret = cifsd_ipc_tree_disconnect_request(tree_conn->id);
	list_del(&tree_conn->list);
	cifsd_share_config_put(tree_conn->share_conf);
	cifsd_free(tree_conn);
	return ret;
}
