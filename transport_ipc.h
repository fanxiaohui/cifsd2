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

#ifndef __CIFSD_TRANSPORT_IPC_H__
#define __CIFSD_TRANSPORT_IPC_H__

#include <linux/wait.h>
#include "cifsd_server.h"  /* FIXME */


struct cifsd_login_response *
cifsd_ipc_login_request(const char *account);

struct cifsd_session;
struct cifsd_share_config;
struct cifsd_tree_connect;

struct cifsd_tree_connect_response *
cifsd_ipc_tree_connect_request(struct cifsd_session *sess,
			       struct cifsd_share_config *share,
			       struct cifsd_tree_connect *tree_conn,
			       struct sockaddr *peer_addr);

int cifsd_ipc_tree_disconnect_request(unsigned long long session_id,
				      unsigned long long connect_id);
int cifsd_ipc_logout_request(const char *account);
struct cifsd_heartbeat *cifsd_ipc_heartbeat_request(void);

struct cifsd_share_config_response *
cifsd_ipc_share_config_request(const char *name);

int cifsd_ipc_session_rpc_alloc(struct cifsd_session *sess);
void cifsd_ipc_session_rpc_free(struct cifsd_session *sess, int id);
void cifsd_ipc_session_rpc_list_clear(struct cifsd_session *sess);

void cifsd_ipc_release(void);
int cifsd_ipc_init(void);

#endif /* __CIFSD_TRANSPORT_IPC_H__ */
