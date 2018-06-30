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

#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/hashtable.h>
#include <net/net_namespace.h>
#include <net/genetlink.h>

#include "transport_ipc.h"
#include "buffer_pool.h"
#include "cifsd_server.h"  /* FIXME */

#define IPC_WAIT_TIMEOUT	(2 * HZ)

#define IPC_MSG_HASH_BITS	3
static DEFINE_HASHTABLE(ipc_msg_table, IPC_MSG_HASH_BITS);

static DECLARE_RWSEM(ipc_msg_table_lock);
static unsigned long long ipc_msg_handle;

static unsigned int cifsd_tools_pid;

#define CIFSD_IPC_MSG_HANDLE(m)						\
	(*(unsigned long long *)m)

#define CIFSD_INVALID_IPC_VERSION(m)					\
	({								\
		int ret = 0;						\
									\
		if (m->genlhdr->version != CIFSD_GENL_VERSION) {	\
			pr_err("IPC protocol version mismatch: %d\n",	\
				m->genlhdr->version);			\
			ret = 1;					\
		}							\
		ret;							\
	})

struct ipc_msg_table_entry {
	unsigned long long	handle;
	struct hlist_node	hlist;
	wait_queue_head_t	wait;

	struct cifsd_ipc_msg	*msg;
};

static struct cifsd_ipc_msg *ipc_msg_alloc(size_t sz)
{
	struct cifsd_ipc_msg *msg;
	size_t msg_sz = sz + sizeof(struct cifsd_ipc_msg);

	msg = cifsd_alloc(msg_sz);
	if (msg)
		msg->sz = sz;
	return msg;
}

void cifsd_ipc_msg_free(struct cifsd_ipc_msg *msg)
{
	cifsd_free(msg);
}

static int handle_response(void *payload, size_t sz)
{
	unsigned long long handle = CIFSD_IPC_MSG_HANDLE(payload);
	struct ipc_msg_table_entry *entry;
	int ret = -EINVAL;

	down_read(&ipc_msg_table_lock);
	hash_for_each_possible(ipc_msg_table, entry, hlist, handle) {
		if (handle != entry->handle)
			continue;

		entry->msg = ipc_msg_alloc(sz);
		if (!entry->msg) {
			ret = -ENOMEM;
			break;
		}

		memcpy(entry->msg, payload, sz);
		wake_up_interruptible(&entry->wait);
		ret = 0;
		break;
	}
	up_read(&ipc_msg_table_lock);

	return ret;
}

static int handle_startup_event(struct sk_buff *skb, struct genl_info *info)
{
	if (CIFSD_INVALID_IPC_VERSION(info))
		return -EINVAL;

	if (!info->attrs[CIFSD_EVENT_STARTING_UP])
		 return -EINVAL;

	if (cifsd_tools_pid)
		return -EINVAL;

	cifsd_tools_pid = info->snd_portid;
	/* start up */
	return 0;
}

static int handle_shutdown_event(struct sk_buff *skb, struct genl_info *info)
{
	if (CIFSD_INVALID_IPC_VERSION(info))
		return -EINVAL;

	if (!info->attrs[CIFSD_EVENT_STARTING_UP])
		 return -EINVAL;

	if (cifsd_tools_pid && cifsd_tools_pid != info->snd_portid) {
		pr_err("A shutdown request from unknown PID %d, ignore.\n",
			info->snd_portid);
		return -EINVAL;
	}

	/* shutdown */
	return 0;
}

static int handle_unsupported_event(struct sk_buff *skb,
				    struct genl_info *info)
{
	pr_err("Unknown IPC event: %d, ignore.\n", info->genlhdr->cmd);
	return -EINVAL;
}

static int handle_generic_event(struct sk_buff *skb, struct genl_info *info)
{
	void *payload;
	int sz;

	if (info->genlhdr->cmd >= CIFSD_EVENT_MAX) {
		WARN_ON(1);
		return -EINVAL;
	}

	if (CIFSD_INVALID_IPC_VERSION(info))
		return -EINVAL;

	if (!info->attrs[info->genlhdr->cmd])
		return -EINVAL;

	payload = nla_data(info->attrs[info->genlhdr->cmd]);
	sz = nla_len(info->attrs[info->genlhdr->cmd]);
	return handle_response(payload, sz);
}

static unsigned long long next_ipc_msg_handle(void)
{
	unsigned long long ret;

	down_write(&ipc_msg_table_lock);
	do {
		ret = ipc_msg_handle++;
	} while (ret == 0);
	up_write(&ipc_msg_table_lock);

	return ret;
}

static const struct nla_policy cifsd_nl_policy[CIFSD_EVENT_MAX] = {
	[CIFSD_EVENT_STARTING_UP] = {
		.len = sizeof(struct cifsd_startup_shutdown),
	},

	[CIFSD_EVENT_SHUTTING_DOWN] = {
		.len = sizeof(struct cifsd_startup_shutdown),
	},

	[CIFSD_EVENT_LOGIN_REQUEST] = {
		.len = sizeof(struct cifsd_login_request),
	},

	[CIFSD_EVENT_LOGIN_RESPONSE] = {
		.len = sizeof(struct cifsd_login_response),
	},

	[CIFSD_EVENT_TREE_CONNECT_REQUEST] = {
		.len = sizeof(struct cifsd_tree_connect_request),
	},

	[CIFSD_EVENT_TREE_CONNECT_RESPONSE] = {
		.len = sizeof(struct cifsd_tree_connect_response),
	},

	[CIFSD_EVENT_TREE_DISCONNECT_REQUEST] = {
		.len = sizeof(struct cifsd_tree_disconnect_request),
	},

	[CIFSD_EVENT_LOGOUT_REQUEST] = {
		.len = sizeof(struct cifsd_logout_request),
	},
};

static const struct genl_ops cifsd_genl_ops[] = {
	{
		.cmd	= CIFSD_EVENT_STARTING_UP,
		.doit	= handle_startup_event,
		.policy = cifsd_nl_policy,
	},
	{
		.cmd	= CIFSD_EVENT_SHUTTING_DOWN,
		.doit	= handle_shutdown_event,
		.policy = cifsd_nl_policy,
	},
	{
		.cmd	= CIFSD_EVENT_LOGIN_REQUEST,
		.doit	= handle_unsupported_event,
		.policy = cifsd_nl_policy,
	},
	{
		.cmd	= CIFSD_EVENT_LOGIN_RESPONSE,
		.doit	= handle_generic_event,
		.policy = cifsd_nl_policy,
	},
	{
		.cmd	= CIFSD_EVENT_TREE_CONNECT_REQUEST,
		.doit	= handle_unsupported_event,
		.policy = cifsd_nl_policy,
	},
	{
		.cmd	= CIFSD_EVENT_TREE_CONNECT_RESPONSE,
		.doit	= handle_generic_event,
		.policy = cifsd_nl_policy,
	},
	{
		.cmd	= CIFSD_EVENT_TREE_DISCONNECT_REQUEST,
		.doit	= handle_unsupported_event,
		.policy = cifsd_nl_policy,
	},
	{
		.cmd	= CIFSD_EVENT_LOGOUT_REQUEST,
		.doit	= handle_unsupported_event,
		.policy = cifsd_nl_policy,
	},
};

struct genl_family cifsd_genl_family = {
	.name		= CIFSD_GENL_NAME,
	.version	= CIFSD_GENL_VERSION,
	.hdrsize	= 0,
	.maxattr	= CIFSD_EVENT_MAX,
	.netnsok	= true,
	.module		= THIS_MODULE,
	.ops		= cifsd_genl_ops,
	.n_ops		= ARRAY_SIZE(cifsd_genl_ops),
};

static int ipc_msg_send(struct cifsd_ipc_msg *msg)
{
	struct genlmsghdr *nlh;
	struct sk_buff *skb;
	int ret = -EINVAL;

	if (!cifsd_tools_pid)
		return ret;

	skb = genlmsg_new(msg->sz, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	nlh = genlmsg_put(skb, 0, 0, &cifsd_genl_family, 0, msg->type);
	if (!nlh)
		goto out;

	ret = nla_put(skb, msg->type, msg->sz, CIFSD_IPC_MSG_PAYLOAD(msg));
	if (ret) {
		genlmsg_cancel(skb, nlh);
		goto out;
	}

	genlmsg_end(skb, nlh);
	ret = genlmsg_unicast(&init_net, skb, cifsd_tools_pid);
	return ret;

out:
	nlmsg_free(skb);
	return ret;
}

static struct cifsd_ipc_msg *ipc_msg_send_request(struct cifsd_ipc_msg *msg,
						  unsigned long long handle)
{
	struct ipc_msg_table_entry entry;
	int ret;

	entry.msg = NULL;
	init_waitqueue_head(&entry.wait);

	down_write(&ipc_msg_table_lock);
	entry.handle = handle;
	hash_add(ipc_msg_table, &entry.hlist, entry.handle);
	up_write(&ipc_msg_table_lock);

	ret = ipc_msg_send(msg);
	if (ret)
		goto out;

	ret = wait_event_interruptible_timeout(entry.wait,
					       entry.msg != NULL,
					       IPC_WAIT_TIMEOUT);
out:
	down_write(&ipc_msg_table_lock);
	hash_del(&entry.hlist);
	up_write(&ipc_msg_table_lock);

	return entry.msg;
}

struct cifsd_ipc_msg *cifsd_ipc_login_request(const char *account)
{
	struct cifsd_ipc_msg *req_msg, *resp_msg;
	struct cifsd_login_request *req;

	req_msg = ipc_msg_alloc(sizeof(struct cifsd_login_request));
	if (!req_msg)
		return NULL;

	req_msg->type = CIFSD_EVENT_LOGIN_REQUEST;
	req = CIFSD_IPC_MSG_PAYLOAD(req_msg);
	req->handle = next_ipc_msg_handle();
	strncpy(req->account, account, sizeof(req->account));

	resp_msg = ipc_msg_send_request(req_msg, req->handle);
	cifsd_ipc_msg_free(req_msg);
	return resp_msg;
}

struct cifsd_ipc_msg *cifsd_ipc_tree_connect_request(void)
{
	struct cifsd_ipc_msg *req_msg, *resp_msg;
	struct cifsd_tree_connect_request *req;

	req_msg = ipc_msg_alloc(sizeof(struct cifsd_tree_connect_request));
	if (!req_msg)
		return NULL;

	req_msg->type = CIFSD_EVENT_TREE_CONNECT_REQUEST;
	req = CIFSD_IPC_MSG_PAYLOAD(req_msg);
	req->handle = next_ipc_msg_handle();

	resp_msg = ipc_msg_send_request(req_msg, req->handle);
	cifsd_ipc_msg_free(req_msg);
	return resp_msg;
}

int cifsd_ipc_tree_disconnect_request(unsigned long long connection_id)
{
	struct cifsd_ipc_msg *msg;
	struct cifsd_tree_disconnect_request *req;
	int ret;

	msg = ipc_msg_alloc(sizeof(struct cifsd_tree_disconnect_request));
	if (!msg)
		return -ENOMEM;

	msg->type = CIFSD_EVENT_TREE_DISCONNECT_REQUEST;
	req = CIFSD_IPC_MSG_PAYLOAD(msg);
	req->connection_id = connection_id;

	ret = ipc_msg_send(msg);
	cifsd_ipc_msg_free(msg);
	return ret;
}

int cifsd_ipc_logout_request(const char *account)
{
	struct cifsd_ipc_msg *msg;
	struct cifsd_logout_request *req;
	int ret;

	msg = ipc_msg_alloc(sizeof(struct cifsd_logout_request));
	if (!msg)
		return -ENOMEM;

	msg->type = CIFSD_EVENT_LOGOUT_REQUEST;
	req = CIFSD_IPC_MSG_PAYLOAD(msg);
	strcpy(req->account, account);

	ret = ipc_msg_send(msg);
	cifsd_ipc_msg_free(msg);
	return ret;
}

void cifsd_ipc_release(void)
{
	genl_unregister_family(&cifsd_genl_family);
}

int cifsd_ipc_init(void)
{
	int ret = genl_register_family(&cifsd_genl_family);

	if (ret) {
		pr_err("Failed to register CIFSD netlink interface %d\n", ret);
		return ret;
	}
	return 0;
}
