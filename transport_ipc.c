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
#include <net/netlink.h>
#include <net/net_namespace.h>

#include "transport_ipc.h"
#include "buffer_pool.h"
#include "cifsd_server.h"  /* FIXME */

#define IPC_WAIT_TIMEOUT	(2 * HZ)

#define IPC_MSG_HASH_BITS	3
static DEFINE_HASHTABLE(ipc_msg_table, IPC_MSG_HASH_BITS);

static DECLARE_RWSEM(ipc_msg_table_lock);
static unsigned long long ipc_msg_handle;

static struct sock *nlsk;
static pid_t cifsd_tools_pid;

#define VALID_IPC_MSG(m,t) 						\
	({								\
		int ret = 1;						\
		if (nlmsg_len(m) != sizeof(t)) {			\
			pr_err("Bad message: %d\n", m->nlmsg_type);	\
			ret = 0;					\
		}							\
		ret;							\
	})

#define CIFSD_IPC_MSG_HANDLE(m)						\
	(*(unsigned long long *)m)

struct ipc_msg_table_entry {
	unsigned long long	handle;
	struct hlist_node	hlist;
	wait_queue_head_t	wait;

	struct cifsd_ipc_msg	*msg;
};

static struct cifsd_ipc_msg *ipc_msg_alloc(size_t sz)
{
	struct cifsd_ipc_msg *msg;
	size_t msg_sz = sz + sizeof(struct cifsd_ipc_msg) - sizeof(void *);

	msg = cifsd_alloc(msg_sz);
	if (msg) {
		msg->destination = -1;
		msg->sz = sz;
	}
	return msg;
}

void cifsd_ipc_msg_free(struct cifsd_ipc_msg *msg)
{
	cifsd_free(msg);
}

static void handle_response(struct nlmsghdr *nlh)
{
	unsigned long long handle = CIFSD_IPC_MSG_HANDLE(nlmsg_data(nlh));
	struct ipc_msg_table_entry *entry;

	down_read(&ipc_msg_table_lock);
	hash_for_each_possible(ipc_msg_table, entry, hlist, handle) {
		if (handle != entry->handle)
			continue;

		entry->msg = ipc_msg_alloc(nlmsg_len(nlh));
		if (!entry->msg)
			break;

		memcpy(entry->msg, nlmsg_data(nlh), nlmsg_len(nlh));
		wake_up_interruptible(&entry->wait);
	}
	up_read(&ipc_msg_table_lock);
}

static int ipc_msg_send(struct cifsd_ipc_msg *msg)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	int ret = -EINVAL;

	skb = nlmsg_new(msg->sz, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	nlh = nlmsg_put(skb, cifsd_tools_pid, 0, msg->type, msg->sz, 0);
	if (!nlh)
		goto out;

	ret = nla_put(skb, NLA_UNSPEC, msg->sz, CIFSD_IPC_MSG_PAYLOAD(msg));
	if (ret) {
		nlmsg_cancel(skb, nlh);
		goto out;
	}

	nlmsg_end(skb, nlh);
	ret = nlmsg_unicast(nlsk, skb, cifsd_tools_pid);
out:
	nlmsg_free(skb);
	return ret;
}

static struct cifsd_ipc_msg *ipc_msg_send_request(struct cifsd_ipc_msg *msg)
{
	struct ipc_msg_table_entry entry;
	int ret;

	entry.msg = NULL;
	init_waitqueue_head(&entry.wait);

	down_write(&ipc_msg_table_lock);
	entry.handle = CIFSD_IPC_MSG_HANDLE(CIFSD_IPC_MSG_PAYLOAD(msg));
	WARN_ON(!entry.handle);
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

static void handle_startup(struct nlmsghdr *nlh)
{
	struct cifsd_startup_shutdown *req = nlmsg_data(nlh);

	cifsd_tools_pid = req->pid;
	if (strcmp(req->version, CIFSD_VERSION)) {
		pr_err("Version mismatch: server %s, client %s, ignore.\n",
			CIFSD_VERSION, req->version);
		cifsd_tools_pid = 0;
	}
}

static void handle_shutdown(struct nlmsghdr *nlh)
{
	struct cifsd_startup_shutdown *req = nlmsg_data(nlh);

	if (cifsd_tools_pid && cifsd_tools_pid != req->pid) {
		pr_err("A shutdown request from unknown PID %d, ignore.\n",
			req->pid);
		return;
	}

	/* shutdown */
}

static void cifsd_ipc_consume_message(struct nlmsghdr *nlh)
{
	switch (nlh->nlmsg_type) {
	case CIFSD_EVENT_TREE_CONNECT_RESPONSE:
		if (!VALID_IPC_MSG(nlh, struct cifsd_tree_connect_response))
			return;
		handle_response(nlh);
		break;

	case CIFSD_EVENT_LOGIN_RESPONSE:
		if (!VALID_IPC_MSG(nlh, struct cifsd_login_response))
			return;
		handle_response(nlh);
		break;

	case CIFSD_EVENT_STARTING_UP:
		handle_startup(nlh);
		break;

	case CIFSD_EVENT_SHUTTING_DOWN:
		handle_shutdown(nlh);
		break;

	default:
		pr_err("Uknown event type %d, ignore.\n", nlh->nlmsg_type);
		break;
	}
}

static void cifsd_ipc_receiving_loop(struct sk_buff *skb)
{
	if (skb->len >= NLMSG_HDRLEN) {
		int payload_sz;
		struct nlmsghdr *nlh;

		nlh = nlmsg_hdr(skb);
		payload_sz = nlmsg_len(nlh);
		if (skb->len < payload_sz)
			goto out;

		cifsd_ipc_consume_message(nlh);
	}
out:
	consume_skb(skb);
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

struct cifsd_ipc_msg *cifsd_ipc_login_request(void)
{
	struct cifsd_ipc_msg *req_msg, *resp_msg;
	struct cifsd_login_request *req;

	req_msg = ipc_msg_alloc(sizeof(struct cifsd_login_request));
	if (!req_msg)
		return NULL;

	req = CIFSD_IPC_MSG_PAYLOAD(req_msg);
	req->handle = next_ipc_msg_handle();

	resp_msg = ipc_msg_send_request(req_msg);
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

	req = CIFSD_IPC_MSG_PAYLOAD(req_msg);
	req->handle = next_ipc_msg_handle();

	resp_msg = ipc_msg_send_request(req_msg);
	cifsd_ipc_msg_free(req_msg);
	return resp_msg;
}

int cifsd_ipc_tree_disconnect_request(unsigned long long connect_id)
{
	struct cifsd_ipc_msg *msg;
	struct cifsd_tree_disconnect_request *req;
	int ret;

	msg = ipc_msg_alloc(sizeof(struct cifsd_tree_disconnect_request));
	if (!msg)
		return -ENOMEM;

	req = CIFSD_IPC_MSG_PAYLOAD(msg);
	req->connect_id = connect_id;

	ret = ipc_msg_send(msg);
	cifsd_ipc_msg_free(msg);
	return ret;
}

int cifsd_ipc_logout_request(unsigned long long account_id)
{
	struct cifsd_ipc_msg *msg;
	struct cifsd_logout_request *req;
	int ret;

	msg = ipc_msg_alloc(sizeof(struct cifsd_logout_request));
	if (!msg)
		return -ENOMEM;

	req = CIFSD_IPC_MSG_PAYLOAD(msg);
	req->account_id = account_id;

	ret = ipc_msg_send(msg);
	cifsd_ipc_msg_free(msg);
	return ret;
}

void cifsd_ipc_release(void)
{
	netlink_kernel_release(nlsk);
}

int cifsd_ipc_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input  = cifsd_ipc_receiving_loop,
	};

	nlsk = netlink_kernel_create(&init_net, CIFSD_TOOLS_NETLINK, &cfg);
	if (!nlsk) {
		pr_err("failed to create cifsd netlink socket.\n");
		return -ENOMEM;
	}
	return 0;
}