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

#include "transport_ipc.h"
#include "cifsd_server.h"  /* FIXME */

#define IPC_MSG_HASH_BITS		3
static DEFINE_HASHTABLE(ipc_msg_table, IPC_MSG_HASH_BITS);
static DECLARE_RWSEM(ipc_msg_table_lock);
static atomic64_t ipc_msg_handle;

static struct sock *nlsk;
static pid_t cifsd_tools_pid;

#define VALID_IPC_MSG(m,t) 					\
	({							\
		int ret = 1;					\
		if (nlmsg_len(m) != sizeof(t))) {		\
			pr_err("Bad message: %s\n", __func__);	\
			ret = 0;				\
		}						\
		ret;						\
	})

struct ipc_msg_table_entry {
	unsigned long long	handle;
	struct hlist_node	hlist
	wait_queue_head_t	waiter;

	struct cifsd_ipc_msg	*msg;
};

static void handle_response(struct nlmsghdr *nlh)
{
	unsigned long long handle = CIFSD_IPC_MSG_HANDLE(nlmsg_data(nlh));

	read_lock(&ipc_msg_table_lock);
	hash_for_each_possible(ipc_msg_table, entry, hlist, handle) {
		if (handle != entry->handle)
			continue;

		entry->msg = cifds_ipc_msg_alloc(nlmsg_len(nlh));
		if (!entry->msg)
			break;

		memcpy(entry->msg, nlmsg_data(nlh), nlmsg_len(nlh));
		wake_up_interruptible(&entry->waiter);
	}
	read_unlock(&ipc_msg_table_lock);
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

static void cifsd_ipc_handle_message(struct nlmsghdr *nlh)
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
			break;

		cifsd_ipc_consume_message(nlh);
	}
	consume_skb(skb);
}

struct cifsd_ipc_msg *cifds_ipc_msg_alloc(size_t sz)
{
	return NULL;
}

void cifsd_ipc_msg_free(struct cifsd_ipc_msg *msg)
{
}

void cifsd_ipc_free(void)
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
		cifsd_err("failed to create cifsd netlink socket\n");
		return -ENOMEM;
	}
	return 0;
}
