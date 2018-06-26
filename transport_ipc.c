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

struct cifsd_ipc_msg *cifds_ipc_msg_alloc(size_t sz)
{
	return NULL;
}

void cifsd_ipc_msg_free(struct cifsd_ipc_msg *msg)
{
}

static void cifsd_ipc_handle_message(struct nlmsghdr *nlh)
{
	switch (nlh->nlmsg_type) {

	}
}

static void cifsd_ipc_receiving_loop(struct sk_buff *skb)
{
	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return;

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
