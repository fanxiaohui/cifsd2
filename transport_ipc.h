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

struct cifsd_ipc_msg {
	unsigned int		type;
	int			destination;

	unsigned int		sz;
	unsigned char		____payload[0];
};

#define CIFSD_IPC_MSG_PAYLOAD(m)	\
	((void *)(m) + offsetof(struct cifsd_ipc_msg, ____payload))

#define CIFSD_IPC_MSG_HANDLE(m)		\
	(*(unsigned long long)m)

struct cifsd_ipc_msg *cifds_ipc_msg_alloc(size_t sz);
void cifsd_ipc_msg_free(struct cifsd_ipc_msg *msg);

int cifsd_ipc_receiving_loop(void);

void cifsd_ipc_free(void);
int cifsd_ipc_init(void);

#endif /* __CIFSD_TRANSPORT_IPC_H__ */
