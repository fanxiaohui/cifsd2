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
#include <linux/rwsem.h>

#include "cifds_ida.h"
#include "user_session.h"
#include "tree_connect.h"
#include "../buffer_pool.h"
#include "../cifsd_server.h" /* FIXME */

static struct cifsd_ida *session_ida;

#define SESSION_HASH_BITS		3
static DEFINE_HASHTABLE(sessions_table, SESSION_HASH_BITS);
static DECLARE_RWSEM(sessions_table_lock);

static void free_channel_list(struct cifsd_session *sess)
{
	struct channel *chann;
	struct list_head *tmp, *t;

	list_for_each_safe(tmp, t, &sess->cifsd_chann_list) {
		chann = list_entry(tmp, struct channel, chann_list);
		if (chann) {
			list_del(&chann->chann_list);
			kfree(chann);
		}
	}
}

static void __kill_smb1_session(struct cifsd_session *sess)
{

}

static void __kill_smb2_session(struct cifsd_session *sess)
{
	destroy_fidtable(sess);
}

void cifsd_session_destroy(struct cifsd_session *sess)
{
	free_channel_list(sess);
	kfree(sess->Preauth_HashValue);
	cifds_release_id(session_ida, sess->id);

	down_write(&sessions_table_lock);
	hash_del(&sess->hlist);
	up_write(&sessions_table_lock);

	if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB1))
		__kill_smb1_session(sess);
	else if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB2))
		__kill_smb2_session(sess);
	cifsd_ida_free(sess->tree_conn_ida);
	cifsd_free(sess);
}

static struct cifsd_session *__session_lookup(unsigned long long id)
{
	struct cifsd_session *sess;

	hash_for_each_possible(sessions_table, sess, hlist, id) {
		if (id == sess->id)
			return sess;
	}
	return NULL;
}

struct cifsd_session *cifsd_session_lookup(unsigned long long id)
{
	struct cifsd_session *sess;

	down_read(&sessions_table_lock);
	sess = __session_lookup(id);
	up_read(&sessions_table_lock);

	return sess;
}

static int __init_smb1_session(struct cifsd_session *sess)
{
	int id = cifds_acquire_next_smb1_id(session_ida);

	if (id < 0)
		return -EINVAL;
	sess->id = id;
	return 0;
}

static int __init_smb2_session(struct cifsd_session *sess)
{
	int id = cifds_acquire_next_smb2_id(session_ida);

	if (id < 0)
		return -EINVAL;
	sess->id = id;
	return init_fidtable(&sess->fidtable);
}

static struct cifsd_session *__session_create(int protocol)
{
	struct cifsd_session *sess;
	int ret;
	
	sess = cifsd_alloc(sizeof(struct cifsd_session));
	if (sess == NULL)
		return NULL;

	set_session_flag(sess, protocol);
	INIT_LIST_HEAD(&sess->tree_conn_list);
	INIT_LIST_HEAD(&sess->cifsd_chann_list);
	sess->sequence_number = 1;
	sess->valid = 1;
	init_waitqueue_head(&sess->pipe_q);
	sess->ev_state = NETLINK_REQ_INIT;

	switch (protocol) {
	case CIFDS_SESSION_FLAG_SMB1:
		ret = __init_smb1_session(sess);
		break;
	case CIFDS_SESSION_FLAG_SMB2:
		ret = __init_smb2_session(sess);
		break;
	}

	sess->tree_conn_ida = cifsd_ida_alloc(0);
	if (!sess->tree_conn_ida)
		ret = -ENOMEM;

	if (ret) {
		cifsd_session_destroy(sess);
		return NULL;
	}

	down_read(&sessions_table_lock);
	hash_add(sessions_table, &sess->hlist, sess->id);
	up_read(&sessions_table_lock);
	return sess;
}

struct cifsd_session *cifsd_smb1_session_create(void)
{
	return __session_create(CIFDS_SESSION_FLAG_SMB1);
}

struct cifsd_session *cifsd_smb2_session_create(void)
{
	return __session_create(CIFDS_SESSION_FLAG_SMB2);
}

int cifsd_acquire_tree_conn_id(struct cifsd_session *sess)
{
	int id = -EINVAL;

	if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB1))
		id = cifds_acquire_next_smb1_id(sess->tree_conn_ida);
	if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB2))
		id = cifds_acquire_next_smb2_id(sess->tree_conn_ida);

	return id;
}

void cifsd_release_tree_conn_id(struct cifsd_session *sess, int id)
{
	cifds_release_id(sess->tree_conn_ida, id);
}

int cifsd_init_session_table(void)
{
	session_ida = cifsd_ida_alloc(1);
	if (!session_ida)
		return -ENOMEM;
	return 0;
}

void cifsd_free_session_table(void)
{
	cifsd_ida_free(session_ida);
}
