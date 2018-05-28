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

#include <linux/slab.h>

#include "cache.h"
#include "file_cache.h"
#include "inode_cache.h"
#include "buffer_pool.h"

#include "export.h"
#include "oplock.h"

#ifdef CONFIG_CIFS_SMB2_SERVER
static struct cifsd_cache file_cache;
#endif

static void cifsd_file_free(struct rcu_head *rcu_head)
{
	struct cifsd_file_ *filp = container_of(rcu_head,
					        struct cifsd_file_,
					        __free_work);
	struct file *vfs_filp;

	if (filp->symlink_filp)
		vfs_filp = filp->symlink_filp;

	kfree(filp->stream.name);
	kfree(filp);
	filp_close(vfs_filp, (struct files_struct *)vfs_filp);
}

static void __cache_destructor_fn(void *val)
{
	struct cifsd_file_ *filp = (struct cifsd_file_ *)val;

	call_rcu(&filp->__free_work, cifsd_file_free);
}

static void __hash_destructor_fn(struct hlist_node *node)
{
}

static void *cifsd_file_get(struct cifsd_file_ *filp)
{
	if (!atomic_inc_not_zero(&filp->__refcount))
		return NULL;
        return filp;
}

void cifsd_file_put(struct cifsd_file_ *filp)
{
	if (!atomic_dec_and_test(&filp->__refcount))
		return;

	__cache_destructor_fn(filp);
}

static void *__cache_lookup_fn(void *val)
{
	struct cifsd_file_ *filp = (struct cifsd_file_ *)val;

	if (!filp->f_filp)
		return NULL;
	return cifsd_file_get(filp);
}

static int __hash_lookup_fn(struct hlist_node *node, unsigned long id)
{
	return 0;
}

#ifdef CONFIG_CIFS_SMB2_SERVER
int cifsd_add_to_global_file_cache(struct cifsd_file_ *filp)
{
	int ret;
	unsigned long id;

	ret = cifsd_cache_insert_index(&file_cache, filp, &id);
	if (ret)
		return ret;

	filp->persistent_id = id;
	return 0;
}

static struct cifsd_file_ *__global_file_cache_lookup(unsigned long key)
{
	return cifsd_cache_lookup(&file_cache, key);
}

static bool is_empty_id(char *id, size_t sz)
{
	int i;

	for (i = 0; i < sz; i++)
		if (id[i] != 0x00)
			return false;
	return true;
}

static void __remove_file_from_id_hash(struct cifsd_sess *sess,
				       struct cifsd_file_ *filp)
{
	cifsd_hash_remove(&sess->file_cache.hash, &filp->client_id_hash);
	cifsd_hash_remove(&sess->file_cache.hash, &filp->create_id_hash);
	cifsd_hash_remove(&sess->file_cache.hash, &filp->app_id_hash);
}

static int __add_file_to_id_hash(struct cifsd_sess *sess,
				 struct cifsd_file_ *filp)
{
	if (!is_empty_id(filp->client_guid, SMB2_CREATE_GUID_SIZE))
		cifsd_hash_insert(&sess->file_cache.hash,
				  (unsigned long)filp->client_guid,
				  &filp->client_id_hash);

	if (!is_empty_id(filp->create_guid, SMB2_CREATE_GUID_SIZE))
		cifsd_hash_insert(&sess->file_cache.hash,
				  (unsigned long)filp->create_guid,
				  &filp->create_id_hash);

	if (!is_empty_id(filp->app_instance_id, SMB2_CREATE_GUID_SIZE))
		cifsd_hash_insert(&sess->file_cache.hash,
				  (unsigned long)filp->app_instance_id,
				  &filp->app_id_hash);
	return 0;
}

static int hash_lookup_client_id(struct hlist_node *node, unsigned long id)
{
	struct cifsd_file_ *fp;

	fp = container_of(node, struct cifsd_file_, client_id_hash);
	if (!memcmp(fp->client_guid, (char *)id, SMB2_CREATE_GUID_SIZE))
		return 0;
	return -1;
}

static int hash_lookup_create_id(struct hlist_node *node, unsigned long id)
{
	struct cifsd_file_ *fp;

	fp = container_of(node, struct cifsd_file_, create_id_hash);
	if (!memcmp(fp->create_guid, (char *)id, SMB2_CREATE_GUID_SIZE))
		return 0;
	return -1;
}

static int hash_lookup_app_id(struct hlist_node *node, unsigned long id)
{
	struct cifsd_file_ *fp;

	fp = container_of(node, struct cifsd_file_, app_id_hash);
	if (!memcmp(fp->app_instance_id, (char *)id, SMB2_CREATE_GUID_SIZE))
		return 0;
	return -1;
}

struct cifsd_file_ *cifsd_file_cache_lookup_client_id(struct cifsd_sess *sess,
						      char *id)
{
	struct hlist_node* fp;

	fp = cifsd_hash_lookup_aux_key(&sess->file_cache.hash,
				       (unsigned long)id,
				       hash_lookup_client_id);
	if (fp)
		return container_of(fp, struct cifsd_file_, client_id_hash);
	return NULL;
}

struct cifsd_file_ *cifsd_file_cache_lookup_create_id(struct cifsd_sess *sess,
						      char *id)
{
	struct hlist_node* fp;

	fp = cifsd_hash_lookup_aux_key(&sess->file_cache.hash,
				       (unsigned long)id,
				       hash_lookup_create_id);
	if (fp)
		return container_of(fp, struct cifsd_file_, create_id_hash);
	return NULL;

}

struct cifsd_file_ *cifsd_file_cache_lookup_app_id(struct cifsd_sess *sess,
						   char *id)
{
	struct hlist_node* fp;

	fp = cifsd_hash_lookup_aux_key(&sess->file_cache.hash,
				       (unsigned long)id,
				       hash_lookup_app_id);
	if (fp)
		return container_of(fp, struct cifsd_file_, app_id_hash);
	return NULL;

}
#else
struct cifsd_file_ *cifsd_file_cache_lookup_client_id(struct cifsd_sess *sess,
						      char *id)
{
	return NULL;
}

struct cifsd_file_ *cifsd_file_cache_lookup_create_id(struct cifsd_sess *sess,
						      char *id)
{
	return NULL;

}

struct cifsd_file_ *cifsd_file_cache_lookup_app_id(struct cifsd_sess *sess,
						   char *id)
{
	return NULL;
}

int cifsd_add_to_global_file_cache(struct cifsd_file_ *filp)
{
	return 0;
}

static struct cifsd_file_ *__global_file_cache_lookup(unsigned long key)
{
	return NULL;
}

static int __add_file_to_id_hash(struct cifsd_sess *sess,
				 struct cifsd_file_ *filp)
{
	return 0;
}

static void __remove_file_from_id_hash(struct cifsd_sess *sess,
				       struct cifsd_file_ *filp)
{
}
#endif

int cifsd_add_to_local_file_cache(struct cifsd_sess *sess,
				  struct cifsd_file_ *filp)
{
	int ret;
	unsigned long id;

	ret = cifsd_cache_insert_index(&sess->file_cache.cache, filp, &id);
	if (ret)
		return ret;

	__add_file_to_id_hash(filp->sess, filp);
	filp->volatile_id = id;
	return 0;
}

struct cifsd_file_ *cifsd_file_cache_lookup(struct cifsd_sess *sess,
					    unsigned long key)
{
	struct cifsd_file_ *filp = cifsd_cache_lookup(&sess->file_cache.cache,
						      key);
	if (filp)
		return filp;
	return __global_file_cache_lookup(key);
}

struct cifsd_file_ *cifsd_file_open(struct file *file)
{
	struct cifsd_file_ *filp;
	struct cifsd_inode *inode;

	filp = cifsd_alloc_file_struct();
	if (!filp)
		return NULL;

	atomic_set(&filp->__refcount, 1);
	inode = cifsd_inode_open(filp);
	if (!inode) {
		WARN_ON(1);
		cifsd_free_file_struct(filp);
		return NULL;
	}

	filp->f_filp = file;
	filp->f_inode = inode;
	INIT_HLIST_NODE(&filp->client_id_hash);
	INIT_HLIST_NODE(&filp->create_id_hash);
	INIT_HLIST_NODE(&filp->app_id_hash);
	return filp;
}

void cifsd_file_close(struct cifsd_file_ *filp)
{
	if (filp->volatile_id)
		cifsd_cache_remove(&filp->sess->file_cache.cache,
				    filp->volatile_id);
#ifdef CONFIG_CIFS_SMB2_SERVER
	if (filp->persistent_id)
		cifsd_cache_remove(&file_cache, filp->persistent_id);
#endif
	__remove_file_from_id_hash(filp->sess, filp);
	//close_id_del_oplock(filp);

	cifsd_inode_close(filp);
	cifsd_file_put(filp);
}

int cifsd_local_file_cache_init(struct cifsd_sess *sess)
{
	int ret = cifsd_cache_init(&sess->file_cache.cache,
				   __cache_lookup_fn,
				   __cache_destructor_fn);
	if (ret)
		return ret;

	return cifsd_hash_init(&sess->file_cache.hash,
				5,
				SMB2_CREATE_GUID_SIZE,
				__hash_lookup_fn,
				__hash_destructor_fn);
}

void cifsd_local_file_cache_destroy(struct cifsd_sess *sess)
{
	cifsd_hash_destroy(&sess->file_cache.hash);
	cifsd_cache_destroy(&sess->file_cache.cache);
}

#ifdef CONFIG_CIFS_SMB2_SERVER
int cifsd_global_file_cache_init(void)
{
	return cifsd_cache_init(&file_cache,
				__cache_lookup_fn,
				__cache_destructor_fn);
}

void cifsd_global_file_cache_destroy(void)
{
	cifsd_cache_destroy(&file_cache);
}
#else
int cifsd_global_file_cache_init(void)
{
	return 0;
}

void cifsd_global_file_cache_destroy(void)
{
}
#endif
