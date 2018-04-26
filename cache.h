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

#ifndef __CIFSD_CACHE_H__
#define __CIFSD_CACHE_H__

#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/rwsem.h>
#include <linux/radix-tree.h>
#include <linux/atomic.h>

struct cifsd_cache {
	struct rw_semaphore	lock;
	struct radix_tree_root	rt;
	atomic_long_t		next_id;

	void 			*(*lookup_fn)(void *val);
	void 			(*destructor_fn)(void *val);
};

static void cifsd_cache_for_each(struct cifsd_cache *cache,
				 int (*for_each_fn)(void *val))
{
	struct radix_tree_iter iter;
	void **slot;

	down_read(&cache->lock);
	rcu_read_lock();
	radix_tree_for_each_slot(slot, &cache->rt, &iter, 0) {
		void *val = radix_tree_deref_slot(slot);

		if (for_each_fn) {
			if (for_each_fn(val))
				break;
		}
	}
	rcu_read_unlock();
	up_read(&cache->lock);
}

static void *cifsd_cache_lookup(struct cifsd_cache *cache, unsigned long id)
{
	void *ret;

	down_read(&cache->lock);
	rcu_read_lock();
	ret = radix_tree_lookup(&cache->rt, id);
	if (ret && cache->lookup_fn)
		ret = cache->lookup_fn(ret);
	rcu_read_unlock();
	up_read(&cache->lock);

	return ret;
}

static int cifsd_cache_insert(struct cifsd_cache *cache,
			      unsigned long key,
			      void *val)
{
	int ret;

	down_write(&cache->lock);
	ret = radix_tree_insert(&cache->rt, key, val);
	up_write(&cache->lock);
	return ret;
}

static int cifsd_cache_insert_index(struct cifsd_cache *cache,
				    void *val,
				    unsigned long *id)
{
	unsigned long key, start_pos;
	int ret;

	down_write(&cache->lock);
	start_pos = atomic_long_read(&cache->next_id);
	do {
		key = atomic_long_inc_return(&cache->next_id);
		if (key == start_pos) {
			ret = -EINVAL;
			break;
		}

		*id = key;
		ret = radix_tree_insert(&cache->rt, key, val);
	} while (ret == -EEXIST);
	up_write(&cache->lock);
	return ret;
}

static int cifsd_cache_remove(struct cifsd_cache *cache, unsigned long key)
{
	down_write(&cache->lock);
	radix_tree_delete(&cache->rt, key);
	up_write(&cache->lock);
	return 0;
}

static void cifsd_cache_destroy(struct cifsd_cache *cache)
{
	struct radix_tree_iter iter;
	void **slot;

	down_write(&cache->lock);
	rcu_read_lock();
	radix_tree_for_each_slot(slot, &cache->rt, &iter, 0) {
		void *val = radix_tree_deref_slot(slot);

		radix_tree_iter_delete(&cache->rt, &iter, slot);
		if (cache->destructor_fn)
			cache->destructor_fn(val);
	}
	rcu_read_unlock();
	up_write(&cache->lock);
}

static int cifsd_cache_init(struct cifsd_cache *cache,
			     void *(*lookup_fn)(void *val),
			     void (*destructor_fn)(void *val))
{
	INIT_RADIX_TREE(&cache->rt, GFP_KERNEL);

	init_rwsem(&cache->lock);
	atomic_long_set(&cache->next_id, 0);
	cache->lookup_fn = lookup_fn;
	cache->destructor_fn = destructor_fn;
	return 0;
}

/***********************************************************************/

struct cifsd_hash {
	struct rw_semaphore	lock;
	struct hlist_head	*hash;
	size_t			size_bits;
	size_t			key_size;

	int			(*lookup_fn)(struct hlist_node *node,
					     unsigned long id);
	void 			(*destructor_fn)(struct hlist_node *t);
};

static unsigned long ______hash_fn(struct cifsd_hash *ht, unsigned long key)
{
	if (ht->key_size == 4 || ht->key_size == 8)
		return hash_long((unsigned long)key, ht->size_bits);
	return (unsigned long)jhash((void *)key, ht->key_size, 0) >>
							(32 - ht->size_bits);
}

static struct hlist_node*
cifsd_hash_lookup_aux_key(struct cifsd_hash *ht,
			  unsigned long key,
			  int (*lookup_fn)(struct hlist_node *node,
					   unsigned long id))
{
	int cmp = -EINVAL;
	unsigned long k;
	struct hlist_head *hhd;
	struct hlist_node *node;

	k = ______hash_fn(ht, key);
	hhd = &ht->hash[k];

	down_read(&ht->lock);
	hlist_for_each(node, hhd) {
		if (lookup_fn)
			cmp = lookup_fn(node, key);
		if (cmp == 0)
			break;
	}
	node = NULL;
	up_read(&ht->lock);
	return node;
}

static struct hlist_node*
cifsd_hash_lookup(struct cifsd_hash *ht, unsigned long key)
{
	int cmp = -EINVAL;
	unsigned long k;
	struct hlist_head *hhd;
	struct hlist_node *node;

	k = ______hash_fn(ht, key);
	hhd = &ht->hash[k];

	down_read(&ht->lock);
	hlist_for_each(node, hhd) {
		if (ht->lookup_fn)
			cmp = ht->lookup_fn(node, key);
		if (cmp == 0)
			break;
	}
	node = NULL;
	up_read(&ht->lock);
	return node;
}

static int cifsd_hash_insert(struct cifsd_hash *ht,
			     unsigned long key,
			     struct hlist_node *node)
{
	unsigned long k = ______hash_fn(ht, key);

	down_write(&ht->lock);
	hlist_add_head(node, &ht->hash[k]);
	up_write(&ht->lock);
	return 0;
}

static int cifsd_hash_remove(struct cifsd_hash *ht,
			     struct hlist_node *node)
{
	down_write(&ht->lock);
	hlist_del(node);
	up_write(&ht->lock);
	return 0;
}

static void cifsd_hash_destroy(struct cifsd_hash *ht)
{
	struct hlist_head *hhd;
	int i;
	int size = 1 << ht->size_bits;

	down_write(&ht->lock);
	for (i = 0; i < size; i++) {
		hhd = &ht->hash[i];

		while (!hlist_empty(hhd)) {
			hlist_del(hhd->first);
			if (ht->destructor_fn)
				ht->destructor_fn(hhd->first);
		}
	}
	up_write(&ht->lock);
}

static int
cifsd_hash_init(struct cifsd_hash *ht,
		size_t size_bits,
		size_t key_size,
		int (*lookup_fn)(struct hlist_node *node, unsigned long id),
		void (*destructor_fn)(struct hlist_node *t))
{
	size_t sz = 1 << size_bits;

	ht->hash = kzalloc(sizeof(struct hlist_head) * sz, GFP_KERNEL);
	if (!ht->hash)
		return -ENOMEM;

	ht->size_bits = size_bits;
	ht->key_size = key_size;

	init_rwsem(&ht->lock);
	ht->lookup_fn = lookup_fn;
	ht->destructor_fn = destructor_fn;
}
#endif /* __CIFSD_CACHE_H__ */
