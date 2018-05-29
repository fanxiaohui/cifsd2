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
	unsigned long		next_id;

	void 			*(*lookup_fn)(void *val);
	void 			(*destructor_fn)(void *val);
};

void cifsd_cache_for_each(struct cifsd_cache *cache,
			  int (*for_each_fn)(void *val));

void *cifsd_cache_lookup(struct cifsd_cache *cache, unsigned long id);

int cifsd_cache_insert(struct cifsd_cache *cache,
		       unsigned long key,
		       void *val);

int cifsd_cache_insert_index(struct cifsd_cache *cache,
			     void *val,
			     unsigned long *id);

int cifsd_cache_remove(struct cifsd_cache *cache, unsigned long key);

void cifsd_cache_destroy(struct cifsd_cache *cache);

int cifsd_cache_init(struct cifsd_cache *cache,
		     void *(*lookup_fn)(void *val),
		     void (*destructor_fn)(void *val));

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

struct hlist_node*
cifsd_hash_lookup_aux_key(struct cifsd_hash *ht,
			  unsigned long key,
			  int (*lookup_fn)(struct hlist_node *node,
					   unsigned long id));

struct hlist_node* cifsd_hash_lookup(struct cifsd_hash *ht, unsigned long key);

int cifsd_hash_insert(struct cifsd_hash *ht,
		      unsigned long key,
		      struct hlist_node *node);

int cifsd_hash_remove(struct cifsd_hash *ht,
		      struct hlist_node *node);

void cifsd_hash_destroy(struct cifsd_hash *ht);

int
cifsd_hash_init(struct cifsd_hash *ht,
		size_t size_bits,
		size_t key_size,
		int (*lookup_fn)(struct hlist_node *node, unsigned long id),
		void (*destructor_fn)(struct hlist_node *t));
#endif /* __CIFSD_CACHE_H__ */
