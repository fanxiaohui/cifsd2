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

#ifndef __CIFSD_FILE_ID_TABLE_H__
#define __CIFSD_FILE_ID_TABLE_H__

#include <linux/idr.h>
#include <linux/rwsem.h>

struct cifsd_fid_table {
	struct idr		idr;
	struct rw_semaphore	lock;
};

struct cifsd_inode {
	spinlock_t		i_lock;
	struct inode		*inode;

	atomic_t		i_count;
	atomic_t		i_op_count;
	unsigned int		i_flags;
	struct list_head	i_fp_list;
	struct oplock_info	*i_opinfo;
	char			*stream_name;
};

struct cifsd_file {
	struct cifsd_sess		*sess;
	struct cifsd_tcon		*tcon;
	struct oplock_info		*f_opinfo;

	/*struct file			*filp; */
	struct dentry			*d_entry;

	/* struct cifsd_inode		*f_mfp; */
	struct cifsd_inode		*f_inode;

	/* Will be used for in case of symlink */
	/* struct file 			*symlink_filp;*/
	struct dentry			*symlink_d_entry;

	struct timespec			open_time;
	/* if ls is happening on directory, below is valid*/
	struct smb_readdir_data		readdir_data;
	int				dot_dotdot[2];
	int				dirent_offset;
	/* oplock info */
	uint64_t			persistent_id;
	unsigned int 			volatile_id;

	bool				islink;
	bool				is_durable;
	bool				is_resilient;
	bool				is_persistent;
	bool				is_nt_open;
	bool				delete_on_close;
	bool				attrib_only;
	bool				is_stream;

	__le32				daccess;
	__le32				saccess;
	__le32				coption;
	__le32				cdoption;
	__le32				fattr;
	__u64				create_time;

	struct stream			stream;
	struct list_head		node;
	struct hlist_node		notify_node;
	struct list_head		queue;
	struct list_head		lock_list;
	spinlock_t			f_lock;
	wait_queue_head_t		wq;
	int				f_state;
	char				client_guid[16];
	char				create_guid[16];
	char				app_instance_id[16];
	int				durable_timeout;
	int				pid; /* for SMB1 */

	/* conflict lock fail count for SMB1 */
	unsigned int			cflock_cnt;
	/* last lock failure start offset for SMB1 */
	unsigned long long		llock_fstart;
};

void cifsd_fid_table_free(struct cifsd_fid_table *table);
int cifsd_fid_init(struct cifsd_fid_table *table);

int cifsd_fid_insert(struct cifsd_fid_table *table,
		     struct cifsd_file *fp,
		     unsigned long long *id);

void cifsd_fid_remove(struct cifsd_fid_table *table,
		      struct cifsd_file *fp);

struct cifsd_file *cifsd_fid_lookup(struct cifsd_fid_table *table,
				    unsigned long long id);

#endif /* __CIFSD_FILE_ID_TABLE_H__ */
