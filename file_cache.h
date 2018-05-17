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

#ifndef __CIFSD_FILE_CACHE_H__
#define __CIFSD_FILE_CACHE_H__

#include <linux/atomic.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/spinlock.h>

/***********************************************************************/
/** TO BE REVISITED **/

#include "cache.h"
#include "netlink.h"
#include "glob.h"

/* Windows style file permissions for extended response */
#define	FILE_GENERIC_ALL	0x1F01FF
#define	FILE_GENERIC_READ	0x120089
#define	FILE_GENERIC_WRITE	0x120116
#define	FILE_GENERIC_EXECUTE	0X1200a0

#define ATTR_FP(fp) (fp->attrib_only && \
		(fp->cdoption != FILE_OVERWRITE_IF_LE && \
		fp->cdoption != FILE_OVERWRITE_LE && \
		fp->cdoption != FILE_SUPERSEDE_LE))

struct cifsd_tcp_conn;
struct cifsd_sess;

struct cifsd_readdir_data {
	struct dir_context	ctx;
	char			*dirent;
	unsigned int		used;
	unsigned int		full;
	unsigned int		dirent_count;
	unsigned int		file_attr;
};

struct cifsd_dirent {
	__le64		ino;
	__le64		offset;
	__le32		d_type;
	__le32		namelen;
	char		name[];
};

struct cifsd_notification {
	unsigned int		mode;
	struct list_head	queuelist;
	struct smb_work		*work;
};

struct cifsd_lock_ {
	struct file_lock	*fl;
	struct list_head	glist;
	struct list_head	llist;
	struct list_head	flist;
	unsigned int		flags;
	unsigned int		cmd;
	int			zero_len;
	unsigned long long	start;
	unsigned long long	end;
	struct smb_work	*work;
};

struct cifsd_stream {
	char		*name;
	int		type;
	ssize_t		size;
};

enum cifsd_pipe_type_ {
	PIPE_SRVSVC,
	PIPE_WINREG,
	PIPE_LANMAN,
	PIPE_MAX
};

struct cifsd_pipe_table_ {
	char		pipename[32];
	unsigned int	pipetype;
};

#define INVALID_PIPE   0xFFFFFFFF

struct cifsd_pipe_ {
	unsigned int		id;
	char			*data;
	int			pkt_type;
	int			pipe_type;
	int			opnum;
	char			*buf;
	int			datasize;
	int			sent;
	struct cifsd_uevent	ev;
	char			*rsp_buf;
};

#define CIFSD_NR_OPEN_DEFAULT BITS_PER_LONG
/***********************************************************************/

struct cifsd_inode;

struct cifsd_file_ {
	struct file			*f_filp;
	struct cifsd_inode		*f_inode;

	struct cifsd_sess		*sess;
	struct cifsd_tcon		*tcon;
	struct oplock_info		*f_opinfo;

	/* Will be used for in case of symlink */
	struct file 			*symlink_filp;

	struct timespec			open_time;
	/* if ls is happening on directory, below is valid*/
	struct cifsd_readdir_data	readdir_data;
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

	struct cifsd_stream		stream;
	struct list_head		f_ino_list;
	struct hlist_node		notify_node;
	struct list_head		queue;
	struct list_head		lock_list;
	spinlock_t			f_lock;
	wait_queue_head_t		wq;
	int				f_state;
	char				client_guid[SMB2_CREATE_GUID_SIZE];
	char				create_guid[SMB2_CREATE_GUID_SIZE];
	char				app_instance_id[SMB2_CREATE_GUID_SIZE];
	struct hlist_node		file_cache_list;
	int				durable_timeout;
	int				pid; /* for SMB1 */

	/* conflict lock fail count for SMB1 */
	unsigned int			cflock_cnt;
	/* last lock failure start offset for SMB1 */
	unsigned long long		llock_fstart;

	struct hlist_node		client_id_hash;
	struct hlist_node		create_id_hash;
	struct hlist_node		app_id_hash;
	atomic_t			__refcount;
	struct work_struct		__free_work;
};

#define CIFSD_FILE_PARENT_VFS_INODE(f)	\
	((f)->f_filp->f_path.dentry->d_parent->d_inode)

#define CIFSD_FILE_VFS_INODE(f)	\
	((f)->f_filp->f_path.dentry->d_inode)

#define CIFSD_FILE_INODE(f)	\
	((f)->f_inode)

struct cifsd_file_cache {
	struct cifsd_cache	cache;
	struct cifsd_hash	hash;
};

int cifsd_add_to_local_file_cache(struct cifsd_sess *sess,
				  struct cifsd_file_ *filp);
int cifsd_add_to_global_file_cache(struct cifsd_file_ *filp);

struct cifsd_file_ *cifsd_file_cache_lookup(struct cifsd_sess *sess,
					    unsigned long key);

void cifsd_file_put(struct cifsd_file_ *filp);

struct cifsd_file_ *cifsd_file_open(struct file *file);
void cifsd_file_close(struct cifsd_file_ *filp);

int cifsd_local_file_cache_init(struct cifsd_sess *sess);
void cifsd_local_file_cache_destroy(struct cifsd_sess *sess);

int cifsd_global_file_cache_init(void);
void cifsd_global_file_cache_destroy(void);

#endif /* __CIFSD_FILE_CACHE_H__ */
