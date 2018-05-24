/*
 *   fs/cifsd/oplock.c
 *
 *   Copyright (C) 2015 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
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

#include "glob.h"
#include "export.h"
#include "smb1pdu.h"
#ifdef CONFIG_CIFS_SMB2_SERVER
#include "smb2pdu.h"
#endif
#include "oplock.h"

#include "buffer_pool.h"
#include "transport.h"

bool oplocks_enable = true;
#ifdef CONFIG_CIFS_SMB2_SERVER
bool lease_enable = true;
bool durable_enable = true;
#endif

LIST_HEAD(lease_table_list);
DEFINE_MUTEX(lease_list_lock);

module_param(oplocks_enable, bool, 0644);
MODULE_PARM_DESC(oplocks_enable, "Enable or disable oplocks. Default: y/Y/1");

#ifdef CONFIG_CIFS_SMB2_SERVER
module_param(lease_enable, bool, 0644);
MODULE_PARM_DESC(lease_enable, "Enable or disable lease. Default: y/Y/1");
#endif

/**
 * get_new_opinfo() - allocate a new opinfo object for oplock info
 * @conn:     TCP server instance of connection
 * @id:		fid of open file
 * @Tid:	tree id of connection
 * @lctx:	lease context information
 *
 * Return:      allocated opinfo object on success, otherwise NULL
 */
static struct oplock_info *alloc_opinfo(struct cifsd_work *work,
		uint64_t id, __u16 Tid)
{
	struct cifsd_sess *sess = work->sess;
	struct oplock_info *opinfo;

	opinfo = kzalloc(sizeof(struct oplock_info), GFP_KERNEL);
	if (!opinfo)
		return NULL;

	opinfo->sess = sess;
	opinfo->conn = sess->conn;
	opinfo->level = OPLOCK_NONE;
	opinfo->op_state = OPLOCK_STATE_NONE;
	opinfo->fid = id;
	opinfo->Tid = Tid;
	opinfo->is_smb2 = IS_SMB2(sess->conn);
	INIT_LIST_HEAD(&opinfo->op_entry);
	INIT_LIST_HEAD(&opinfo->interim_list);
	init_waitqueue_head(&opinfo->op_end_wq);
	init_waitqueue_head(&opinfo->oplock_q);
	init_waitqueue_head(&opinfo->oplock_brk);

	return opinfo;
}

static int alloc_lease(struct oplock_info *opinfo,
	struct lease_ctx_info *lctx)
{
	struct lease *lease;

	lease = kmalloc(sizeof(struct lease), GFP_KERNEL);
	if (!lease)
		return -ENOMEM;

	memcpy(lease->lease_key, lctx->lease_key, SMB2_LEASE_KEY_SIZE);
	lease->state = lctx->req_state;
	lease->new_state = 0;
	lease->flags = lctx->flags;
	lease->duration = lctx->duration;
	INIT_LIST_HEAD(&opinfo->lease_entry);
	opinfo->o_lease = lease;

	return 0;
}

static void free_lease(struct oplock_info *opinfo)
{
	struct lease *lease;

	list_del(&opinfo->lease_entry);
	lease = opinfo->o_lease;
	kfree(lease);
}

static void free_opinfo(struct oplock_info *opinfo, spinlock_t *m_lock)
{
	mutex_lock(&lease_list_lock);
	spin_lock(m_lock);
	list_del(&opinfo->op_entry);
	spin_unlock(m_lock);
	if (opinfo->is_lease)
		free_lease(opinfo);
	kfree(opinfo);
	mutex_unlock(&lease_list_lock);
}

/**
 * opinfo_write_to_read() - convert a write oplock to read oplock
 * @opinfo:		current oplock info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_write_to_read(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

	if (opinfo->is_smb2) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (!((opinfo->level == SMB2_OPLOCK_LEVEL_BATCH) ||
			(opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))) {
			cifsd_err("bad oplock(0x%x)\n", opinfo->level);
			if (opinfo->is_lease)
				cifsd_err("lease state(0x%x)\n", lease->state);
			return -EINVAL;
		}
		opinfo->level = SMB2_OPLOCK_LEVEL_II;

		if (opinfo->is_lease)
			lease->state = lease->new_state;
#endif
	} else {
		if (!((opinfo->level == OPLOCK_EXCLUSIVE) ||
			(opinfo->level == OPLOCK_BATCH))) {
			cifsd_err("bad oplock(0x%x)\n", opinfo->level);
			return -EINVAL;
		}
		opinfo->level = OPLOCK_READ;
	}

	return 0;
}

/**
 * opinfo_read_handle_to_read() - convert a read/handle oplock to read oplock
 * @opinfo:		current oplock info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_read_handle_to_read(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

#ifdef CONFIG_CIFS_SMB2_SERVER
	lease->state = lease->new_state;
	opinfo->level = SMB2_OPLOCK_LEVEL_II;
#endif
	return 0;
}

/**
 * opinfo_write_to_none() - convert a write oplock to none
 * @opinfo:	current oplock info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_write_to_none(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

	if (opinfo->is_smb2) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (!((opinfo->level == SMB2_OPLOCK_LEVEL_BATCH) ||
			(opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))) {
			cifsd_err("bad oplock(0x%x)\n", opinfo->level);
			if (opinfo->is_lease)
				cifsd_err("lease state(0x%x)\n",
						lease->state);
			return -EINVAL;
		}
		opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
		if (opinfo->is_lease)
			lease->state = lease->new_state;
#endif
	} else {
		if (!((opinfo->level == OPLOCK_EXCLUSIVE) ||
			(opinfo->level == OPLOCK_BATCH))) {
			cifsd_err("bad oplock(0x%x)\n", opinfo->level);
			return -EINVAL;
		}
		opinfo->level = OPLOCK_NONE;
	}

	return 0;
}

/**
 * opinfo_read_to_none() - convert a write read to none
 * @opinfo:	current oplock info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_read_to_none(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

	if (opinfo->is_smb2) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (opinfo->level != SMB2_OPLOCK_LEVEL_II) {
			cifsd_err("bad oplock(0x%x)\n", opinfo->level);
			if (opinfo->is_lease)
				cifsd_err("lease state(0x%x)\n", lease->state);
			return -EINVAL;
		}
		opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
		if (opinfo->is_lease)
			lease->state = lease->new_state;
#endif
	} else {
		if (opinfo->level != OPLOCK_READ) {
			cifsd_err("bad oplock(0x%x)\n", opinfo->level);
			return -EINVAL;
		}
		opinfo->level = OPLOCK_NONE;
	}

	return 0;
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * lease_read_to_write() - upgrade lease state from read to write
 * @opinfo:	current lease info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int lease_read_to_write(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

	if (!(lease->state & SMB2_LEASE_READ_CACHING)) {
		cifsd_debug("bad lease state(0x%x)\n",
				lease->state);
		return -EINVAL;
	}

	lease->new_state = SMB2_LEASE_NONE;
	lease->state |= SMB2_LEASE_WRITE_CACHING;
	if (lease->state & SMB2_LEASE_HANDLE_CACHING)
		opinfo->level = SMB2_OPLOCK_LEVEL_BATCH;
	else
		opinfo->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	return 0;
}

/**
 * lease_none_upgrade() - upgrade lease state from none
 * @opinfo:	current lease info
 * @new_state:	new lease state
 *
 * Return:	0 on success, otherwise -EINVAL
 */
int lease_none_upgrade(struct oplock_info *opinfo,
	__le32 new_state)
{
	struct lease *lease = opinfo->o_lease;

	if (!(lease->state == SMB2_LEASE_NONE)) {
		cifsd_debug("bad lease state(0x%x)\n",
				lease->state);
		return -EINVAL;
	}

	lease->new_state = SMB2_LEASE_NONE;
	lease->state = new_state;
	if (lease->state & SMB2_LEASE_HANDLE_CACHING)
		if (lease->state & SMB2_LEASE_WRITE_CACHING)
			opinfo->level = SMB2_OPLOCK_LEVEL_BATCH;
		else
			opinfo->level = SMB2_OPLOCK_LEVEL_II;
	else if (lease->state & SMB2_LEASE_WRITE_CACHING)
		opinfo->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	else if (lease->state & SMB2_LEASE_READ_CACHING)
		opinfo->level = SMB2_OPLOCK_LEVEL_II;

	return 0;
}
#endif

/**
 * close_id_del_oplock() - release oplock object at file close time
 * @conn:     TCP server instance of connection
 * @fp:		cifsd file pointer
 * @id:		fid of open file
 */
void close_id_del_oplock(struct cifsd_file *fp)
{
	struct oplock_info *opinfo;

	if (!oplocks_enable || S_ISDIR(file_inode(fp->filp)->i_mode))
		return;

	opinfo = fp->f_opinfo;
	if (!opinfo)
		return;

	fp->f_opinfo = NULL;
	if (opinfo->op_state == OPLOCK_ACK_WAIT) {
		opinfo->op_state = OPLOCK_CLOSING;
		wake_up_interruptible(&opinfo->oplock_q);
		if (opinfo->is_lease) {
			atomic_set(&opinfo->breaking_cnt, 0);
			wake_up_interruptible(&opinfo->oplock_brk);
		}
		wait_event_timeout(opinfo->op_end_wq,
				opinfo->op_state == OPLOCK_STATE_NONE,
				OPLOCK_WAIT_TIME);
	} else {
		atomic_dec(&fp->f_ino->op_count);
	}

	free_opinfo(opinfo, &fp->f_ino->m_lock);
}


#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * smb2_send_lease_break_notification() - send lease break command from server
 * to client
 * @work:     smb work object
 */
static void smb2_send_lease_break_notification(struct work_struct *wk)
{
	struct smb2_lease_break *rsp = NULL;
	struct cifsd_work *work = container_of(wk, struct cifsd_work, work);
	struct lease_break_info *br_info =
		(struct lease_break_info *)REQUEST_BUF(work);
	struct cifsd_tcp_conn *conn = work->conn;
	struct smb2_hdr *rsp_hdr;

	cifsd_tcp_conn_lock(conn);
	if (conn->ops->allocate_rsp_buf(work)) {
		cifsd_debug("smb2_allocate_rsp_buf failed! ");
		cifsd_tcp_conn_unlock(conn);
		cifsd_free_work_struct(work);
		return;
	}

	rsp_hdr = (struct smb2_hdr *)RESPONSE_BUF(work);
	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);
	rsp_hdr->smb2_buf_length = cpu_to_be32(sizeof(struct smb2_hdr) - 4);

	rsp_hdr->ProtocolId[0] = 0XFE;
	rsp_hdr->ProtocolId[1] = 'S';
	rsp_hdr->ProtocolId[2] = 'M';
	rsp_hdr->ProtocolId[3] = 'B';
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->CreditRequest = cpu_to_le16(0);
	rsp_hdr->Command = cpu_to_le16(0x12);
	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);
	rsp_hdr->NextCommand = 0;
	rsp_hdr->MessageId = cpu_to_le64(-1);
	rsp_hdr->Id.SyncId.ProcessId = 0;
	rsp_hdr->Id.SyncId.TreeId = 0;
	rsp_hdr->SessionId = 0;
	memset(rsp_hdr->Signature, 0, 16);

	rsp = (struct smb2_lease_break *)RESPONSE_BUF(work);
	rsp->StructureSize = cpu_to_le16(44);
	rsp->Reserved = 0;
	rsp->Flags = 0;

	if (br_info->curr_state & (SMB2_LEASE_WRITE_CACHING |
			SMB2_LEASE_HANDLE_CACHING))
		rsp->Flags = SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED;

	memcpy(rsp->LeaseKey, br_info->lease_key, SMB2_LEASE_KEY_SIZE);
	rsp->CurrentLeaseState = br_info->curr_state;
	rsp->NewLeaseState = br_info->new_state;
	rsp->BreakReason = 0;
	rsp->AccessMaskHint = 0;
	rsp->ShareMaskHint = 0;

	inc_rfc1001_len(rsp, 44);
	cifsd_tcp_write(work);
	cifsd_tcp_conn_unlock(conn);
	cifsd_free_work_struct(work);
}
#endif

/**
 * smb1_oplock_break_notification() - send smb1 exclusive/batch to level2 oplock
 *		break command from server to client
 * @opinfo:		oplock info object
 * @ack_required	if requiring ack
 *
 * Return:      0 on success, otherwise error
 */
static int smb1_oplock_break_notification(struct oplock_info *opinfo,
	int ack_required)
{
	struct cifsd_tcp_conn *conn = opinfo->conn;
	int ret = 0;
	struct cifsd_work *work = cifsd_alloc_work_struct();
	if (!work)
		return -ENOMEM;

	work->request_buf = (char *)opinfo;
	work->conn = conn;

	if (ack_required) {
		int rc;

		INIT_WORK(&work->work, smb1_send_oplock_break_notification);
		schedule_work(&work->work);

		/*
		 * TODO: change to wait_event_interruptible_timeout once oplock
		 * break notification timeout is decided. In case of oplock
		 * break from levelII to none, we don't need to wait for client
		 * response.
		 */
		rc = wait_event_interruptible_timeout(opinfo->oplock_q,
				opinfo->op_state == OPLOCK_STATE_NONE ||
				opinfo->op_state == OPLOCK_CLOSING,
				OPLOCK_WAIT_TIME);

		/* is this a timeout ? */
		if (!rc) {
			opinfo->level = OPLOCK_NONE;
			opinfo->op_state = OPLOCK_STATE_NONE;
		}
	} else {
		smb1_send_oplock_break_notification(&work->work);
		if (opinfo->level == OPLOCK_READ)
			opinfo->level = OPLOCK_NONE;
	}
	return ret;
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * smb2_oplock_break_notification() - send smb2 exclusive/batch to level2 oplock
 *		break command from server to client
 * @opinfo:		oplock info object
 * @ack_required	if requiring ack
 *
 * Return:      0 on success, otherwise error
 */
static int smb2_oplock_break_notification(struct oplock_info *opinfo,
	int ack_required)
{
	struct cifsd_tcp_conn *conn = opinfo->conn;
	struct oplock_break_info *br_info;
	int ret = 0;
	struct cifsd_work *work = cifsd_alloc_work_struct();
	if (!work)
		return -ENOMEM;

	br_info = kmalloc(sizeof(struct oplock_break_info), GFP_KERNEL);
	if (!br_info) {
		cifsd_free_work_struct(work);
		return -ENOMEM;
	}

	br_info->level = opinfo->level;
	br_info->fid = opinfo->fid;
	br_info->open_trunc = opinfo->open_trunc;

	work->request_buf = (char *)br_info;
	work->conn = conn;
	work->sess = opinfo->sess;

	if (ack_required) {
		int rc;

		INIT_WORK(&work->work, smb2_send_oplock_break_notification);
		schedule_work(&work->work);

		rc = wait_event_interruptible_timeout(opinfo->oplock_q,
			opinfo->op_state == OPLOCK_STATE_NONE ||
			opinfo->op_state == OPLOCK_CLOSING,
			OPLOCK_WAIT_TIME);

		/* is this a timeout ? */
		if (!rc) {
			opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
			opinfo->op_state = OPLOCK_STATE_NONE;
		}
	} else {
		smb2_send_oplock_break_notification(&work->work);
		if (opinfo->level == SMB2_OPLOCK_LEVEL_II)
			opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
	}
	return ret;
}
#endif

/**
 * grant_write_oplock() - grant exclusive/batch oplock or write lease
 * @opinfo_new:	new oplock info object
 * @req_oplock: request oplock
 * @lctx:	lease context information
 *
 * Return:      0
 */
static void grant_write_oplock(struct oplock_info *opinfo_new, int req_oplock,
	struct lease_ctx_info *lctx)
{
	struct lease *lease = opinfo_new->o_lease;

	if (opinfo_new->is_smb2) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (req_oplock == SMB2_OPLOCK_LEVEL_BATCH)
			opinfo_new->level = SMB2_OPLOCK_LEVEL_BATCH;
		else
			opinfo_new->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
#endif
	} else {
		if (req_oplock == REQ_BATCHOPLOCK)
			opinfo_new->level = OPLOCK_BATCH;
		else
			opinfo_new->level = OPLOCK_EXCLUSIVE;
	}

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (lctx) {
		lease->state = lctx->req_state;
		memcpy(lease->lease_key, lctx->lease_key,
				SMB2_LEASE_KEY_SIZE);
	}
#endif
}

/**
 * grant_read_oplock() - grant level2 oplock or read lease
 * @opinfo_new:	new oplock info object
 * @lctx:	lease context information
 *
 * Return:      0
 */
static void grant_read_oplock(struct oplock_info *opinfo_new,
	struct lease_ctx_info *lctx)
{
	struct lease *lease = opinfo_new->o_lease;

	if (opinfo_new->is_smb2) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		opinfo_new->level = SMB2_OPLOCK_LEVEL_II;
#endif
	} else
		opinfo_new->level = OPLOCK_READ;

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (lctx) {
		lease->state = SMB2_LEASE_READ_CACHING;
		if (lctx->req_state & SMB2_LEASE_HANDLE_CACHING)
			lease->state |= SMB2_LEASE_HANDLE_CACHING;
		memcpy(lease->lease_key, lctx->lease_key,
				SMB2_LEASE_KEY_SIZE);
	}
#endif
}

/**
 * grant_none_oplock() - grant none oplock or none lease
 * @opinfo_new:	new oplock info object
 * @lctx:	lease context information
 *
 * Return:      0
 */
static void grant_none_oplock(struct oplock_info *opinfo_new,
	struct lease_ctx_info *lctx)
{
	struct lease *lease = opinfo_new->o_lease;

	if (opinfo_new->is_smb2) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		opinfo_new->level = SMB2_OPLOCK_LEVEL_NONE;
#endif
	} else
		opinfo_new->level = OPLOCK_NONE;

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (lctx) {
		lease->state = 0;
		memcpy(lease->lease_key, lctx->lease_key,
			SMB2_LEASE_KEY_SIZE);
	}
#endif
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * find_opinfo() - find lease object for given client guid and lease key
 * @head:	oplock list(read,write or none) head
 * @guid1:	client guid of matching lease owner
 * @key1:	lease key of matching lease owner
 *
 * Return:      oplock(lease) object on success, otherwise NULL
 */
static inline int compare_guid_key(struct oplock_info *opinfo,
		const char *guid1, const char *key1)
{
	const char *guid2, *key2;

	guid2 = opinfo->conn->ClientGUID;
	key2 = opinfo->o_lease->lease_key;
	if (!memcmp(guid1, guid2, SMB2_CLIENT_GUID_SIZE) &&
			!memcmp(key1, key2, SMB2_LEASE_KEY_SIZE))
		return 1;

	return 0;
}

/**
 * same_client_has_lease() - check whether current lease request is
 *		from lease owner of file
 * @mfp:		master file pointer
 * @client_guid:	Client GUID
 * @lctx:		lease context information
 *
 * Return:      oplock(lease) object on success, otherwise NULL
 */
struct oplock_info *same_client_has_lease(struct cifsd_inode *mfp,
	char *client_guid, struct lease_ctx_info *lctx)
{
	int ret;
	struct lease *lease;
	struct oplock_info *opinfo;
	struct oplock_info *m_opinfo = NULL;

	if (!lctx)
		return NULL;

	/*
	 * Compare lease key and client_guid to know request from same owner
	 * of same client
	 */
	spin_lock(&mfp->m_lock);
	list_for_each_entry(opinfo, &mfp->m_op_list, op_entry) {
		if (!opinfo->is_lease)
			continue;
		spin_unlock(&mfp->m_lock);
		lease = opinfo->o_lease;

		ret = compare_guid_key(opinfo, client_guid, lctx->lease_key);
		if (ret) {
			m_opinfo = opinfo;
			/* skip upgrading lease about breaking lease */
			if (atomic_read(&opinfo->breaking_cnt)) {
				spin_lock(&mfp->m_lock);
				continue;
			}

			/* upgrading lease */
			if (atomic_read(&mfp->op_count) == 1) {
				if (lease->state ==
					(lctx->req_state & lease->state)) {
					lease->state |= lctx->req_state;
					if (lctx->req_state &
						SMB2_LEASE_WRITE_CACHING)
						lease_read_to_write(opinfo);
				}
			} else if (atomic_read(&mfp->op_count) > 1) {
				if (lctx->req_state == 0x3)
					lease->state = lctx->req_state;
			}

			if (lctx->req_state && lease->state == SMB2_LEASE_NONE)
				lease_none_upgrade(opinfo, lctx->req_state);
		}
		spin_lock(&mfp->m_lock);
	}
	spin_unlock(&mfp->m_lock);

	return m_opinfo;
}
#endif

void wait_for_lease_break_ack(struct oplock_info *opinfo)
{
	int rc = 0;

	rc = wait_event_interruptible_timeout(opinfo->oplock_q,
		opinfo->op_state == OPLOCK_STATE_NONE ||
		opinfo->op_state == OPLOCK_CLOSING,
		OPLOCK_WAIT_TIME);

	/* is this a timeout ? */
	if (!rc) {
		if (opinfo->is_lease)
			opinfo->o_lease->state = SMB2_LEASE_NONE;
		opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
		opinfo->op_state = OPLOCK_STATE_NONE;
	}
}

/**
 * smb2_break_lease_notification() - break lease when a new client request
 *			write lease
 * @opinfo:		conains lease state information
 * @ack_required:	if requring ack
 *
 * Return:	0 on success, otherwise error
 */
int smb2_break_lease_notification(struct oplock_info *opinfo, int ack_required)
{
	struct cifsd_tcp_conn *conn = opinfo->conn;
	struct list_head *tmp, *t;
	struct cifsd_work *work;
	struct lease_break_info *br_info;
	struct lease *lease = opinfo->o_lease;

	work = cifsd_alloc_work_struct();
	if (!work)
		return -ENOMEM;

	br_info = kmalloc(sizeof(struct lease_break_info), GFP_KERNEL);
	if (!br_info) {
		cifsd_free_work_struct(work);
		return -ENOMEM;
	}

	br_info->curr_state = lease->state;
	br_info->new_state = lease->new_state;
	memcpy(br_info->lease_key, lease->lease_key, SMB2_LEASE_KEY_SIZE);

	work->request_buf = (char *)br_info;
	work->conn = conn;
	work->sess = opinfo->sess;

	if (ack_required) {
		list_for_each_safe(tmp, t, &opinfo->interim_list) {
			struct cifsd_work *in_work;

			in_work = list_entry(tmp, struct cifsd_work,
				interim_entry);
			smb2_send_interim_resp(in_work);
			list_del(&in_work->interim_entry);
		}
		INIT_WORK(&work->work, smb2_send_lease_break_notification);
		schedule_work(&work->work);
		wait_for_lease_break_ack(opinfo);

		if (!atomic_read(&opinfo->breaking_cnt))
			wake_up_interruptible(&opinfo->oplock_brk);

		if (atomic_read(&opinfo->breaking_cnt)) {
			int ret = 0;

			ret = wait_event_interruptible_timeout(opinfo->oplock_brk,
				atomic_read(&opinfo->breaking_cnt) == 0,
				OPLOCK_WAIT_TIME);
			if (!ret)
				atomic_set(&opinfo->breaking_cnt, 0);
		}
	} else {
		smb2_send_lease_break_notification(&work->work);
		if (opinfo->o_lease->state == SMB2_LEASE_READ_CACHING) {
			opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
			opinfo->o_lease->state = SMB2_LEASE_NONE;
		}
	}
	return 0;
}

static int smb_send_oplock_break_notification(struct oplock_info *brk_opinfo)
{
	int err = 0;
	int ack_required = 0;

	/* Need to break exclusive/batch oplock, write lease or overwrite_if */
	cifsd_debug("request to send oplock(level : 0x%x) break notification\n",
		brk_opinfo->level);

	if (brk_opinfo->is_lease) {
		struct lease *lease = brk_opinfo->o_lease;

		if (!(lease->state == SMB2_LEASE_READ_CACHING))
			atomic_inc(&brk_opinfo->breaking_cnt);

		if (brk_opinfo->op_state == OPLOCK_ACK_WAIT) {
			/* wait till getting break ack */
			wait_for_lease_break_ack(brk_opinfo);

			/* Not immediately break to none. */
			brk_opinfo->open_trunc = 0;
		}

		if (brk_opinfo->open_trunc) {
			/*
			 * Create overwrite break trigger the lease break to
			 * none.
			 */
			lease->new_state = SMB2_LEASE_NONE;
		} else {
			if (lease->state & SMB2_LEASE_WRITE_CACHING) {
				if (lease->state & SMB2_LEASE_HANDLE_CACHING)
					lease->new_state =
						SMB2_LEASE_READ_CACHING |
						SMB2_LEASE_HANDLE_CACHING;
				else
					lease->new_state =
						SMB2_LEASE_READ_CACHING;
			} else {
				if (lease->state & SMB2_LEASE_HANDLE_CACHING)
					lease->new_state =
						SMB2_LEASE_READ_CACHING;
				else
					lease->new_state = SMB2_LEASE_NONE;
			}
		}

		if (lease->state & (SMB2_LEASE_WRITE_CACHING |
				SMB2_LEASE_HANDLE_CACHING))
			brk_opinfo->op_state = OPLOCK_ACK_WAIT;
	} else if (brk_opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||
		brk_opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)
		brk_opinfo->op_state = OPLOCK_ACK_WAIT;

	if (brk_opinfo->is_smb2) {
#ifdef CONFIG_CIFS_SMB2_SERVER
		if (brk_opinfo->is_lease) {
			struct lease *lease = brk_opinfo->o_lease;

			if ((brk_opinfo->open_trunc == 1 &&
				!(lease->state & SMB2_LEASE_WRITE_CACHING)) ||
				lease->state == SMB2_LEASE_READ_CACHING)
				ack_required = 0;
			else
				ack_required = 1;

			err = smb2_break_lease_notification(brk_opinfo,
				ack_required);
		} else {
			/* break oplock */
			if (brk_opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||
				brk_opinfo->level ==
				SMB2_OPLOCK_LEVEL_EXCLUSIVE)
				ack_required = 1;
			err = smb2_oplock_break_notification(brk_opinfo,
				ack_required);
		}
#endif
	} else {
		if ((brk_opinfo->level == SMB2_OPLOCK_LEVEL_BATCH) ||
			(brk_opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))
			ack_required = 1;
		err = smb1_oplock_break_notification(brk_opinfo,
			ack_required);
	}

	cifsd_debug("oplock granted = %d\n", brk_opinfo->level);
	if (brk_opinfo->op_state == OPLOCK_CLOSING) {
		brk_opinfo->op_state = OPLOCK_STATE_NONE;
		atomic_dec(&(brk_opinfo->o_fp->f_ino->op_count));
		wake_up_interruptible(&brk_opinfo->op_end_wq);
		err = -ENOENT;
	}

	return err;
}

void destroy_lease_table(struct cifsd_tcp_conn *conn)
{
	struct lease_table *lb, *lbtmp;

	mutex_lock(&lease_list_lock);
	if (list_empty(&lease_table_list)) {
		mutex_unlock(&lease_list_lock);
		return;
	}

	list_for_each_entry_safe(lb, lbtmp, &lease_table_list, l_entry) {
		if (conn && memcmp(lb->client_guid, conn->ClientGUID,
					SMB2_CLIENT_GUID_SIZE))
			continue;
		if (list_empty(&lb->lease_list)) {
			list_del(&lb->l_entry);
			kfree(lb);
		}
	}
	mutex_unlock(&lease_list_lock);
}

int find_same_lease_key(struct cifsd_sess *sess, struct cifsd_inode *mfp,
		struct lease_ctx_info *lctx)
{
	struct oplock_info *opinfo;
	int err = 0;
	struct lease_table *lb;

	if (!lctx)
		return err;

	mutex_lock(&lease_list_lock);
	if (list_empty(&lease_table_list))
		goto out;

	list_for_each_entry(lb, &lease_table_list, l_entry) {
		if (!memcmp(lb->client_guid, sess->conn->ClientGUID,
					SMB2_CLIENT_GUID_SIZE)) {
			list_for_each_entry(opinfo, &lb->lease_list,
					lease_entry) {
				if (opinfo->o_fp->f_ino == mfp)
					continue;
				err = compare_guid_key(opinfo,
					sess->conn->ClientGUID,
					lctx->lease_key);
				if (err) {
					err = -EINVAL;
					cifsd_debug("found same lease key is already used in other files\n");
					goto out;
				}
			}
		}
	}

out:
	mutex_unlock(&lease_list_lock);
	return err;
}

static void copy_lease(struct oplock_info *op1, struct oplock_info *op2)
{
	struct lease *lease1 = op1->o_lease;
	struct lease *lease2 = op2->o_lease;

	op2->level = op1->level;
	lease2->state = lease1->state;
	memcpy(lease2->lease_key, lease1->lease_key,
		SMB2_LEASE_KEY_SIZE);
	lease2->duration = lease1->duration;
	lease2->flags = lease1->flags;
}

void add_lease_global_list(struct oplock_info *opinfo)
{
	struct lease_table *lb;
	int added = 0;

	mutex_lock(&lease_list_lock);
	list_for_each_entry(lb, &lease_table_list, l_entry) {
		if (!memcmp(lb->client_guid, opinfo->conn->ClientGUID,
			SMB2_CLIENT_GUID_SIZE)) {
			list_add(&opinfo->lease_entry, &lb->lease_list);
			added = 1;
			break;
		}
	}

	if (!added) {
		lb = kmalloc(sizeof(struct lease_table), GFP_KERNEL);
		memcpy(lb->client_guid, opinfo->conn->ClientGUID,
			SMB2_CLIENT_GUID_SIZE);
		INIT_LIST_HEAD(&lb->lease_list);
		list_add(&opinfo->lease_entry, &lb->lease_list);
		list_add(&lb->l_entry, &lease_table_list);
	}
	mutex_unlock(&lease_list_lock);
}

static void set_oplock_level(struct oplock_info *opinfo, int level,
	struct lease_ctx_info *lctx)
{
	switch (level) {
	case REQ_OPLOCK:
	case REQ_BATCHOPLOCK:
	case SMB2_OPLOCK_LEVEL_BATCH:
	case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
		grant_write_oplock(opinfo,
			level, lctx);
		break;
	case SMB2_OPLOCK_LEVEL_II:
		grant_read_oplock(opinfo, lctx);
		break;
	default:
		grant_none_oplock(opinfo, lctx);
		break;
	}
}

/**
 * smb_grant_oplock() - handle oplock/lease request on file open
 * @fp:		cifsd file pointer
 * @oplock:	granted oplock type
 * @id:		fid of open file
 * @Tid:	Tree id of connection
 * @lctx:	lease context information on file open
 * @attr_only:	attribute only file open type
 *
 * Return:      0 on success, otherwise error
 */
int smb_grant_oplock(struct cifsd_work *work, int req_op_level, uint64_t pid,
	struct cifsd_file *fp, __u16 tid, struct lease_ctx_info *lctx,
	int share_ret)
{
	struct cifsd_sess *sess = work->sess;
	int err = 0;
	struct oplock_info *opinfo = NULL, *prev_opinfo = NULL;
	struct cifsd_inode *mfp = fp->f_ino;

	/* not support directory lease */
	if (S_ISDIR(file_inode(fp->filp)->i_mode)) {
		if (lctx)
			lctx->dlease = 1;
		return 0;
	}

	opinfo = alloc_opinfo(work, pid, tid);
	if (!opinfo)
		return -ENOMEM;

	if (lctx) {
		err = alloc_lease(opinfo, lctx);
		if (err)
			goto err_out;
		opinfo->is_lease = 1;
	}

	/* mfp does not have any oplock */
	if (!atomic_read(&mfp->op_count))
		goto set_lev;

	/* grant none-oplock if second open is trunc */
	if (ATTR_FP(fp)) {
		req_op_level = SMB2_OPLOCK_LEVEL_NONE;
		goto set_lev;
	}

#ifdef CONFIG_CIFS_SMB2_SERVER
	if (lctx) {
		struct oplock_info *m_opinfo;

		/* is lease already granted ? */
		m_opinfo = same_client_has_lease(mfp, sess->conn->ClientGUID,
			lctx);
		if (m_opinfo) {
			copy_lease(m_opinfo, opinfo);
			if (atomic_read(&m_opinfo->breaking_cnt))
				opinfo->o_lease->flags =
					SMB2_LEASE_FLAG_BREAK_IN_PROGRESS;
			goto out;
		}
	}
#endif
	spin_lock(&mfp->m_lock);
	prev_opinfo = list_first_entry(&mfp->m_op_list, struct oplock_info,
		op_entry);
	spin_unlock(&mfp->m_lock);
	if (!prev_opinfo)
		goto set_lev;

	if (share_ret < 0 &&
		(prev_opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)) {
		err = share_ret;
		goto err_out;
	}

	if ((prev_opinfo->level != SMB2_OPLOCK_LEVEL_BATCH) &&
		(prev_opinfo->level != SMB2_OPLOCK_LEVEL_EXCLUSIVE))
		goto op_break_not_needed;

	list_add(&work->interim_entry, &prev_opinfo->interim_list);
	err = smb_send_oplock_break_notification(prev_opinfo);
	if (err == -ENOENT)
		goto set_lev;
	/* Check all oplock was freed by close */
	else if (err < 0)
		goto err_out;

op_break_not_needed:
	if (share_ret < 0) {
		err = share_ret;
		goto err_out;
	}

	if (req_op_level != SMB2_OPLOCK_LEVEL_NONE)
		req_op_level = SMB2_OPLOCK_LEVEL_II;

	/* grant fixed oplock on stacked locking between lease and oplock */
	if (prev_opinfo->is_lease && !lctx)
		if (prev_opinfo->o_lease->state & SMB2_LEASE_HANDLE_CACHING)
			req_op_level = SMB2_OPLOCK_LEVEL_NONE;

	if (!prev_opinfo->is_lease && lctx) {
		req_op_level = SMB2_OPLOCK_LEVEL_II;
		lctx->req_state = SMB2_LEASE_READ_CACHING;
	}

set_lev:
	set_oplock_level(opinfo, req_op_level, lctx);

out:
	fp->f_opinfo = opinfo;
	opinfo->o_fp = fp;
	atomic_inc(&mfp->op_count);
	spin_lock(&mfp->m_lock);
	list_add(&opinfo->op_entry, &mfp->m_op_list);
	spin_unlock(&mfp->m_lock);
	if (opinfo->is_lease == 1)
		add_lease_global_list(opinfo);

	return 0;
err_out:
	free_opinfo(opinfo, &mfp->m_lock);
	return err;
}

/**
 * smb_break_write_oplock() - break batch/exclusive oplock to level2
 * @conn:	TCP server instance of connection
 * @fp:		cifsd file pointer
 * @openfile:	open file object
 */
int smb_break_all_write_oplock(struct cifsd_work *work,
	struct cifsd_file *fp, int is_trunc)
{
	struct cifsd_inode *mfp;
	struct oplock_info *brk_opinfo;

	mfp = fp->f_ino;
	spin_lock(&mfp->m_lock);
	if (list_empty(&mfp->m_op_list)) {
		spin_unlock(&mfp->m_lock);
		return 0;
	}
	brk_opinfo = list_first_entry(&mfp->m_op_list, struct oplock_info,
		op_entry);
	spin_unlock(&mfp->m_lock);
	if (!brk_opinfo || (brk_opinfo->level != SMB2_OPLOCK_LEVEL_BATCH &&
			brk_opinfo->level != SMB2_OPLOCK_LEVEL_EXCLUSIVE)) {
		return 0;
	}

	brk_opinfo->open_trunc = is_trunc;
	list_add(&work->interim_entry, &brk_opinfo->interim_list);
	smb_send_oplock_break_notification(brk_opinfo);

	return 1;
}

/**
 * smb_break_all_levII_oplock() - send level2 oplock or read lease break command
 *	from server to client
 * @conn:     TCP server instance of connection
 * @fp:		cifsd file pointer
 * @openfile:	open file information
 */
void smb_break_all_levII_oplock(struct cifsd_tcp_conn *conn,
	struct cifsd_file *fp, int is_trunc)
{
	struct oplock_info *op, *brk_op, *optmp;
	struct cifsd_inode *mfp;

	mfp = fp->f_ino;
	op = fp->f_opinfo;

	spin_lock(&mfp->m_lock);
	list_for_each_entry_safe(brk_op, optmp, &mfp->m_op_list, op_entry) {
		if (brk_op->is_smb2) {
#ifdef CONFIG_CIFS_SMB2_SERVER
			if (brk_op->is_lease && (brk_op->o_lease->state &
					(~(SMB2_LEASE_READ_CACHING |
					   SMB2_LEASE_HANDLE_CACHING)))) {
				cifsd_debug("unexpected lease state(0x%x)\n",
						brk_op->o_lease->state);
				continue;
			} else if (brk_op->level !=
					SMB2_OPLOCK_LEVEL_II) {
				cifsd_debug("unexpected oplock(0x%x)\n",
						brk_op->level);
				continue;
			}

			/* Skip oplock being break to none */
			if (brk_op->is_lease && (brk_op->o_lease->new_state ==
					SMB2_LEASE_NONE) &&
				atomic_read(&brk_op->breaking_cnt))
				continue;
#endif
		} else {
			if (brk_op->level != OPLOCK_READ) {
				cifsd_debug("unexpected oplock(0x%x)\n",
					brk_op->level);
				continue;
			}
		}

#ifdef CONFIG_CIFS_SMB2_SERVER
		if (op && op->is_lease &&
			brk_op->is_lease &&
			!memcmp(conn->ClientGUID, brk_op->conn->ClientGUID,
				SMB2_CLIENT_GUID_SIZE) &&
			!memcmp(op->o_lease->lease_key,
				brk_op->o_lease->lease_key,
				SMB2_LEASE_KEY_SIZE))
			continue;
#endif
		brk_op->open_trunc = is_trunc;
		spin_unlock(&mfp->m_lock);
		smb_send_oplock_break_notification(brk_op);
		spin_lock(&mfp->m_lock);
	}
	spin_unlock(&mfp->m_lock);
}

/**
 * smb_break_all_oplock() - break both batch/exclusive and level2 oplock
 * @conn:	TCP server instance of connection
 * @fp:		cifsd file pointer
 * @openfile:	open file object
 */
void smb_break_all_oplock(struct cifsd_work *work, struct cifsd_file *fp)
{
	int ret;

	ret = smb_break_all_write_oplock(work, fp, 1);
	if (!ret)
		smb_break_all_levII_oplock(work->conn, fp, 1);
}

/**
 * smb1_send_oplock_break_notification() - send smb1 oplock break cmd from conn
 * to client
 * @work:     smb work object
 *
 * There are two ways this function can be called. 1- while file open we break
 * from exclusive/batch lock to levelII oplock and 2- while file write/truncate
 * we break from levelII oplock no oplock.
 * REQUEST_BUF(work) contains oplock_info.
 */
void smb1_send_oplock_break_notification(struct work_struct *wk)
{
	struct cifsd_work *work = container_of(wk, struct cifsd_work, work);
	struct cifsd_tcp_conn *conn = work->conn;
	struct smb_hdr *rsp_hdr;
	LOCK_REQ *req;
	struct oplock_info *opinfo = (struct oplock_info *)REQUEST_BUF(work);

	cifsd_tcp_conn_lock(conn);
	if (conn->ops->allocate_rsp_buf(work)) {
		cifsd_err("smb_allocate_rsp_buf failed! ");
		cifsd_tcp_conn_unlock(conn);
		cifsd_free_work_struct(work);
		return;
	}

	/* Init response header */
	rsp_hdr = (struct smb_hdr *)RESPONSE_BUF(work);
	/* wct is 8 for locking andx */
	memset(rsp_hdr, 0, sizeof(struct smb_hdr) + 2 + 8*2);
	rsp_hdr->smb_buf_length = cpu_to_be32(HEADER_SIZE(conn) - 1 + 8*2);
	rsp_hdr->Protocol[0] = 0xFF;
	rsp_hdr->Protocol[1] = 'S';
	rsp_hdr->Protocol[2] = 'M';
	rsp_hdr->Protocol[3] = 'B';

	rsp_hdr->Command = SMB_COM_LOCKING_ANDX;
	/* we know unicode, long file name and use nt error codes */
	rsp_hdr->Flags2 = SMBFLG2_UNICODE | SMBFLG2_KNOWS_LONG_NAMES |
		SMBFLG2_ERR_STATUS;
	rsp_hdr->Uid = conn->vuid;
	rsp_hdr->Pid = 0xFFFF;
	rsp_hdr->Mid = 0xFFFF;
	rsp_hdr->Tid = cpu_to_le16(opinfo->Tid);
	rsp_hdr->WordCount = 8;

	/* Init locking request */
	req = (LOCK_REQ *)RESPONSE_BUF(work);

	req->AndXCommand = 0xFF;
	req->AndXReserved = 0;
	req->AndXOffset = 0;
	req->Fid = opinfo->fid;
	req->LockType = LOCKING_ANDX_OPLOCK_RELEASE;
	if (!opinfo->open_trunc && (opinfo->level == OPLOCK_BATCH ||
			opinfo->level == OPLOCK_EXCLUSIVE))
		req->OplockLevel = 1;
	else {
		req->OplockLevel = 0;
	}
	req->Timeout = 0;
	req->NumberOfUnlocks = 0;
	req->ByteCount = 0;
	cifsd_debug("sending oplock break for fid %d lock level = %d\n",
			req->Fid, req->OplockLevel);
	cifsd_tcp_write(work);
	cifsd_tcp_conn_unlock(conn);
	cifsd_free_work_struct(work);
}

#ifdef CONFIG_CIFS_SMB2_SERVER
/**
 * smb2_send_oplock_break_notification() - send smb1 oplock break cmd from conn
 * to client
 * @work:     smb work object
 *
 * There are two ways this function can be called. 1- while file open we break
 * from exclusive/batch lock to levelII oplock and 2- while file write/truncate
 * we break from levelII oplock no oplock.
 * REQUEST_BUF(work) contains oplock_info.
 */
void smb2_send_oplock_break_notification(struct work_struct *wk)
{
	struct smb2_oplock_break *rsp = NULL;
	struct cifsd_work *work = container_of(wk, struct cifsd_work, work);
	struct cifsd_tcp_conn *conn = work->conn;
	struct oplock_break_info *br_info =
		(struct oplock_break_info *)REQUEST_BUF(work);
	struct smb2_hdr *rsp_hdr;
	struct cifsd_file *fp;

	cifsd_tcp_conn_lock(conn);
	fp = cifsd_get_global_fp(br_info->fid);
	if (!fp) {
		cifsd_tcp_conn_unlock(conn);
		cifsd_free_work_struct(work);
		return;
	}

	if (conn->ops->allocate_rsp_buf(work)) {
		cifsd_err("smb2_allocate_rsp_buf failed! ");
		cifsd_tcp_conn_unlock(conn);
		cifsd_free_work_struct(work);
		return;
	}

	rsp_hdr = (struct smb2_hdr *)RESPONSE_BUF(work);
	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);
	rsp_hdr->smb2_buf_length = cpu_to_be32(sizeof(struct smb2_hdr) - 4);

	rsp_hdr->ProtocolId[0] = 0XFE;
	rsp_hdr->ProtocolId[1] = 'S';
	rsp_hdr->ProtocolId[2] = 'M';
	rsp_hdr->ProtocolId[3] = 'B';
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->CreditRequest = cpu_to_le16(0);
	rsp_hdr->Command = cpu_to_le16(0x12);
	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);
	rsp_hdr->NextCommand = 0;
	rsp_hdr->MessageId = cpu_to_le64(-1);
	rsp_hdr->Id.SyncId.ProcessId = 0;
	rsp_hdr->Id.SyncId.TreeId = 0;
	rsp_hdr->SessionId = 0;
	memset(rsp_hdr->Signature, 0, 16);


	rsp = (struct smb2_oplock_break *)RESPONSE_BUF(work);

	rsp->StructureSize = cpu_to_le16(24);
	if (!br_info->open_trunc &&
			(br_info->level == SMB2_OPLOCK_LEVEL_BATCH ||
			br_info->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))
		rsp->OplockLevel = 1;
	else
		rsp->OplockLevel = 0;
	rsp->Reserved = 0;
	rsp->Reserved2 = 0;
	rsp->PersistentFid = cpu_to_le64(fp->persistent_id);
	rsp->VolatileFid = cpu_to_le64(fp->volatile_id);

	inc_rfc1001_len(rsp, 24);

	cifsd_debug("sending oplock break v_id %llu p_id = %llu lock level = %d\n",
			rsp->VolatileFid, rsp->PersistentFid, rsp->OplockLevel);
	cifsd_tcp_write(work);
	cifsd_tcp_conn_unlock(conn);
	cifsd_free_work_struct(work);
}

/**
 * smb2_map_lease_to_oplock() - map lease state to corresponding oplock type
 * @lease_state:     lease type
 *
 * Return:      0 if no mapping, otherwise corresponding oplock type
 */
__u8 smb2_map_lease_to_oplock(__le32 lease_state)
{
	if (lease_state == (SMB2_LEASE_HANDLE_CACHING |
		SMB2_LEASE_READ_CACHING | SMB2_LEASE_WRITE_CACHING))
		return SMB2_OPLOCK_LEVEL_BATCH;
	else if (lease_state != SMB2_LEASE_WRITE_CACHING &&
		lease_state & SMB2_LEASE_WRITE_CACHING) {
		if (!(lease_state & SMB2_LEASE_HANDLE_CACHING))
			return SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	} else if (lease_state & SMB2_LEASE_READ_CACHING)
		return SMB2_OPLOCK_LEVEL_II;
	return 0;
}

/**
 * create_lease_buf() - create lease context for open cmd response
 * @rbuf:	buffer to create lease context response
 * @lreq:	buffer to stored parsed lease state information
 */
void create_lease_buf(u8 *rbuf, struct lease *lease)
{
	struct create_lease *buf = (struct create_lease *)rbuf;
	char *LeaseKey = (char *)&lease->lease_key;

	memset(buf, 0, sizeof(struct create_lease));
	buf->lcontext.LeaseKeyLow = *((u64 *)LeaseKey);
	buf->lcontext.LeaseKeyHigh = *((u64 *)(LeaseKey + 8));
	buf->lcontext.LeaseFlags = lease->flags;
	buf->lcontext.LeaseState = lease->state;
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
					(struct create_lease, lcontext));
	buf->ccontext.DataLength = cpu_to_le32(sizeof(struct lease_context));
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
				(struct create_lease, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	buf->Name[0] = 'R';
	buf->Name[1] = 'q';
	buf->Name[2] = 'L';
	buf->Name[3] = 's';
}

/**
 * parse_lease_state() - parse lease context containted in file open request
 * @open_req:	buffer containing smb2 file open(create) request
 * @lreq:	buffer to stored parsed lease state information
 *
 * Return:  oplock state, -ENOENT if create lease context not found
 */
struct lease_ctx_info *parse_lease_state(void *open_req)
{
	char *data_offset;
	struct create_context *cc;
	unsigned int next = 0;
	char *name;
	bool found = false;
	struct smb2_create_req *req = (struct smb2_create_req *)open_req;
	struct lease_ctx_info *lreq = kzalloc(sizeof(struct lease_ctx_info),
		GFP_KERNEL);
	if (!lreq)
		return NULL;

	data_offset = (char *)req + 4 + le32_to_cpu(req->CreateContextsOffset);
	cc = (struct create_context *)data_offset;
	do {
		cc = (struct create_context *)((char *)cc + next);
		name = le16_to_cpu(cc->NameOffset) + (char *)cc;
		if (le16_to_cpu(cc->NameLength) != 4 ||
				strncmp(name, SMB2_CREATE_REQUEST_LEASE, 4)) {
			next = le32_to_cpu(cc->Next);
			continue;
		}
		found = true;
		break;
	} while (next != 0);

	if (found) {
		struct create_lease *lc = (struct create_lease *)cc;
		*((u64 *)lreq->lease_key) = lc->lcontext.LeaseKeyLow;
		*((u64 *)(lreq->lease_key + 8)) = lc->lcontext.LeaseKeyHigh;
		lreq->req_state = lc->lcontext.LeaseState;
		lreq->flags = lc->lcontext.LeaseFlags;
		lreq->duration = lc->lcontext.LeaseDuration;
		return lreq;
	}

	return NULL;
}

/**
 * smb2_find_context_vals() - find a particular context info in open request
 * @open_req:	buffer containing smb2 file open(create) request
 * @str:	context name to search for
 *
 * Return:      pointer to requested context, NULL if @str context not found
 */
struct create_context *smb2_find_context_vals(void *open_req, char *str)
{
	char *data_offset;
	struct create_context *cc;
	unsigned int next = 0;
	char *name;
	bool found = false;
	struct smb2_create_req *req = (struct smb2_create_req *)open_req;
	int len;

	data_offset = (char *)req + 4 + le32_to_cpu(req->CreateContextsOffset);
	cc = (struct create_context *)data_offset;
	do {
		cc = (struct create_context *)((char *)cc + next);
		name = le16_to_cpu(cc->NameOffset) + (char *)cc;
		if (le16_to_cpu(cc->NameLength) < 4)
			return ERR_PTR(-EINVAL);

		len = strlen(str);
		if (strncmp(name, str, len)) {
			next = le32_to_cpu(cc->Next);
			continue;
		}
		found = 1;
		break;
	} while (next != 0);

	if (found)
		return cc;
	else
		return ERR_PTR(-ENOENT);
}

/**
 * create_durable_buf() - create durable handle context
 * @cc:	buffer to create durable context response
 */
void create_durable_rsp_buf(char *cc)
{
	struct create_durable_rsp *buf;

	buf = (struct create_durable_rsp *)cc;
	memset(buf, 0, sizeof(struct create_durable_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_durable_rsp, Data));
	buf->ccontext.DataLength = cpu_to_le32(8);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_durable_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* SMB2_CREATE_DURABLE_HANDLE_RESPONSE is "DHnQ" */
	buf->Name[0] = 'D';
	buf->Name[1] = 'H';
	buf->Name[2] = 'n';
	buf->Name[3] = 'Q';
}

/**
 * create_durable_buf() - create durable handle v2 context
 * @cc:	buffer to create durable context response
 */
void create_durable_v2_rsp_buf(char *cc, struct cifsd_file *fp)
{
	struct create_durable_v2_rsp *buf;

	buf = (struct create_durable_v2_rsp *)cc;
	memset(buf, 0, sizeof(struct create_durable_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_durable_rsp, Data));
	buf->ccontext.DataLength = cpu_to_le32(8);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_durable_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2 is "DH2Q" */
	buf->Name[0] = 'D';
	buf->Name[1] = 'H';
	buf->Name[2] = '2';
	buf->Name[3] = 'Q';

	buf->Timeout = fp->durable_timeout;
	if (fp->is_persistent)
		buf->Flags = SMB2_FLAGS_REPLAY_OPERATIONS;
}

/**
 * create_mxac_buf() - create query maximal access context
 * @cc:	buffer to create maximal access context response
 */
void create_mxac_rsp_buf(char *cc, int maximal_access)
{
	struct create_mxac_rsp *buf;

	buf = (struct create_mxac_rsp *)cc;
	memset(buf, 0, sizeof(struct create_mxac_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_mxac_rsp, QueryStatus));
	buf->ccontext.DataLength = cpu_to_le32(8);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_mxac_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE is "MxAc" */
	buf->Name[0] = 'M';
	buf->Name[1] = 'x';
	buf->Name[2] = 'A';
	buf->Name[3] = 'c';

	buf->QueryStatus = NT_STATUS_OK;
	buf->MaximalAccess = cpu_to_le32(maximal_access);
}

/**
 * create_mxac_buf() - create query maximal access context
 * @cc:	buffer to create query disk on id context response
 */
void create_disk_id_rsp_buf(char *cc, __u64 file_id, __u64 vol_id)
{
	struct create_disk_id_rsp *buf;

	buf = (struct create_disk_id_rsp *)cc;
	memset(buf, 0, sizeof(struct create_disk_id_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_disk_id_rsp, DiskFileId));
	buf->ccontext.DataLength = cpu_to_le32(32);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_mxac_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* SMB2_CREATE_QUERY_ON_DISK_ID_RESPONSE is "QFid" */
	buf->Name[0] = 'Q';
	buf->Name[1] = 'F';
	buf->Name[2] = 'i';
	buf->Name[3] = 'd';

	buf->DiskFileId = cpu_to_le64(file_id);
	buf->VolumeId = cpu_to_le64(vol_id);
}

/*
 * Find lease object(opinfo) for given lease key/fid from lease
 * break/file close path.
 */
/**
 * lookup_lease_in_table() - find a matching lease info object
 * @conn:	TCP server instance of connection
 * @lease_key:	lease key to be searched for
 *
 * Return:      opinfo if found matching opinfo, otherwise NULL
 */
struct oplock_info *lookup_lease_in_table(struct cifsd_tcp_conn *conn,
	char *lease_key)
{
	struct oplock_info *opinfo = NULL, *ret_op = NULL;
	struct lease_table *lt;
	int ret;

	list_for_each_entry(lt, &lease_table_list, l_entry) {
		if (memcmp(lt->client_guid, conn->ClientGUID,
			SMB2_CLIENT_GUID_SIZE))
			continue;
		list_for_each_entry(opinfo, &lt->lease_list, lease_entry) {
			if (!opinfo->op_state ||
				opinfo->op_state == OPLOCK_CLOSING)
				continue;
			if (!(opinfo->o_lease->state &
				(SMB2_LEASE_HANDLE_CACHING |
				SMB2_LEASE_WRITE_CACHING)))
				continue;
			ret = compare_guid_key(opinfo, conn->ClientGUID,
				lease_key);
			if (ret) {
				cifsd_debug("found opinfo\n");
				ret_op = opinfo;
				goto out;
			}
		}
	}

out:
	return ret_op;
}

int smb2_check_durable_oplock(struct cifsd_file *fp,
	struct lease_ctx_info *lctx, char *name)
{
	struct oplock_info *opinfo = fp->f_opinfo;

	if (opinfo && opinfo->is_lease) {
		if (!lctx) {
			cifsd_err("open does not include lease\n");
			return -EBADF;
		}
		if (memcmp(opinfo->o_lease->lease_key, lctx->lease_key,
					SMB2_LEASE_KEY_SIZE)) {
			cifsd_err("invalid lease key\n");
			return -EBADF;
		}
		if (name && strcmp(fp->filename, name)) {
			cifsd_err("invalid name reconnect %s\n", name);
			return -EINVAL;
		}
	}

	return 0;
}
#endif
