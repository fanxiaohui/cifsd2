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

#ifndef __USER_MANAGEMENT_H__
#define __USER_MANAGEMENT_H__

#include "../glob.h"  /* FIXME */

#define UF_GUEST_ACCOUNT	(1 << 0)
#define UF_PENDING_REMOVAL	(1 << 1)

struct cifsd_user {
	unsigned short		status;

	char			*name;
	
	size_t			passkey_sz;
	char			*passkey;

	unsigned int		uid;
	unsigned int		gid;
};

static inline bool user_guest(struct cifsd_user *user)
{
	return user->status & UF_GUEST_ACCOUNT;
}

static inline void set_user_guest(struct cifsd_user *user)
{
	user->status |= UF_GUEST_ACCOUNT;
}

static inline char *user_passkey(struct cifsd_user *user)
{
	return user->passkey;
}

static inline char *user_name(struct cifsd_user *user)
{
	return user->name;
}

static inline unsigned int user_uid(struct cifsd_user *user)
{
	return user->uid;
}

static inline unsigned int user_gid(struct cifsd_user *user)
{
	return user->gid;
}


struct cifsd_user *cifsd_alloc_user(const char *account);
void cifsd_free_user(struct cifsd_user *user);


/* TO BE REMOVED */

void put_cifsd_user(struct cifsd_user *user);
unsigned short alloc_smb1_vuid(void);
void free_smb1_vuid(unsigned short uid);
struct cifsd_user *um_user_search(char *name);
struct cifsd_user *um_user_search_guest(void);
int um_add_new_user(char *name, char *pass, kuid_t uid, kgid_t gid);
int um_delete_user(char *name);
void um_cleanup_users(void);
size_t um_users_show(char *buf, size_t sz);

#endif /* __USER_MANAGEMENT_H__ */
