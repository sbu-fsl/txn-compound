/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Max Matveev, 2012
 *
 * Copyright CEA/DAM/DIF  (2008)
 *
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "fsal.h"
#include "FSAL/fsal_init.h"
#include "fs_fsal_methods.h"

/* defined the set of attributes supported with POSIX */
#define SUPPORTED_ATTRIBUTES (                                       \
		ATTR_TYPE     | ATTR_SIZE     |			     \
		ATTR_FSID     | ATTR_FILEID   |			     \
		ATTR_MODE     | ATTR_NUMLINKS | ATTR_OWNER     |     \
		ATTR_GROUP    | ATTR_ATIME    | ATTR_RAWDEV    |     \
		ATTR_CTIME    | ATTR_MTIME    | ATTR_SPACEUSED |     \
		ATTR_CHGTIME)

/* filesystem info for PROXY */
static struct fsal_staticfsinfo_t kern_info = {
	.maxfilesize = UINT64_MAX,
	.maxlink = _POSIX_LINK_MAX,
	.maxnamelen = 1024,
	.maxpathlen = 1024,
	.no_trunc = true,
	.chown_restricted = true,
	.case_preserving = true,
	.lock_support = true,
	.named_attr = true,
	.unique_handles = true,
	.lease_time = {10, 0},
	.acl_support = FSAL_ACLSUPPORT_ALLOW,
	.homogenous = true,
	.supported_attrs = SUPPORTED_ATTRIBUTES,
};

#ifdef _USE_GSSRPC
static struct config_item_list sec_types[] = {
	CONFIG_LIST_TOK("krb5", RPCSEC_GSS_SVC_NONE),
	CONFIG_LIST_TOK("krb5i", RPCSEC_GSS_SVC_INTEGRITY),
	CONFIG_LIST_TOK("krb5p", RPCSEC_GSS_SVC_PRIVACY),
	CONFIG_LIST_EOL
};
#endif

static struct config_item kern_client_params[] = {
	CONF_ITEM_UI32("Retry_SleepTime", 0, 60, 10,
		       fs_client_params, retry_sleeptime),
	CONF_ITEM_IPV4_ADDR("Srv_Addr", "127.0.0.1",
			    fs_client_params, srv_addr),
	CONF_ITEM_UI32("NFS_Service", 0, UINT32_MAX, 100003,
		       fs_client_params, srv_prognum),
	CONF_ITEM_UI32("NFS_SendSize", 512, FSAL_MAXIOSIZE, 32768,
		       fs_client_params, srv_sendsize),
	CONF_ITEM_UI32("NFS_RecvSize", 512, FSAL_MAXIOSIZE, 32768,
		       fs_client_params, srv_recvsize),
	CONF_ITEM_INET_PORT("NFS_Port", 0, UINT16_MAX, 2049,
			    fs_client_params, srv_port),
	CONF_ITEM_BOOL("Use_Privileged_Client_Port", false,
		       fs_client_params, use_privileged_client_port),
	CONF_ITEM_UI32("RPC_Client_Timeout", 1, 60*4, 60,
		       fs_client_params, srv_timeout),
#ifdef _USE_GSSRPC
	CONF_ITEM_STR("Remote_PrincipalName", 0, MAXNAMLEN, NULL,
		      fs_client_params, remote_principal),
	CONF_ITEM_STR("KeytabPath", 0, MAXPATHLEN, "/etc/krb5.keytab"
		      fs_client_params, keytab),
	CONF_ITEM_UI32("Credential_LifeTime", 0, 86400*2, 86400,
		       fs_client_params, cred_lifetime),
	CONF_ITEM_ENUM("Sec_Type", RPCSEC_GSS_SVC_NONE, sec_types,
		       fs_client_params, sec_type),
	CONF_ITEM_BOOL("Active_krb5", false,
		       fs_client_params, active_krb5),
#endif
#ifdef PROXY_HANDLE_MAPPING
	CONF_ITEM_BOOL("Enable_Handle_Mapping", false,
		       fs_client_params, enable_handle_mapping),
	CONF_ITEM_STR("HandleMap_DB_Dir", 0, MAXPATHLEN,
		      "/var/ganesha/handlemap",
		      fs_client_params, hdlmap.databases_directory),
	CONF_ITEM_STR("HandleMap_Tmp_Dir", 0, MAXPATHLEN,
		      "/var/ganesha/tmp",
		      fs_client_params, hdlmap.temp_directory),
	CONF_ITEM_UI32("HandleMap_DB_Count", 1, 16, 8,
		       fs_client_params, hdlmap.database_count),
	CONF_ITEM_UI32("HandleMap_HashTable_Size", 1, 127, 103,
		       fs_client_params, hdlmap.hashtable_size),
#endif
	CONFIG_EOL
};


/**
 * @brief Validate and commit the kern params
 *
 * This is also pretty simple.  Just a NOP in both cases.
 *
 * @param link_mem - pointer to the link_mem struct memory.
 * @param self_struct - NULL for init parent, not NULL for attaching
 */

static struct config_item kern_params[] = {
	CONF_ITEM_BOOL("link_support", true,
		       fs_fsal_module, fsinfo.link_support),
	CONF_ITEM_BOOL("symlink_support", true,
		       fs_fsal_module, fsinfo.symlink_support),
	CONF_ITEM_BOOL("cansettime", true,
		       fs_fsal_module, fsinfo.cansettime),
	CONF_ITEM_UI64("maxread", 512, FSAL_MAXIOSIZE, FSAL_MAXIOSIZE,
		       fs_fsal_module, fsinfo.maxread),
	CONF_ITEM_UI64("maxwrite", 512, FSAL_MAXIOSIZE, FSAL_MAXIOSIZE,
		       fs_fsal_module, fsinfo.maxwrite),
	CONF_ITEM_MODE("umask", 0, 0777, 0,
		       fs_fsal_module, fsinfo.umask),
	CONF_ITEM_BOOL("auth_xdev_export", false,
		       fs_fsal_module, fsinfo.auth_exportpath_xdev),
	CONF_ITEM_MODE("xattr_access_rights", 0, 0777, 0400,
		       fs_fsal_module, fsinfo.xattr_access_rights),
	CONF_ITEM_BLOCK("remote_server", kern_client_params,
			noop_conf_init, noop_conf_commit,
			fs_fsal_module, special), /*fake filler */
	CONFIG_EOL
};

struct config_block kern_param = {
	.dbus_interface_name = "org.ganesha.nfsd.config.fsal.kern",
	.blk_desc.name = "TCNFS",
	.blk_desc.type = CONFIG_BLOCK,
	.blk_desc.u.blk.init = noop_conf_init,
	.blk_desc.u.blk.params = kern_params,
	.blk_desc.u.blk.commit = noop_conf_commit
};


static fsal_status_t fs_init_config(struct fsal_module *fsal_hdl,
				     config_file_t config_struct)
{
	struct config_error_type err_type;
	int rc;
	struct fs_fsal_module *fs =
	    container_of(fsal_hdl, struct fs_fsal_module, module);

	fs->fsinfo = kern_info;
	(void) load_config_from_parse(config_struct,
				      &kern_param,
				      fs,
				      true,
				      &err_type);
	if (!config_error_is_harmless(&err_type))
		return fsalstat(ERR_FSAL_INVAL, 0);

#ifdef PROXY_HANDLE_MAPPING
	rc = HandleMap_Init(&fs->special.hdlmap);
	if (rc < 0)
		return fsalstat(ERR_FSAL_INVAL, -rc);
#endif

	rc = fs_init_rpc(fs);
	if (rc)
		return fsalstat(ERR_FSAL_FAULT, rc);
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static struct fs_fsal_module TCNFS;

MODULE_INIT void fs_init(void)
{
	if (register_fsal(&TCNFS.module, "TCNFS", FSAL_MAJOR_VERSION,
			  FSAL_MINOR_VERSION, FSAL_ID_NO_PNFS) != 0)
		return;
	TCNFS.module.ops->init_config = fs_init_config;
	TCNFS.module.ops->create_export = fs_create_export;
}

MODULE_FINI void fs_unload(void)
{
	int retval;

	retval = unregister_fsal(&TCNFS.module);
	if (retval != 0) {
		fprintf(stderr, "TCNFS module failed to unregister");
		return;
	}
	free_io_contexts();
}
