/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Stony Brook University, 2014
 * Author: Ming Chen, v.mingchen@gmail.com
 *
 * Copyright (C) Panasas Inc., 2011
 * Author: Jim Lieb jlieb@panasas.com
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * -------------
 */

/* main.c
 * Module core functions
 */

#include "config.h"

#include "fsal.h"
#include <libgen.h>		/* used for 'dirname' */
#include <pthread.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include "FSAL/fsal_init.h"
#include "secnfs_methods.h"
#include "secnfs.h"

/* defined the set of attributes supported with POSIX */
#define SECNFS_SUPPORTED_ATTRIBUTES (                                       \
          ATTR_TYPE     | ATTR_SIZE     |                  \
          ATTR_FSID     | ATTR_FILEID   |                  \
          ATTR_MODE     | ATTR_NUMLINKS | ATTR_OWNER     | \
          ATTR_GROUP    | ATTR_ATIME    | ATTR_RAWDEV    | \
          ATTR_CTIME    | ATTR_MTIME    | ATTR_SPACEUSED | \
          ATTR_CHGTIME  )

const char myname[] = "SECNFS";

/* filesystem info for SECNFS */
static struct fsal_staticfsinfo_t default_posix_info = {
	.maxfilesize = 0xFFFFFFFFFFFFFFFFLL,	/* (64bits) */
	.maxlink = _POSIX_LINK_MAX,
	.maxnamelen = 1024,
	.maxpathlen = 1024,
	.no_trunc = true,
	.chown_restricted = true,
	.case_insensitive = false,
	.case_preserving = true,
	.link_support = true,
	.symlink_support = true,
	.lock_support = true,
	.lock_support_owner = false,
	.lock_support_async_block = false,
	.named_attr = true,
	.unique_handles = true,
	.lease_time = {10, 0},
	.acl_support = FSAL_ACLSUPPORT_ALLOW,
	.cansettime = true,
	.homogenous = true,
	.supported_attrs = SECNFS_SUPPORTED_ATTRIBUTES,
	.maxread = 0,
	.maxwrite = 0,
	.umask = 0,
	.auth_exportpath_xdev = false,
	.xattr_access_rights = 0400,	/* root=RW, owner=R */
};

/************** private helper for export object *******************/

struct fsal_staticfsinfo_t *secnfs_staticinfo(struct fsal_module *hdl)
{
	struct secnfs_fsal_module *myself;

	myself = container_of(hdl, struct secnfs_fsal_module, fsal);
	return &myself->fs_info;
}

/************************ Module methods **************************/

// XXX fsal_init_info_t is removed in a3595873380
// TODO how to load in 2.1
/*
static int secnfs_init_params(const char *key, const char *val,
			      fsal_init_info_t *info, const char *name)
{
        struct secnfs_fsal_module *secnfs = container_of(
                        fsal, struct secnfs_fsal_module, fsal);
        secnfs_info_t *secnfs_info = &secnfs->secnfs_info;

        if (!strcasecmp(key, "Context_Cache_File")) {
                strncpy(secnfs_info->context_cache_file, val, MAXPATHLEN);
        } else if (!strcasecmp(key, "Create_If_No_Context")) {
                secnfs_info->create_if_no_context = str_to_bool(val);
        } else if (!strcasecmp(key, "Name")) {
                strncpy(secnfs_info->secnfs_name, val, MAXPATHLEN);
        } else if (!strcasecmp(key, "Proxy_Lists")) {
                strncpy(secnfs_info->plist_file, val, MAXPATHLEN);
        } else {
		LogCrit(COMPONENT_CONFIG, "Unknown key: %s in %s", key, name);
		return 1;
        }

        return 0;
}
*/


static int validate_conf_params(const secnfs_info_t *info)
{
        if (!info->context_cache_file) {
                LogCrit(COMPONENT_CONFIG, "'Context_Cache_File' not set");
                return 0;
        }

        if (!access(info->context_cache_file, F_OK)
                        && !info->create_if_no_context) {
                LogCrit(COMPONENT_CONFIG, "cannot access '%s'",
                        info->context_cache_file);
                return 0;
        }

        return 1;
}


/*
 * must be called with a reference taken (via lookup_fsal)
 */
static fsal_status_t init_config(struct fsal_module *fsal_hdl,
				 config_file_t config_struct)
{
	struct secnfs_fsal_module *secnfs_me = secnfs_module(fsal_hdl);
        secnfs_info_t *info = &secnfs_me->secnfs_info;
	fsal_status_t st;

	secnfs_me->fs_info = default_posix_info;	/* get a copy of the defaults */

	/* if we have fsal specific params, do them here
	 * fsal_hdl->name is used to find the block containing the
	 * params.
	 */
        // XXX fsal_load_config is removed git show 1b81f1e
        /*
        st = fsal_load_config(fsal_hdl->ops->get_name(fsal_hdl), config_struct,
                              &secnfs_me->fsal_info, &secnfs_me->fs_info,
                              secnfs_init_params);
	if (FSAL_IS_ERROR(st)) {
                LogCrit(COMPONENT_FSAL, "cannot load SECNFS config");
		return st;
        }
        */

        SECNFS_F("Context_Cache_File = %s", info->context_cache_file);
        SECNFS_F("secnfs_name = %s", info->secnfs_name);
        SECNFS_F("create_if_no_context = %d", info->create_if_no_context);

        if (!validate_conf_params(info)) {
                SECNFS_ERR("invalid SECNFS config");
                return fsalstat(ERR_FSAL_INVAL, SECNFS_WRONG_CONFIG);
        }

        if (secnfs_init_info(info) != SECNFS_OKAY) {
                SECNFS_ERR("SECNFS failed to created context");
                return fsalstat(ERR_FSAL_NOMEM, ENOMEM);
        }

	display_fsinfo(&secnfs_me->fs_info);
	LogFullDebug(COMPONENT_FSAL,
		     "Supported attributes constant = 0x%" PRIx64,
		     (uint64_t) SECNFS_SUPPORTED_ATTRIBUTES);
	LogFullDebug(COMPONENT_FSAL,
		     "Supported attributes default = 0x%" PRIx64,
		     default_posix_info.supported_attrs);
	LogDebug(COMPONENT_FSAL,
		 "FSAL INIT: Supported attributes mask = 0x%" PRIx64,
		 secnfs_me->fs_info.supported_attrs);
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/* Internal SECNFS method linkage to export object
 */

fsal_status_t secnfs_create_export(struct fsal_module * fsal_hdl,
				   void *parse_node,
				   const struct fsal_up_vector * up_ops);

/* Module initialization.
 * Called by dlopen() to register the module
 * keep a private pointer to me in myself
 */

/* my module private storage
 */

static struct secnfs_fsal_module SECNFS;

/* TODO make it a per-export variable? Then, we need to call fsal_export_init
 * to initialize each struct next_ops. */
struct next_ops next_ops;

/* linkage to the exports and handle ops initializers
 */

MODULE_INIT void secnfs_init(void)
{
	int retval;
	struct fsal_module *myself = &SECNFS.fsal;

	retval = register_fsal(myself, myname, FSAL_MAJOR_VERSION,
			       FSAL_MINOR_VERSION, FSAL_ID_SECNFS);
	if (retval != 0) {
		fprintf(stderr, "SECNFS module failed to register");
		return;
	}
	myself->ops->create_export = secnfs_create_export;
	myself->ops->init_config = init_config;
	init_fsal_parameters(&SECNFS.fsal_info);
	SECNFS_D("secnfs module initialized.");
}

MODULE_FINI void secnfs_unload(void)
{
	int retval;

	retval = unregister_fsal(&SECNFS.fsal);
	if (retval != 0) {
		fprintf(stderr, "SECNFS module failed to unregister");
		return;
	}

        secnfs_destroy_context(&SECNFS.secnfs_info);
}
