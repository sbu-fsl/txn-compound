/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright CEA/DAM/DIF  (2008)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * ---------------------------------------
 */

/**
 * @file  nfs_init.c
 * @brief Most of the init routines
 */
#include "config.h"
#include "ganesha_rpc.h"
#include "nfs_init.h"
#include "log.h"
#include "fsal.h"
#include "nfs23.h"
#include "nfs4.h"
#include "mount.h"
#include "nlm4.h"
#include "rquota.h"
#include "nfs_core.h"
#include "cache_inode.h"
#include "cache_inode_lru.h"
#include "nfs_file_handle.h"
#include "nfs_exports.h"
#include "nfs_proto_functions.h"
#include "nfs_dupreq.h"
#include "config_parsing.h"
#include "nfs4_acls.h"
#include "nfs_rpc_callback.h"
#ifdef USE_DBUS
#include "ganesha_dbus.h"
#endif
#ifdef _USE_CB_SIMULATOR
#include "nfs_rpc_callback_simulator.h"
#endif
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include "nlm_util.h"
#include "nsm.h"
#include "sal_functions.h"
#include "fridgethr.h"
#include "idmapper.h"
#include "delayed_exec.h"
#include "client_mgr.h"
#include "export_mgr.h"
#ifdef USE_CAPS
#include <sys/capability.h>	/* For capget/capset */
#endif
#include "uid2grp.h"


/* global information exported to all layers (as extern vars) */
nfs_parameter_t nfs_param;

/* ServerEpoch is ServerBootTime unless overriden by -E command line option */
struct timespec ServerBootTime;
time_t ServerEpoch;

verifier4 NFS4_write_verifier;	/* NFS V4 write verifier */
writeverf3 NFS3_write_verifier;	/* NFS V3 write verifier */

/* node ID used to identify an individual node in a cluster */
ushort g_nodeid = 0;

nfs_start_info_t nfs_start_info;

pthread_t admin_thrid;
pthread_t sigmgr_thrid;
pthread_t gsh_dbus_thrid;

char *config_path = "/etc/ganesha/ganesha.conf";

char *pidfile_path = "/var/run/ganesha.pid";

/**
 * @brief This thread is in charge of signal management
 *
 * @param[in] UnusedArg Unused
 *
 * @return NULL.
 */
void *sigmgr_thread(void *UnusedArg)
{
	SetNameFunction("sigmgr");
	int signal_caught = 0;

	/* Loop until we catch SIGTERM */
	while (signal_caught != SIGTERM) {
		sigset_t signals_to_catch;
		sigemptyset(&signals_to_catch);
		sigaddset(&signals_to_catch, SIGTERM);
		sigaddset(&signals_to_catch, SIGHUP);
		if (sigwait(&signals_to_catch, &signal_caught) != 0) {
			LogFullDebug(COMPONENT_THREAD,
				     "sigwait exited with error");
			continue;
		}
		if (signal_caught == SIGHUP) {
			LogEvent(COMPONENT_MAIN,
				 "SIGHUP_HANDLER: Received SIGHUP.... initiating export list reload");
			admin_replace_exports();
			reread_log_config(config_path);
			svcauth_gss_release_cred();
		}
	}
	LogDebug(COMPONENT_THREAD, "sigmgr thread exiting");

	admin_halt();

	/* Might as well exit - no need for this thread any more */
	return NULL;
}

/**
 * @brief Initialize NFSd prerequisites
 *
 * @param[in] program_name Name of the program
 * @param[in] host_name    Server host name
 * @param[in] debug_level  Debug level
 * @param[in] log_path     Log path
 */
void nfs_prereq_init(const char *program_name, const char *host_name,
		     int debug_level, const char *log_path)
{
	/* Initialize logging */
	SetNamePgm(program_name);
	SetNameFunction("main");
	SetNameHost(host_name);

	init_logging(log_path, debug_level);
}

/**
 * @brief Load parameters from config file
 *
 * @param[in]  config_struct Parsed config file
 * @param[out] p_start_info  Startup parameters
 *
 * @return -1 on failure.
 */
int nfs_set_param_from_conf(config_file_t parse_tree,
			    nfs_start_info_t *p_start_info)
{
	struct config_error_type err_type;

	/*
	 * Initialize exports and clients so config parsing can use them
	 * early.
	 */
	client_pkginit();
	export_pkginit();

	/* Core parameters */
	(void) load_config_from_parse(parse_tree,
				    &nfs_core,
				    &nfs_param.core_param,
				    true,
				    &err_type);
	if (!config_error_is_harmless(&err_type)) {
		LogCrit(COMPONENT_INIT,
			"Error while parsing core configuration");
		return -1;
	}

	/* Worker paramters: ip/name hash table and expiration for each entry */
	(void) load_config_from_parse(parse_tree,
				    &nfs_ip_name,
				    NULL,
				    true,
				    &err_type);
	if (!config_error_is_harmless(&err_type)) {
		LogCrit(COMPONENT_INIT,
			"Error while parsing IP/name configuration");
		return -1;
	}

#ifdef _HAVE_GSSAPI
	/* NFS kerberos5 configuration */
	(void) load_config_from_parse(parse_tree,
				    &krb5_param,
				    &nfs_param.krb5_param,
				    true,
				    &err_type);
	if (!config_error_is_harmless(&err_type)) {
		LogCrit(COMPONENT_INIT,
			"Error while parsing NFS/KRB5 configuration for RPCSEC_GSS");
		return -1;
	}
#endif

	/* NFSv4 specific configuration */
	(void) load_config_from_parse(parse_tree,
				    &version4_param,
				    &nfs_param.nfsv4_param,
				    true,
				    &err_type);
	if (!config_error_is_harmless(&err_type)) {
		LogCrit(COMPONENT_INIT,
			"Error while parsing NFSv4 specific configuration");
		return -1;
	}

	/* Cache inode client parameters */
	(void) load_config_from_parse(parse_tree,
				    &cache_inode_param_blk,
				    NULL,
				    true,
				    &err_type);
	if (!config_error_is_harmless(&err_type)) {
		LogCrit(COMPONENT_INIT,
			"Error while parsing 9P specific configuration");
		return -1;
	}

	LogEvent(COMPONENT_INIT, "Configuration file successfully parsed");

	return 0;
}

int init_server_pkgs(void)
{
	cache_inode_status_t cache_status;
	state_status_t state_status;

	/* init uid2grp cache */
	uid2grp_cache_init();

	/* Cache Inode Initialisation */
	cache_status = cache_inode_init();
	if (cache_status != CACHE_INODE_SUCCESS) {
		LogCrit(COMPONENT_INIT,
			"Cache Inode Layer could not be initialized, status=%s",
			cache_inode_err_str(cache_status));
		return -1;
	}

	state_status = state_lock_init();
	if (state_status != STATE_SUCCESS) {
		LogCrit(COMPONENT_INIT,
			"State Lock Layer could not be initialized, status=%s",
			state_err_str(state_status));
		return -1;
	}
	LogInfo(COMPONENT_INIT, "Cache Inode library successfully initialized");

	/* Init the IP/name cache */
	LogDebug(COMPONENT_INIT, "Now building IP/name cache");
	if (nfs_Init_ip_name() != IP_NAME_SUCCESS) {
		LogCrit(COMPONENT_INIT,
			"Error while initializing IP/name cache");
		return -1;
	}
	LogInfo(COMPONENT_INIT, "IP/name cache successfully initialized");

	LogEvent(COMPONENT_INIT, "Initializing ID Mapper.");
	if (!idmapper_init()) {
		LogCrit(COMPONENT_INIT, "Failed initializing ID Mapper.");
		return -1;
	}
	LogEvent(COMPONENT_INIT, "ID Mapper successfully initialized.");
	return 0;
}

/**
 *  * @brief Init the nfs daemon
 *   *
 *    * @param[in] p_start_info Unused
 *     */

static void nfs_Init(const nfs_start_info_t *p_start_info)
{

	create_pseudofs();

	LogInfo(COMPONENT_INIT,
			"NFSv4 pseudo file system successfully initialized");

}

#ifdef USE_CAPS
/**
 * @brief Lower my capabilities (privs) so quotas work right
 *
 * This will/should be moved to set_credentials where it belongs
 * Deal with capabilities in order to remove CAP_SYS_RESOURCE (needed
 * for proper management of data quotas)
 */

static void lower_my_caps(void)
{
	struct __user_cap_header_struct caphdr = {
		.version = _LINUX_CAPABILITY_VERSION
	};
	cap_user_data_t capdata;
	ssize_t capstrlen = 0;
	cap_t my_cap;
	char *cap_text;
	int capsz;

	(void) capget(&caphdr, NULL);
	switch (caphdr.version) {
	case _LINUX_CAPABILITY_VERSION_1:
		capsz = _LINUX_CAPABILITY_U32S_1;
		break;
	case _LINUX_CAPABILITY_VERSION_2:
		capsz = _LINUX_CAPABILITY_U32S_2;
		break;
	default:
		abort(); /* can't happen */
	}

	capdata = gsh_calloc(capsz, sizeof(struct __user_cap_data_struct));
	caphdr.pid = getpid();

	if (capget(&caphdr, capdata) != 0)
		LogFatal(COMPONENT_INIT,
			 "Failed to query capabilities for process, errno=%u",
			 errno);

	/* Set the capability bitmask to remove CAP_SYS_RESOURCE */
	if (capdata->effective & CAP_TO_MASK(CAP_SYS_RESOURCE))
		capdata->effective &= ~CAP_TO_MASK(CAP_SYS_RESOURCE);

	if (capdata->permitted & CAP_TO_MASK(CAP_SYS_RESOURCE))
		capdata->permitted &= ~CAP_TO_MASK(CAP_SYS_RESOURCE);

	if (capdata->inheritable & CAP_TO_MASK(CAP_SYS_RESOURCE))
		capdata->inheritable &= ~CAP_TO_MASK(CAP_SYS_RESOURCE);

	if (capset(&caphdr, capdata) != 0)
		LogFatal(COMPONENT_INIT,
			 "Failed to set capabilities for process, errno=%u",
			 errno);
	else
		LogEvent(COMPONENT_INIT,
			 "CAP_SYS_RESOURCE was successfully removed for proper quota management in FSAL");

	/* Print newly set capabilities (same as what CLI "getpcaps" displays */
	my_cap = cap_get_proc();
	cap_text = cap_to_text(my_cap, &capstrlen);
	LogEvent(COMPONENT_INIT, "currenty set capabilities are: %s",
		 cap_text);
	cap_free(cap_text);
	cap_free(my_cap);
	gsh_free(capdata);
}
#endif

