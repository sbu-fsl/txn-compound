add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

include_directories(
  ${LIBTIRPC_INCLUDE_DIR}
)

if(USE_DBUS)
  include_directories(
    ${DBUS_INCLUDE_DIRS}
    )
endif(USE_DBUS)

########### next target ###############

SET(MainServices_STAT_SRCS
   nfs_admin_thread.c
   nfs_rpc_callback.c
   nfs_worker_thread.c
   nfs_rpc_dispatcher_thread.c
   nfs_init.c
   ../support/client_mgr.c
)

add_library(MainServices STATIC ${MainServices_STAT_SRCS})

# FSAL core sources
# fsal_manager and fsal_destroyer are the only objects referenced by the
# core server all the rest are for the common support of fsal plugins.
# we put them here in the core rather than in a lib so that they are always
# present and available for runtime linkage.

set(fsal_CORE_SRCS
   ../FSAL/fsal_convert.c
   ../FSAL/commonlib.c
   ../FSAL/fsal_manager.c
   ../FSAL/access_check.c
   ../FSAL/fsal_config.c
   ../FSAL/default_methods.c
   ../FSAL/common_pnfs.c
   ../FSAL/fsal_destroyer.c
   ../FSAL_UP/fsal_up_top.c
   ../FSAL_UP/fsal_up_async.c
   ../FSAL_UP/fsal_up_utils.c
   ../nfs4/handle.c
   ../nfs4/tc_utils.c
   ../nfs4/tc_seq.c
   ../nfs4/tc_dist.c
   ../nfs4/tc_daemontest.c
)

########### next target ###############

SET(tc_seq_SRCS
   tc_seq.c
)

add_executable(tc_seq
  ${tc_seq_SRCS}
  ${fsal_CORE_SRCS}
)

target_link_libraries(tc_seq
  MainServices
  ${PROTOCOLS}
  ${GANESHA_CORE}
  config_parsing
  ${LIBTIRPC_LIBRARIES}
  ${SYSTEM_LIBRARIES}
  m
  tc_util
  tc_impl_nfs4
)

SET(tcfiledist_SRCS
   tc_filedist.c
)

add_executable(tc_filedist
  ${tcfiledist_SRCS}
  ${fsal_CORE_SRCS}
)

target_link_libraries(tc_filedist
  MainServices
  ${PROTOCOLS}
  ${GANESHA_CORE}
  config_parsing
  ${LIBTIRPC_LIBRARIES}
  ${SYSTEM_LIBRARIES}
  m
  tc_util
  tc_impl_nfs4
)

SET(tc_singlefile_SRCS
   tc_singlefile.c
)

add_executable(tc_singlefile
  ${tc_singlefile_SRCS}
  ${fsal_CORE_SRCS}
)

target_link_libraries(tc_singlefile
  MainServices
  ${PROTOCOLS}
  ${GANESHA_CORE}
  config_parsing
  ${LIBTIRPC_LIBRARIES}
  ${SYSTEM_LIBRARIES}
  m
  tc_util
  tc_impl_nfs4
)

SET(tc_daemon_SRCS
   tc_daemon.c
)

add_executable(tc_daemon
  ${tc_daemon_SRCS}
  ${fsal_CORE_SRCS}
)

target_link_libraries(tc_daemon
  MainServices
  ${PROTOCOLS}
  ${GANESHA_CORE}
  config_parsing
  ${LIBTIRPC_LIBRARIES}
  ${SYSTEM_LIBRARIES}
  m
  tc_util
  tc_impl_nfs4
)

########### install files ###############

# We are still missing the install of docs and stuff
