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
   ../nfs4/test1.c
   ../nfs4/test2.c
   ../nfs4/tc_test.c
   ../nfs4/tc_dist.c
   ../nfs4/tc_daemontest.c
)

########### next target ###############

SET(test1_SRCS
   test1.c
)

add_executable(test1
  ${test1_SRCS}
  ${fsal_CORE_SRCS}
  ../include/tc_user.h
)

target_link_libraries(test1
  MainServices
  ${PROTOCOLS}
  ${GANESHA_CORE}
  config_parsing
  ${LIBTIRPC_LIBRARIES}
  ${SYSTEM_LIBRARIES}
  m
  tc_util
)

SET(test2_SRCS
   test2.c
)

add_executable(test2
  ${test2_SRCS}
  ${fsal_CORE_SRCS}
  ../include/tc_utils.h
)

target_link_libraries(test2
  MainServices
  ${PROTOCOLS}
  ${GANESHA_CORE}
  config_parsing
  ${LIBTIRPC_LIBRARIES}
  ${SYSTEM_LIBRARIES}
  m
  tc_util
)

SET(tctest_SRCS
   tc_test.c
)

add_executable(cache_test
  ${tctest_SRCS}
  ${fsal_CORE_SRCS}
  ../include/tc_utils.h
)

target_link_libraries(cache_test
  MainServices
  ${PROTOCOLS}
  ${GANESHA_CORE}
  config_parsing
  ${LIBTIRPC_LIBRARIES}
  ${SYSTEM_LIBRARIES}
  m
  tc_util
)

SET(tcfiledist_SRCS
   tc_filedist.c
)

add_executable(tc_filedist
  ${tcfiledist_SRCS}
  ${fsal_CORE_SRCS}
  ../include/tc_utils.h
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
)

SET(tc_singlefile_SRCS
   tc_singlefile.c
)

add_executable(tc_singlefile
  ${tc_singlefile_SRCS}
  ${fsal_CORE_SRCS}
  ../include/tc_utils.h
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
)

########### install files ###############

# We are still missing the install of docs and stuff
