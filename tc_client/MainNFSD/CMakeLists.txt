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

########### next target ###############

SET(tc_seq_SRCS
   tc_seq.c
)

add_executable(tc_seq
  ${tc_seq_SRCS}
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

function (add_tc_binary Name)
  add_executable(${Name} "${Name}.c")
  target_link_libraries(${Name}
    tc_impl
    tc_impl_nfs4
    tc_impl_posix
    tc_util
    MainServices
    ${PROTOCOLS}
    ${GANESHA_CORE}
    config_parsing
    path_utils
    ${LIBTIRPC_LIBRARIES}
    ${SYSTEM_LIBRARIES}
    m
  )
endfunction (add_tc_binary)

add_tc_binary(tc_test_read)
add_tc_binary(tc_test_mkdir)
add_tc_binary(tc_test_mkdirs)
