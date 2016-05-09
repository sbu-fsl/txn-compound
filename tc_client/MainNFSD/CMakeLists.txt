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

########### install files ###############

# We are still missing the install of docs and stuff
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
    tc_helper
    ${LIBTIRPC_LIBRARIES}
    ${SYSTEM_LIBRARIES}
    m
  )
endfunction (add_tc_binary)

add_tc_binary(tc_seq)
add_tc_binary(tc_filedist)
add_tc_binary(tc_singlefile)
add_tc_binary(tc_test_open)
add_tc_binary(tc_test_openread)

add_tc_binary(tc_test_read)
add_tc_binary(tc_test_write)
add_tc_binary(tc_test_mkdir)
add_tc_binary(tc_test_mkdirs)
add_tc_binary(tc_test_listdirs)
add_tc_binary(tc_test_remove)
add_tc_binary(tc_test_rename)
add_tc_binary(tc_test_append)
add_tc_binary(tc_test_copy)
