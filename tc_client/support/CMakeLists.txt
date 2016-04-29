include_directories(
  ${LIBTIRPC_INCLUDE_DIR}
)

if(USE_DBUS)
  include_directories(
    ${DBUS_INCLUDE_DIRS}
    )
endif(USE_DBUS)

# string utilities.  This should eventually go into src/os
# because BSD has them and Linux doesn't

set(string_utils_STAT_SRCS
   strlcpy.c
   strnlen.c
)

add_library(string_utils STATIC ${string_utils_STAT_SRCS})
set_target_properties(string_utils PROPERTIES POSITION_INDEPENDENT_CODE on)

# hash function libraries

set(hash_SRCS
   murmur3.c
   city.c
)

add_library(hash STATIC ${hash_SRCS})
set_target_properties(hash PROPERTIES POSITION_INDEPENDENT_CODE on)

SET(hashtable_STAT_SRCS
   hashtable.c
)

add_library(hashtable STATIC ${hashtable_STAT_SRCS})
set_target_properties(hashtable PROPERTIES POSITION_INDEPENDENT_CODE on)

SET(avltree_STAT_SRCS
   avl.c
   bst.c
   rb.c
   splay.c
)

add_library(avltree STATIC ${avltree_STAT_SRCS})
set_target_properties(avltree PROPERTIES POSITION_INDEPENDENT_CODE on)

# uid2grp mapper
set( uid2grp_SRCS
     uid2grp.c
     uid2grp_cache.c
)

add_library(uid2grp ${uid2grp_SRCS})
set_target_properties(uid2grp PROPERTIES POSITION_INDEPENDENT_CODE on)

set(tc_helper_SRCS tc_helper.c)
add_library(tc_helper STATIC ${tc_helper_SRCS})

########### next target ###############

SET(support_STAT_SRCS
   nfs4_acls.c
   nfs_creds.c
   nfs_filehandle_mgmt.c
   nfs_read_conf.c
   nfs_convert.c
   nfs_ip_name.c
   exports.c
   fridgethr.c
   delayed_exec.c
   misc.c
   bsd-base64.c
   server_stats.c
   export_mgr.c
)

if(ERROR_INJECTION)
  set(support_STAT_SRCS
    ${support_STAT_SRCS}
    err_inject.c
    )
endif(ERROR_INJECTION)

if(APPLE)
  set(support_STAT_SRCS
    ${support_STAT_SRCS}
    misc.c
    )
endif(APPLE)

add_library(support STATIC ${support_STAT_SRCS})
target_link_libraries(support hashtable avltree nfsproto)
set_target_properties(support PROPERTIES POSITION_INDEPENDENT_CODE on)

########### install files ###############
