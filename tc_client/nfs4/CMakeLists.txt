add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

########### next target ###############

set(LIB_PREFIX 64)
SET(fsalproxy_LIB_SRCS
   handle.c
   fs.c
   export.c
   xattrs.c
)

add_library(fsalproxy SHARED ${fsalproxy_LIB_SRCS} ${fsal_CORE_SRCS})
target_link_libraries(fsalproxy ntirpc ${SYSTEM_LIBRARIES})
set_target_properties(fsalproxy PROPERTIES VERSION 4.2.0 SOVERSION 4)
set_target_properties(fsalproxy PROPERTIES POSITION_INDEPENDENT_CODE on)
install(TARGETS fsalproxy COMPONENT fsal DESTINATION  ${FSAL_DESTINATION} )


SET(tc_impl_nfs4_SRCS
   tc_impl_nfs4.c
)

add_library(tc_impl_nfs4 STATIC ${tc_impl_nfs4_SRCS})

#target_link_libraries(tc_impl_nfs4
		      #${SYSTEM_LIBRARIES}
		      #${LIBTIRPC_LIBRARIES}
		      #support
                      #tc_util
		      #MainServices
                      #m)

#set_target_properties(tc_impl_nfs4 PROPERTIES VERSION 4.2.0 SOVERSION 4)
#install(TARGETS tc_impl_nfs4 COMPONENT fsal DESTINATION  ${FSAL_DESTINATION} )


########### install files ###############
