add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

########### next target ###############

SET(fsalproxy_LIB_SRCS
   handle.c
   fs.c
   export.c
   xattrs.c
   tc_utils.c
   tc_seq.c
   tc_dist.c
   tc_singlefile.c
   tc_impl_nfs4.c
)

add_library(tc_impl_nfs4 SHARED ${fsalproxy_LIB_SRCS})

target_link_libraries(tc_impl_nfs4
		      ${SYSTEM_LIBRARIES}
                      ${LIBTIRPC_LIBRARIES}
                      tc_util
                      m)

set_target_properties(tc_impl_nfs4 PROPERTIES VERSION 4.2.0 SOVERSION 4)
install(TARGETS tc_impl_nfs4 COMPONENT fsal DESTINATION  ${FSAL_DESTINATION} )


########### install files ###############
