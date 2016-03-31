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
)

add_library(fsalproxy SHARED ${fsalproxy_LIB_SRCS})

target_link_libraries(fsalproxy
		      ${SYSTEM_LIBRARIES}
                      ${LIBTIRPC_LIBRARIES}
                      tc_util
                      m)

set_target_properties(fsalproxy PROPERTIES VERSION 4.2.0 SOVERSION 4)
install(TARGETS fsalproxy COMPONENT fsal DESTINATION  ${FSAL_DESTINATION} )


########### install files ###############
