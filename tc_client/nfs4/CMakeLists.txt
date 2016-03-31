add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

########### next target ###############

SET(tc_impl_nfs4_SRCS
   handle.c
   fs.c
   export.c
   xattrs.c
   tc_utils.c
   tc_seq.c
   tc_dist.c
   tc_impl_nfs4.c
   tc_daemontest.c
)

add_library(tc_impl_nfs4 SHARED ${tc_impl_nfs4_SRCS})

target_link_libraries(tc_impl_nfs4
		      ${SYSTEM_LIBRARIES}
                      ${LIBTIRPC_LIBRARIES}
		      ${PROTOCOLS}
		      ${GANESHA_CORE}
		      config_parsing
                      tc_util
		      MainServices
		      fsal_core
                      m)

set_target_properties(tc_impl_nfs4 PROPERTIES VERSION 4.2.0 SOVERSION 4)
install(TARGETS tc_impl_nfs4 COMPONENT fsal DESTINATION  ${FSAL_DESTINATION} )


########### install files ###############
