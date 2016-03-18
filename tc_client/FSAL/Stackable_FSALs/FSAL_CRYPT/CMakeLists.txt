add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

set( LIB_PREFIX 64)

########### next target ###############

SET(fsalcrypt_LIB_SRCS
   handle.c
   file.c
   xattrs.c
   cryptfs_methods.h
   main.c
   export.c
   fsal_convert.c
   ctr_crypto.c
)

add_library(fsalcrypt SHARED ${fsalcrypt_LIB_SRCS})

target_link_libraries(fsalcrypt
  gos
)

set_target_properties(fsalcrypt PROPERTIES VERSION 4.2.0 SOVERSION 4)
install(TARGETS fsalcrypt COMPONENT fsal DESTINATION ${FSAL_DESTINATION} )


########### install files ###############
