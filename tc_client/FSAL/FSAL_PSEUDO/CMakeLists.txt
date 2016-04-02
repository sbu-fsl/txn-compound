add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

set( LIB_PREFIX 64)

########### next target ###############

SET(fsalpseudo_LIB_SRCS
   handle.c
   file.c
   xattrs.c
   pseudofs_methods.h
   main.c
   export.c
   ../fsal_convert.c
   ../commonlib.c
   ../fsal_manager.c
   ../access_check.c
   ../fsal_config.c
   ../default_methods.c
   ../common_pnfs.c
   ../fsal_destroyer.c
   ../../FSAL_UP/fsal_up_top.c
   ../../FSAL_UP/fsal_up_async.c
   ../../FSAL_UP/fsal_up_utils.c
)

add_library(fsalpseudo STATIC ${fsalpseudo_LIB_SRCS})

########### install files ###############
