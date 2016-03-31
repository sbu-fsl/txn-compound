include_directories(
  ${LIBTIRPC_INCLUDE_DIR}
)

if(_MSPAC_SUPPORT)
  include_directories(
    ${WBCLIENT_INCLUDE_DIR}
    )
endif(_MSPAC_SUPPORT)

########### next target ###############

SET(idmap_STAT_SRCS
   idmapper.c
   idmapper_cache.c
)

add_library(idmap STATIC ${idmap_STAT_SRCS})
set_target_properties(idmap PROPERTIES POSITION_INDEPENDENT_CODE on)

########### install files ###############
