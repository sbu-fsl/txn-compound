include_directories(
  ${LIBTIRPC_INCLUDE_DIR}
)

# Add the directory for stackable FSALs
add_subdirectory(Stackable_FSALs)

# Add the directory for Pseudo FSAL
add_subdirectory(FSAL_PSEUDO)

