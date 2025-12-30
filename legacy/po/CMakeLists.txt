find_package (Gettext REQUIRED)

file (GLOB POFILES *.po)
GETTEXT_CREATE_TRANSLATIONS (encfs.pot ALL ${POFILES})

find_program(XGETTEXT_CMD xgettext)

set(_xgettext_option_list --language=C
  --keyword=_
  --keyword=N_
  --keyword=C_:1c,2
  --keyword=NC_:1c,2 -s
  --package-name=encfs
  --package-version=${ENCFS_VERSION})

set(_potFile encfs.pot)
file(GLOB _src_list ../**/*.cpp)

if(XGETTEXT_CMD)
  ADD_CUSTOM_COMMAND(OUTPUT ${_potFile}
    COMMAND ${XGETTEXT_CMD} ${_xgettext_option_list} -o ${_potFile} ${_src_list}
    DEPENDS ${_src_list}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Extract translatable messages to ${_potFile}")

  ADD_CUSTOM_TARGET(pot_file ${_all}
    DEPENDS ${_potFile})
endif()
