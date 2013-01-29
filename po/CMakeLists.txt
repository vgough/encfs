
file (GLOB PO_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.po")
file (GLOB CXX_FILES RELATIVE ${PROJECT_SOURCE_DIR} "*/*.cpp")

set (GettextTranslate_GMO_BINARY true)

include (GetTextTranslate)



#find_package (Gettext REQUIRED)
#find_program (GETTEXT_XGETTEXT_EXE xgettext)
#
#if (NOT GETTEXT_FOUND)
#    message (STATUS "    Gettext not found")
#endif (NOT GETTEXT_FOUND)
#if (NOT GETTEXT_XGETTEXT_EXE)
#    message (STATUS "    Can't find xgettext")
#endif (NOT GETTEXT_XGETTEXT_EXE)
#
#
#if (GETTEXT_FOUND AND GETTEXT_XGETTEXT_EXE)
#    add_custom_command(
#        OUTPUT ${PROJECT_NAME}.pot
#        COMMAND ${GETTEXT_XGETTEXT_EXE} --omit-header --keyword=_ --keyword=N_ ${CXX_FILES} -o ${PROJECT_NAME}.pot
#        )
#
#    if (PO_FILES)
#        message (STATUS "Translations will be built!")
#        gettext_create_translations (${PROJECT_NAME}.pot ALL ${PO_FILES})
#    else (PO_FILES)
#        message (STATUS "Translations not found!")
#    endif (PO_FILES)
#else (GETTEXT_FOUND AND GETTEXT_XGETTEXT_EXE)
#    message (STATUS "Translations won't be built.")
#endif (GETTEXT_FOUND AND GETTEXT_XGETTEXT_EXE)

