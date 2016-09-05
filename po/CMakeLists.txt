find_package (Gettext REQUIRED)

file (GLOB POFILES *.po)
GETTEXT_CREATE_TRANSLATIONS (encfs.pot ALL ${POFILES})
