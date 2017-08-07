#define VERSION "@ENCFS_VERSION@"

#cmakedefine HAVE_ATTR_XATTR_H
#cmakedefine HAVE_SYS_XATTR_H
#cmakedefine XATTR_ADD_OPT
#cmakedefine XATTR_LLIST

#cmakedefine HAVE_LCHMOD
#cmakedefine HAVE_FDATASYNC

#cmakedefine HAVE_DIRENT_D_TYPE

#cmakedefine DEFAULT_CASE_INSENSITIVE

/* TODO: add other thread library support. */
#cmakedefine CMAKE_USE_PTHREADS_INIT

