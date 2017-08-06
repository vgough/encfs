#define VERSION "@ENCFS_VERSION@"

#cmakedefine HAVE_ATTR_XATTR_H
#cmakedefine HAVE_SYS_XATTR_H
#cmakedefine XATTR_ADD_OPT
#cmakedefine XATTR_LLIST

#cmakedefine HAVE_LCHMOD

/* TODO: add other thread library support. */
#cmakedefine CMAKE_USE_PTHREADS_INIT

