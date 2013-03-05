#define VERSION "@ENCFS_VERSION@"

#cmakedefine HAVE_ATTR_XATTR_H
#cmakedefine HAVE_SYS_XATTR_H
#cmakedefine XATTR_ADD_OPT
#cmakedefine HAVE_COMMON_CRYPTO

#cmakedefine HAVE_TR1_MEMORY
#cmakedefine HAVE_TR1_UNORDERED_MAP
#cmakedefine HAVE_TR1_UNORDERED_SET
#cmakedefine HAVE_TR1_TUPLE

#cmakedefine HAVE_EVP_BF
#cmakedefine HAVE_EVP_AES
#cmakedefine HAVE_EVP_AES_XTS

#cmakedefine HAVE_LCHMOD

#cmakedefine HAVE_VALGRIND_VALGRIND_H
#cmakedefine HAVE_VALGRIND_MEMCHECK_H

/* TODO: add other thread library support. */
#cmakedefine CMAKE_USE_PTHREADS_INIT

