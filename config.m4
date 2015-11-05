PHP_ARG_ENABLE(couchbase, whether to enable Couchbase support,
[  --with-couchbase        Include Couchbase support])

PHP_ARG_WITH(system-fastlz, wheter to use system FastLZ bibrary,
[  --with-system-fastlz    Use system FastLZ bibrary], no, no)

if test "$PHP_COUCHBASE" = "yes"; then
  AC_DEFINE(HAVE_COUCHBASE, 1, [Whether you have Couchbase])

  AC_CHECK_HEADERS([libcouchbase/couchbase.h])
  AS_IF([test "x$ac_cv_header_libcouchbase_couchbase_h" = "xno"], [
		 AC_MSG_ERROR([the couchbase extension requires libcouchbase])])

  PHP_ADD_LIBRARY(couchbase, 1, COUCHBASE_SHARED_LIBADD)
  
  if test "$PHP_SYSTEM_FASTLZ" != "no"; then
    FASTLZ=""
    AC_CHECK_HEADERS([fastlz.h])
    PHP_CHECK_LIBRARY(fastlz, fastlz_compress,
      [PHP_ADD_LIBRARY(fastlz, 1, COUCHBASE_SHARED_LIBADD)],
      [AC_MSG_ERROR(FastLZ library not found)])
  else
    FASTLZ="fastlz/fastlz.c"
  fi

  ifdef([PHP_ADD_EXTENDION_DEP], [
	PHP_ADD_EXTENSION_DEP(couchbase, json)
  ]) 

  PHP_SUBST(COUCHBASE_SHARED_LIBADD)
  PHP_NEW_EXTENSION(couchbase, \
	bucket.c \
	cas.c \
	cluster.c \
	couchbase.c \
	exception.c \
	metadoc.c \
	transcoding.c \
	$FASTLZ \
  , $ext_shared)

  if test -n "$FASTLZ" ; then
    PHP_ADD_BUILD_DIR($ext_builddir/fastlz, 1)
    PHP_ADD_INCLUDE([$ext_srcdir/fastlz])
  fi
fi