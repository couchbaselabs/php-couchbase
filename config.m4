PHP_ARG_WITH(couchbase, whether to enable Couchbase support,
[  --with-couchbase   Include Couchbase support])

PHP_ARG_WITH(system-fastlz, wheter to use system FastLZ library,
    [  --with-system-fastlz   Use system FastLZ library], no, no)

if test "$PHP_COUCHBASE" != "no"; then
  AC_PATH_PROG(PKG_CONFIG, pkg-config, no)

  AC_MSG_CHECKING(for libcouchbase)

  dnl try given directory
  if test -r $PHP_COUCHBASE/include/libcouchbase/couchbase.h; then
    LIBCOUCHBASE_DIR=$PHP_COUCHBASE
    AC_MSG_RESULT(found in $PHP_COUCHBASE)

  dnl try pkg-config
  elif test -x "$PKG_CONFIG" && $PKG_CONFIG --exists libcouchbase; then
    LIBCOUCHBASE_VERSION=`$PKG_CONFIG libcouchbase --modversion`

    if $PKG_CONFIG libcouchbase --atleast-version 3.0.0; then
      LIBCOUCHBASE_CFLAGS=`$PKG_CONFIG libcouchbase --cflags`
      LIBCOUCHBASE_LIBS=`$PKG_CONFIG libcouchbase --libs`
      AC_MSG_RESULT(from pkgconfig: version $LIBCOUCHBASE_VERSION found)
    else
      AC_MSG_ERROR([libcouchbase version $LIBCOUCHBASE_VERSION found, must be upgraded to version >= 3.0.0])
    fi

  dnl fallback on standard directory
  else
    for i in /usr/local /usr; do
      if test -r $i/include/libcouchbase/couchbase.h; then
        LIBCOUCHBASE_DIR=$i
        AC_MSG_RESULT(found in $i)
      fi
    done
  fi

  dnl from pkg-config
  if test -n "$LIBCOUCHBASE_LIBS"; then
    PHP_EVAL_LIBLINE($LIBCOUCHBASE_LIBS, COUCHBASE_SHARED_LIBADD)
    PHP_EVAL_INCLINE($LIBCOUCHBASE_CFLAGS)

  dnl not found in directories
  elif test -z "$LIBCOUCHBASE_DIR"; then
    AC_MSG_RESULT(not found)
    AC_MSG_ERROR(Please reinstall the libcouchbase distribution -
                 libcouchbase.h should be <libcouchbase-dir>/include and
                 libcouchbase.a should be in <libcouchbase-dir>/lib)

  dnl found in directory
  else
    AC_MSG_CHECKING([for libcouchbase version >= 3.0.0])
    LCB_VERSION=$($EGREP "define LCB_VERSION " $LIBCOUCHBASE_DIR/include/libcouchbase/configuration.h | $SED -e 's/[[^0-9x]]//g')
    AC_MSG_RESULT([$LCB_VERSION])
    if test "x$LCB_VERSION" = "x0x000000"; then
      AC_MSG_ERROR([seems like libcouchbase is not installed from official tarball or git clone. Do not use github tags to download releases.])
    fi
    if test $(printf %d $LCB_VERSION) -lt $(printf %d 0x030000); then
      AC_MSG_ERROR([libcouchbase greater or equal to 3.0.0 required])
    fi

    PHP_ADD_INCLUDE($LIBCOUCHBASE_DIR/include)
    PHP_ADD_LIBRARY_WITH_PATH(couchbase, $LIBCOUCHBASE_DIR/$PHP_LIBDIR, COUCHBASE_SHARED_LIBADD)
  fi

  PHP_SUBST(COUCHBASE_SHARED_LIBADD)

  AC_DEFINE(HAVE_COUCHBASE, 1, [Whether you have Couchbase])

  ifdef([PHP_ADD_EXTENDION_DEP], [
	PHP_ADD_EXTENSION_DEP(couchbase, json)
  ])

  PHP_SUBST(COUCHBASE_SHARED_LIBADD)

COUCHBASE_FILES=" \
    couchbase.c \
    exception.c \
    log.c \
    opcookie.c \
    src/couchbase/authenticator.c \
    src/couchbase/bucket.c \
    src/couchbase/bucket/cbas.c \
    src/couchbase/bucket/cbft.c \
    src/couchbase/bucket/counter.c \
    src/couchbase/bucket/exists.c \
    src/couchbase/bucket/get.c \
    src/couchbase/bucket/get_replica.c \
    src/couchbase/bucket/health.c \
    src/couchbase/bucket/http.c \
    src/couchbase/bucket/n1ql.c \
    src/couchbase/bucket/remove.c \
    src/couchbase/bucket/store.c \
    src/couchbase/bucket/subdoc.c \
    src/couchbase/bucket/touch.c \
    src/couchbase/bucket/unlock.c \
    src/couchbase/bucket/view.c \
    src/couchbase/cert_authenticator.c \
    src/couchbase/cluster.c \
    src/couchbase/cluster_options.c \
    src/couchbase/collection.c \
    src/couchbase/log_formatter.c \
    src/couchbase/lookup_spec.c \
    src/couchbase/managers/bucket_manager.c \
    src/couchbase/managers/collection_manager.c \
    src/couchbase/managers/query_index_manager.c \
    src/couchbase/managers/search_index_manager.c \
    src/couchbase/managers/user_manager.c \
    src/couchbase/managers/view_index_manager.c \
    src/couchbase/mutate_spec.c \
    src/couchbase/mutation_state.c \
    src/couchbase/password_authenticator.c \
    src/couchbase/pool.c \
    src/couchbase/result.c \
    src/couchbase/search/boolean_field_query.c \
    src/couchbase/search/boolean_query.c \
    src/couchbase/search/conjunction_query.c \
    src/couchbase/search/date_range_facet.c \
    src/couchbase/search/date_range_query.c \
    src/couchbase/search/disjunction_query.c \
    src/couchbase/search/doc_id_query.c \
    src/couchbase/search/facet.c \
    src/couchbase/search/geo_bounding_box_query.c \
    src/couchbase/search/geo_distance_query.c \
    src/couchbase/search/geo_polygon_query.c \
    src/couchbase/search/match_all_query.c \
    src/couchbase/search/match_none_query.c \
    src/couchbase/search/match_phrase_query.c \
    src/couchbase/search/match_query.c \
    src/couchbase/search/numeric_range_facet.c \
    src/couchbase/search/numeric_range_query.c \
    src/couchbase/search/phrase_query.c \
    src/couchbase/search/prefix_query.c \
    src/couchbase/search/query_string_query.c \
    src/couchbase/search/regexp_query.c \
    src/couchbase/search/search_query.c \
    src/couchbase/search/sort.c \
    src/couchbase/search/sort_field.c \
    src/couchbase/search/sort_geo.c \
    src/couchbase/search/sort_id.c \
    src/couchbase/search/sort_score.c \
    src/couchbase/search/term_facet.c \
    src/couchbase/search/term_query.c \
    src/couchbase/search/term_range_query.c \
    src/couchbase/search/wildcard_query.c \
    src/couchbase/search_options.c \
    transcoding.c \
"

  AC_CHECK_HEADERS([zlib.h])
  PHP_CHECK_LIBRARY(z, compress, [
    AC_DEFINE(HAVE_COUCHBASE_ZLIB,1,[Whether zlib compressor is enabled])
    PHP_ADD_LIBRARY(z, 1, COUCHBASE_SHARED_LIBADD)],
    [AC_MSG_WARN(zlib library not found)])

  if test "$PHP_SYSTEM_FASTLZ" != "no"; then
    AC_CHECK_HEADERS([fastlz.h])
    PHP_CHECK_LIBRARY(fastlz, fastlz_compress,
      [PHP_ADD_LIBRARY(fastlz, 1, COUCHBASE_SHARED_LIBADD)],
      [AC_MSG_ERROR(FastLZ library not found)])
  else
    COUCHBASE_FILES="${COUCHBASE_FILES} fastlz/fastlz.c"
  fi
  PHP_NEW_EXTENSION(couchbase, ${COUCHBASE_FILES}, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
  PHP_ADD_BUILD_DIR($ext_builddir/fastlz, 1)
  PHP_ADD_BUILD_DIR($ext_builddir/src/couchbase, 1)
  PHP_ADD_BUILD_DIR($ext_builddir/src/couchbase/search, 1)
  PHP_ADD_BUILD_DIR($ext_builddir/src/couchbase/bucket, 1)
  PHP_ADD_BUILD_DIR($ext_builddir/src/couchbase/managers, 1)
  PHP_ADD_EXTENSION_DEP(couchbase, json)
fi
