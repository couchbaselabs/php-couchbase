PHP_ARG_WITH(couchbase, whether to enable Couchbase support,
[  --with-couchbase   Include Couchbase support])

PHP_ARG_WITH(system-fastlz, wheter to use system FastLZ bibrary,
    [  --with-system-fastlz   Use system FastLZ bibrary], no, no)

if test "$PHP_COUCHBASE" != "no"; then
  if test -r $PHP_COUCHBASE/include/libcouchbase/couchbase.h; then
    LIBCOUCHBASE_DIR=$PHP_COUCHBASE
  else
    AC_MSG_CHECKING(for libcouchbase in default path)
    for i in /usr/local /usr; do
      if test -r $i/include/libcouchbase/couchbase.h; then
        LIBCOUCHBASE_DIR=$i
        AC_MSG_RESULT(found in $i)
      fi
    done
  fi

  if test -z "$LIBCOUCHBASE_DIR"; then
    AC_MSG_RESULT(not found)
    AC_MSG_ERROR(Please reinstall the libcouchbase distribution -
                 libcouchbase.h should be <libcouchbase-dir>/include and
                 libcouchbase.a should be in <libcouchbase-dir>/lib)
  fi

  AC_MSG_CHECKING([for libcouchbase version >= 2.7.2])
  LCB_VERSION=$($EGREP "define LCB_VERSION " $LIBCOUCHBASE_DIR/include/libcouchbase/configuration.h | $SED -e 's/[[^0-9x]]//g')
  AC_MSG_RESULT([$LCB_VERSION])
  if test $(printf %d $LCB_VERSION) -lt $(printf %d 0x020702); then
    AC_MSG_ERROR([libcouchbase greater or equal to 2.7.2 required])
  fi

  PHP_ADD_INCLUDE($LIBCOUCHBASE_DIR/include)

  PHP_SUBST(COUCHBASE_SHARED_LIBADD)
  PHP_ADD_LIBRARY_WITH_PATH(couchbase, $LIBCOUCHBASE_DIR/$PHP_LIBDIR, COUCHBASE_SHARED_LIBADD)

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
    paramparser.c \
    src/couchbase/authenticator.c \
    src/couchbase/classic_authenticator.c \
    src/couchbase/base36.c \
    src/couchbase/pool.c \
    src/couchbase/log_formatter.c \
    src/couchbase/bucket.c \
    src/couchbase/bucket/cbft.c \
    src/couchbase/bucket/counter.c \
    src/couchbase/bucket/durability.c \
    src/couchbase/bucket/get.c \
    src/couchbase/bucket/http.c \
    src/couchbase/bucket/n1ql.c \
    src/couchbase/bucket/remove.c \
    src/couchbase/bucket/store.c \
    src/couchbase/bucket/subdoc.c \
    src/couchbase/bucket/touch.c \
    src/couchbase/bucket/unlock.c \
    src/couchbase/bucket/view.c \
    src/couchbase/bucket_manager.c \
    src/couchbase/bucket_manager/n1ix_create.c \
    src/couchbase/bucket_manager/n1ix_drop.c \
    src/couchbase/bucket_manager/n1ix_list.c \
    src/couchbase/cluster.c \
    src/couchbase/cluster_manager.c \
    src/couchbase/document.c \
    src/couchbase/document_fragment.c \
    src/couchbase/lookup_in_builder.c \
    src/couchbase/mutate_in_builder.c \
    src/couchbase/mutation_state.c \
    src/couchbase/mutation_token.c \
    src/couchbase/n1ql_index.c \
    src/couchbase/n1ql_query.c \
    src/couchbase/search_query.c \
    src/couchbase/search/query_part.c \
    src/couchbase/search/boolean_field_query.c \
    src/couchbase/search/boolean_query.c \
    src/couchbase/search/conjunction_query.c \
    src/couchbase/search/date_range_query.c \
    src/couchbase/search/disjunction_query.c \
    src/couchbase/search/doc_id_query.c \
    src/couchbase/search/match_all_query.c \
    src/couchbase/search/match_none_query.c \
    src/couchbase/search/match_phrase_query.c \
    src/couchbase/search/match_query.c \
    src/couchbase/search/numeric_range_query.c \
    src/couchbase/search/phrase_query.c \
    src/couchbase/search/prefix_query.c \
    src/couchbase/search/query_string_query.c \
    src/couchbase/search/regexp_query.c \
    src/couchbase/search/term_query.c \
    src/couchbase/search/wildcard_query.c \
    src/couchbase/search/facet.c \
    src/couchbase/search/term_facet.c \
    src/couchbase/search/date_range_facet.c \
    src/couchbase/search/numeric_range_facet.c \
    src/couchbase/view_query.c \
    src/couchbase/view_query_encodable.c \
    src/couchbase/spatial_view_query.c \
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
  PHP_ADD_BUILD_DIR($ext_builddir/src/couchbase/bucket_manager, 1)
  PHP_ADD_EXTENSION_DEP(couchbase, json)


  AC_MSG_CHECKING([for igbinary support])
  igbinary_inc_path=""
  if test -f "$abs_srcdir/include/php/ext/igbinary/igbinary.h"; then
    igbinary_inc_path="$abs_srcdir/include/php"
  elif test -f "$abs_srcdir/ext/igbinary/igbinary.h"; then
    igbinary_inc_path="$abs_srcdir"
  elif test -f "$phpincludedir/ext/session/igbinary.h"; then
    igbinary_inc_path="$phpincludedir"
  elif test -f "$phpincludedir/ext/igbinary/igbinary.h"; then
    igbinary_inc_path="$phpincludedir"
  fi
  if test "$igbinary_inc_path" = ""; then
    AC_MSG_WARN([Cannot find igbinary.h])
  else
    AC_DEFINE(HAVE_COUCHBASE_IGBINARY,1,[Whether igbinary serializer is enabled])
    IGBINARY_INCLUDES="-I$igbinary_inc_path"
    ifdef([PHP_ADD_EXTENSION_DEP],
      [
        PHP_ADD_EXTENSION_DEP(couchbase, igbinary)
      ])
    AC_MSG_RESULT([$igbinary_inc_path])
  fi
fi
