AC_INIT([retrace-server],
	[1.12],
	[crash-catcher@fedorahosted.org])

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign silent-rules])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_PROG_CC
AC_PROG_LN_S

AC_SYS_LARGEFILE
CFLAGS="$CFLAGS -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE \
          -D_FILE_OFFSET_BITS=64 -fno-strict-aliasing -std=gnu99 -Wall"

AC_ARG_ENABLE(debug,
              [AC_HELP_STRING([--enable-debug],
                             [Enable debug information])],
              [CFLAGS="$CFLAGS -DDEBUG -ggdb -g"])

dnl ****** INTERNATIONALIZATION **********************
GETTEXT_PACKAGE=retrace-server
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE", [Package name for gettext])

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.17])

IT_PROG_INTLTOOL([0.35.0])

dnl ****** END ****************************************

AM_PATH_PYTHON
if test -z "$PYTHON"; then
    echo "*** Essential program python not found" 1>&2
    exit 1
fi

AC_PATH_PROG([DF], [df], [no])
[if test "$DF" = "no"]
[then]
    [echo "The df program was not found in the search path. Please ensure"]
    [echo "that it is installed and its directory is included in the search path."]
    [echo "Then run configure again before attempting to build Retrace server."]
    [exit 1]
[fi]

AC_PATH_PROG([DU], [du], [no])
[if test "$DU" = "no"]
[then]
    [echo "The du program was not found in the search path. Please ensure"]
    [echo "that it is installed and its directory is included in the search path."]
    [echo "Then run configure again before attempting to build Retrace server."]
    [exit 1]
[fi]

AC_PATH_PROG([GZIP], [gzip], [no])
[if test "$GZIP" = "no"]
[then]
    [echo "The gzip program was not found in the search path. Please ensure"]
    [echo "that it is installed and its directory is included in the search path."]
    [echo "Then run configure again before attempting to build Retrace server."]
    [exit 1]
[fi]

AC_PATH_PROG([TAR], [tar], [no])
[if test "$TAR" = "no"]
[then]
    [echo "The tar program was not found in the search path. Please ensure"]
    [echo "that it is installed and its directory is included in the search path."]
    [echo "Then run configure again before attempting to build Retrace server."]
    [exit 1]
[fi]

AC_PATH_PROG([XZ], [xz], [no])
[if test "$XZ" = "no"]
[then]
    [echo "The xz program was not found in the search path. Please ensure"]
    [echo "that it is installed and its directory is included in the search path."]
    [echo "Then run configure again before attempting to build Retrace server."]
    [exit 1]
[fi]

AC_PATH_PROG([ASCIIDOC], [asciidoc], [no])
[if test "$ASCIIDOC" = "no"]
[then]
    [echo "The asciidoc program was not found in the search path. Please ensure"]
    [echo "that it is installed and its directory is included in the search path."]
    [echo "Then run configure again before attempting to build Retrace server."]
    [exit 1]
[fi]

AC_PATH_PROG([XMLTO], [xmlto], [no])
[if test "$XMLTO" = "no"]
[then]
    [echo "The xmlto program was not found in the search path. Please ensure"]
    [echo "that it is installed and its directory is included in the search path."]
    [echo "Then run configure again before attempting to build Retrace server."]
    [exit 1]
[fi]

PKG_PROG_PKG_CONFIG
AC_ARG_WITH([systemdsystemunitdir],
        AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
        [], [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
AM_CONDITIONAL(HAVE_SYSTEMD, [test -n "$with_systemdsystemunitdir"])

DATA_DIR='${localstatedir}/spool/${PACKAGE_NAME}'
LOG_DIR='${localstatedir}/log/${PACKAGE_NAME}'
REPO_DIR='${localstatedir}/cache/${PACKAGE_NAME}'
SCRIPT_DIR='${datadir}/${PACKAGE_NAME}'

AC_SUBST(DATA_DIR)
AC_SUBST(LOG_DIR)
AC_SUBST(REPO_DIR)
AC_SUBST(SCRIPT_DIR)

AM_MISSING_PROG([AUTOM4TE], [autom4te])

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([
	retrace-server.spec
	Makefile
	doc/Makefile
	po/Makefile.in
	src/Makefile
	src/config/Makefile
	src/gpg/Makefile
	src/plugins/Makefile
	src/lib/Makefile
])

AC_OUTPUT
