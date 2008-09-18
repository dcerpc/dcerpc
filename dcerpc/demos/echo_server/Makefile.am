## Process this file with automake to produce Makefile.in
include $(top_srcdir)/include.mk

MY_IDLFLAGS = -I$(IDL_INCLUDE_DIR)/.. -I$(top_builddir)/include $(DCETHREADINCLUDES) -keep c_source

install-strip:	install

nobase_bin_PROGRAMS=demo/echo_server demo/echo_client

demo_echo_server_SOURCES=misc.c echo_server.c echo_sstub.c
demo_echo_client_SOURCES=misc.c echo_client.c echo_cstub.c

noinst_HEADERS=misc.h echo.idl echo.acf

CLEANFILES=echo.h echo_sstub.c echo_cstub.c

libs=$(top_builddir)/dcelib/libdcerpc.la $(top_builddir)/uuid/libuuid.la

demo_echo_server_LDADD=$(libs)
demo_echo_client_LDADD=$(libs)

BUILT_SOURCES=echo.h echo_sstub.c echo_cstub.c

echo.h echo_sstub.c echo_cstub.c: echo.idl
	$(IDL) $(MY_IDLFLAGS) $(top_srcdir)/demos/echo_server/echo.idl

