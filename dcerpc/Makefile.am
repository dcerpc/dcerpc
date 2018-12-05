ACLOCAL_AMFLAGS = -I m4
include $(top_srcdir)/include.mk

SUBDIRS=compat libdcethread idl_compiler include idl_lib uuid ncklib dcelib rpcd demos perf tools

EXTRA_DIST=include.mk

dist-hook:
	-chmod -R a+r $(distdir)
	$(TAR) choIf $(distdir).tar.bz2 $(distdir)

