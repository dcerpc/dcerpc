## Process this file with automake to produce Makefile.in
include $(top_srcdir)/include.mk
include $(top_srcdir)/ncklib/ncklib.mk

NCK_IDL_FLAGS=-keep c_source -no_cpp -v -no_mepv -I$(IDL_INCLUDE_DIR)/.. -I$(top_builddir)/include @DCETHREADINCLUDES@ $(TARGET_OS)

AM_CFLAGS += -Wall -Werror -fno-strict-aliasing -DDCETHREAD_ENFORCE_API

# Initialize
lib_LTLIBRARIES=
noinst_LTLIBRARIES=
noinst_HEADERS=
CLEANFILES=

######################################################################
## COMPONENT: transport/cn - comprises of libprot_ncacn shared lib

# code for connection orientated transports
if PROT_NCACN

lib_LTLIBRARIES+=libprot_ncacn.la

libprot_ncacn_la_LDFLAGS = $(MODULELDFLAGS) $(DCERPC_LDFLAGS) -version-info 1:0:0
libprot_ncacn_la_SOURCES = cnassoc.c cnbind.c cncall.c cncasgsm.c \
 cncassm.c cncclsm.c cncthd.c cnfbuf.c cnid.c cninit.c cnmgmt.c \
 cnnet.c cnp.c cnpkt.c cnrcvr.c cnsasgsm.c cnsassm.c cnsclsm.c \
 cnsm.c cnxfer.c
libprot_ncacn_la_LIBADD = ../dcelib/libdcerpc.la

endif

######################################################################
## COMPONENT: transport/dg - comprises of libprot_ncadg shared lib

lib_LTLIBRARIES+=libprot_ncadg.la
noinst_LTLIBRARIES+=libprot_ncadg_stubs.la

libprot_ncadg_stubs_la_SOURCES=conv_cstub.c convc_cstub.c convc_sstub.c
libprot_ncadg_stubs_la_CPPFLAGS=-I. $(BASE_CPPFLAGS) $(IDL_CPPFLAGS)
libprot_ncadg_stubs_la_CFLAGS=$(BASE_CFLAGS)

noinst_HEADERS+=conv.h convc.h

conv.h conv_cstub.c: $(IDL_INCLUDE_DIR)/conv.idl
	$(IDL) $(NCK_IDL_FLAGS) -cepv -server none $<

convc.h convc_cstub.c convc_sstub.c: $(IDL_INCLUDE_DIR)/convc.idl
	$(IDL) $(NCK_IDL_FLAGS) -cepv $<

libprot_ncadg_la_SOURCES=conv.c dg.c dgcall.c dgccall.c \
 dgccallt.c dgcct.c dgclive.c dgclsn.c dgexec.c dgfwd.c \
 dgglob.c dghnd.c dginit.c dglossy.c dglsn.c dgpkt.c dgrq.c \
 dgscall.c dgsct.c dgslive.c dgslsn.c dgsoc.c dgutl.c dgxq.c 

libprot_ncadg_la_LDFLAGS=$(MODULELDFLAGS) -version-info 1:0:0
libprot_ncadg_la_LIBADD=libprot_ncadg_stubs.la ../dcelib/libdcerpc.la

######################################################################
## COMPONENT: naf - comprises of libnaf_{np,ip,uxd} shared libs

if NAF_IP
lib_LTLIBRARIES+=libnaf_ip.la
libnaf_ip_la_SOURCES=ipnaf.c ipnaf_linux.c twr_ip.c
libnaf_ip_la_LDFLAGS=$(MODULELDFLAGS)
libnaf_ip_la_LIBADD= ../dcelib/libdcerpc.la
# Unused: ipnaf_bsd.c
endif

if NAF_NP
lib_LTLIBRARIES+=libnaf_np.la
libnaf_np_la_SOURCES=npnaf.c npnaf_linux.c twr_np.c twr_uxd.c
libnaf_np_la_LDFLAGS=$(MODULELDFLAGS)
libnaf_np_la_LIBADD= ../dcelib/libdcerpc.la
endif

if NAF_UXD
lib_LTLIBRARIES+=libnaf_uxd.la
libnaf_uxd_la_SOURCES=uxdnaf.c uxdnaf_linux.c twr_uxd.c
libnaf_uxd_la_LDFLAGS=$(MODULELDFLAGS)
libnaf_uxd_la_LIBADD= ../dcelib/libdcerpc.la
endif

# Unused: twr_dnet.c

if AUTH_GSS_NEGOTIATE
lib_LTLIBRARIES += libauth_gss_negotiate.la

libauth_gss_negotiate_la_SOURCES = gssauth.c gssauthcn.c
libauth_gss_negotiate_la_CFLAGS = @GSSAPI_INCLUDES@
libauth_gss_negotiate_la_LDFLAGS = @GSSAPI_LDFLAGS@
libauth_gss_negotiate_la_LIBADD = @GSSAPI_LIBS@ ../dcelib/libdcerpc.la
endif

if AUTH_SCHANNEL
lib_LTLIBRARIES += libauth_schannel.la

libauth_schannel_la_SOURCES = schnauth.c schnauthcn.c
libauth_schannel_la_CFLAGS = @SCHANNEL_INCLUDES@
libauth_schannel_la_LDFLAGS = @SCHANNEL_LDFLAGS@
libauth_schannel_la_LIBADD = @SCHANNEL_LIBS@ ../dcelib/libdcerpc.la
endif


EXTRA_DIST=../ncklib/ncklib.mk 
