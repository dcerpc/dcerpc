NCK_INCLUDES=-I$(top_srcdir)/ncklib -I$(top_srcdir)/ncklib/include/$(target_os)
NCK_DEFINES=-DNCK -DRPC_C_NP_DIR=\"$(localstatedir)/rpc\" -DRPC_C_UXD_DIR=\"$(localstatedir)/rpc\" 

# It would seem that putting the defines in CFLAGS is a hack.
AM_CPPFLAGS+=$(NCK_INCLUDES)
AM_CFLAGS+=$(NCK_DEFINES)

