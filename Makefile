#
# Copyright (c) 2009 Apple Inc. All rights reserved.
#
# @APPLE_LICENSE_HEADER_START@
#
# This file contains Original Code and/or Modifications of Original Code
# as defined in and that are subject to the Apple Public Source License
# Version 2.0 (the 'License'). You may not use this file except in
# compliance with the License. Please obtain a copy of the License at
# http://www.opensource.apple.com/apsl/ and read it before using this
# file.
#
# The Original Code and all software distributed under the License are
# distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
# EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
# INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
# Please see the License for the specific language governing rights and
# limitations under the License.
#
# @APPLE_LICENSE_HEADER_END@
#

# Project info
Project         := dcerpc
UserType        := Developer

Install_Target := install
Install_Prefix := /usr/local
RC_Install_Prefix = $(Install_Prefix)

Extra_Configure_Flags := \
	--enable-idldumpers \
	--disable-schannel \
	--disable-demoprogs

Extra_GCC_Warnings := \
	-Wall \
	-Wextra \
	-Wshadow \
	-Wshorten-64-to-32 \
	-Wbad-function-cast \
	-Wstrict-prototypes \
	-Wpointer-arith \
	-Wcast-align \
	-Wwrite-strings \
	-Wformat=2

Extra_CC_Flags := \
	-D_FORTIFY_SOURCE=2 \
	-fstack-protector \
	-fno-strict-aliasing \
	-fPIC \
	-Os \
	-g \
	$(Extra_GCC_Warnings)

GnuAfterInstall := clean-dstroot install-symroot

NCPU := $(shell sysctl hw.ncpu | awk -F: '{print $$2}' )
NPROCS := $(shell expr $(NCPU) '*' 2)

build:: MAKEFLAGS += -j $(NPROCS)

# When the default makefiles support building multiple architectures in
# separate directories with multiple invokations of configure, we
# can go back to using them.

# include $(MAKEFILEPATH)/CoreOS/ReleaseControl/GNUSource.make
include build/GNUSource.make

Install_Target := install

# Hook the pre-configure stage in the release-control makefiles.
install_source:: autogen

autogen:
	cd $(Sources) && ./buildconf

# Remove all the default stuff that the DCERPC build installs, but that we
# don't really want in the OS install.
clean-dstroot:
	$(_v)$(RM) -r -f $(DSTROOT)$(Install_Prefix)/bin/idl
	$(_v)$(RM) -r -f $(DSTROOT)$(Install_Prefix)/bin/uuid
	$(_v)$(RM) -r -f $(DSTROOT)$(Install_Prefix)/bin/demo
	$(_v)$(RM) -r -f $(DSTROOT)$(Install_Prefix)/include/ncklib
	$(_v)$(RM) -r -f $(DSTROOT)$(Install_Prefix)/include/compat
	$(_v)find $(DSTROOT) -name \*.la -delete

# Copy binaries into $(SYMROOT) so that the builder can generate dSYMs.
install-symroot:
	$(_v)for d in bin sbin lib ; do \
		$(INSTALL_DIRECTORY) $(SYMROOT)$(Install_Prefix)/$$d && \
		$(CP) $(DSTROOT)$(Install_Prefix)/$$d/* \
			$(SYMROOT)$(Install_Prefix)/$$d ; \
	done

# vim: set sw=8 ts=8 noet tw=0 :
