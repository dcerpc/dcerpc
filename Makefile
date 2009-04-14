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

ifeq ($(GnuNoStrip),YES)
STRIP_X	:= true
else
STRIP_X	:= strip -x
endif

Extra_Configure_Flags :=\
	--disable-dependency-tracking \
	--disable-afnp	\
	--disable-schannel \
	--disable-demoprogs

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

RC_OBJROOTS := $(addprefix $(OBJROOT)/, $(RC_ARCHS))

# vim: set sw=8 ts=8 noet tw=0 :
