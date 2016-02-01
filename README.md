[![Build Status](https://travis-ci.org/jpeach/dcerpc.svg?branch=master)](https://travis-ci.org/jpeach/dcerpc)
[![Coverity Status](https://scan.coverity.com/projects/6628/badge.svg)](https://scan.coverity.com/projects/dce-rpc)

DCE/RPC
-------

This project is a fork of the Likewise DCE/RPC renovation.  The
Likewise git repository was once available
[here](git://git.likewisesoftware.com/likewise-open.git) and can
probably stull be found somewhere on the internet.

Build notes.
------------

The build system for DCE/RPC is relatively complex, partly due to
the use of automake and libtool and partly because it does a lot
of code generation.

Xcode does not support this sort of thing particularly well, so we
make heavy use of shell script build phases and "workarounds".

Our basic approach to cross-compilation is to separate the build
into two phases. We have a dceidl project that builds the IDL
compiler and installs it into the SDK. Then we have the dcerpc
project that builds the DCERPC framework using the previously
installed IDL compiler.

The dcerpc and dceidl projects should typically by run with different
build architectures, since dceidl is expected to run on the uild
host, and dcerpc is expected to run on the target host. Inside
Apple, the build group has all this preconfigured.

We assume that the IDL compiler is actually an IDL cross-compiler.
This assumption is valid because the autotools build system uses
the "generic" architecture, and everything that depends on the
target architecture is determined at compilation time without the
use of autoconf tests.

We do use autoconf tests to select available features when we are
building the DCERPC framework, and this relies on the fact that
features vary between target SDKs, but not between target architectures.
You can only target a single SDK, and within that SDK, the feature
set is constant, and independent of the suported architecture.
Therefore it is valid to do a single configure pass followed by a
multi-architecture build.

DCE/RPC Documentation
--------------------

*Open Group documentation*

[C706](http://www.opengroup.org/onlinepubs/9629399/) is the primary
specification for DCE/RPC 1.1. This document describes the concepts,
protocol and internal mechanisms of the RPC architecture. The Open
Group also has the
[DCE 1.2.2 documentation](http://www.opengroup.org/bookstore/catalog/t151x.htm)
set available for purchase. This contains some useful RPC information,
particularly in the Application Development Guide.

*Microsoft documentation*

Since DCE/RPC is the basis for the Windows RPC implementation,
Microsoft provide a lot of useful documentation. Windows extensions
to the DCE/RPC protocols are documented in
[MS-RPCE](http://msdn.microsoft.com/en-us/library/cc243560.aspx).
The [Remote Procedure Call](https://msdn.microsoft.com/en-us/library/aa378651.aspx)
section of MSDN provides a wealth of information about the Windows
RPC implementation. The O'Reilly
[Microsoft RPC programming guide](http://openlibrary.org/books/OL555525M/Microsoft_RPC_programming_guide)
is a nice introduction to RPC programming on Windows. Most of it
can be directly applied to DCE/RPC just by changing the function
names.

*Other documentation*

The [RPC Internals](docs/rpc-internals.pdf) document is dated and
incomplete, but provides a useful insight into some of the source
code architecture and conventions.

The [porting guide](docs/rpc-porting.pdf) contains some historical
information about porting DCE/RPC to new platforms. It's not
particularly relevant any more, but it occasionally explains some
of the rationale for the strange things that you find in the source.
