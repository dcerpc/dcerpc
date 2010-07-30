/*
 * Copyright (c) 2010 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Inc. ("Apple") nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Portions of this software have been released under the following terms:
 *
 * (c) Copyright 1989-1993 OPEN SOFTWARE FOUNDATION, INC.
 * (c) Copyright 1989-1993 HEWLETT-PACKARD COMPANY
 * (c) Copyright 1989-1993 DIGITAL EQUIPMENT CORPORATION
 *
 * To anyone who acknowledges that this file is provided "AS IS"
 * without any express or implied warranty:
 * permission to use, copy, modify, and distribute this file for any
 * purpose is hereby granted without fee, provided that the above
 * copyright notices and this notice appears in all source code copies,
 * and that none of the names of Open Software Foundation, Inc., Hewlett-
 * Packard Company, Apple Inc. or Digital Equipment Corporation be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.  Neither Open Software
 * Foundation, Inc., Hewlett-Packard Company, Apple Inc. nor Digital
 * Equipment Corporation makes any representations about the suitability
 * of this software for any purpose.
 *
 * Copyright (c) 2007, Novell, Inc. All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Novell Inc. ("Apple") nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * 3. Neither the name of the Novell, Inc. nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
**
**  NAME:
**
**      wc16str.c
**
**  FACILITY:
**
**      Microsoft RPC compatibility wrappers.
**
**  ABSTRACT:
**
**  This module converts between UTF8 and UTF16 encodings.
**
*/

#include "compat/mswrappers.h"

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <CoreFoundation/CFStringEncodingConverter.h>
#include <stdlib.h>
#include <string.h>

#include "wc16str.h"

#define CONVERSION_FLAGS ( \
    kCFStringEncodingAllowLossyConversion \
)

static size_t
wchar16_strlen(const wchar16_t *source)
{
    size_t len = 0;

    while (*source++) {
        ++len;
    }

    return len;
}

/* Convert from UTF16 (native endian) to UTF16. */
char *
awc16stombs(const wchar16_t * input)
{
    CFIndex inputlen = wchar16_strlen(input);
    char * output;

    uint32_t ret;
    CFIndex produced = 0;   // output units produced

    output = malloc(3 * (inputlen + 1));
    if (output == NULL) {
	return NULL;
    }

    ret = CFStringEncodingUnicodeToBytes(
	    kCFStringEncodingUTF8,
	    CONVERSION_FLAGS,
	    input, inputlen,
	    &inputlen,
	    (uint8_t *)output, inputlen * 3,
	    &produced);

    if (ret != kCFStringEncodingConversionSuccess) {
	free(output);
	return NULL;
    }

    output[produced] = '\0';
    return output;
}

wchar16_t *
ambstowc16s(const char * input)
{
    CFIndex inputlen = strlen(input);
    wchar16_t * output;

    uint32_t ret;
    CFIndex produced = 0;   // output units produced

    output = malloc(sizeof(wchar16_t) *(inputlen + 1));
    if (output == NULL) {
	return NULL;
    }

    ret = CFStringEncodingBytesToUnicode(
	    kCFStringEncodingUTF8,
	    CONVERSION_FLAGS,
	    (const uint8_t *)input, inputlen,
	    &inputlen,
	    output, inputlen * sizeof(wchar16_t),
	    &produced);

    if (ret != kCFStringEncodingConversionSuccess) {
	free(output);
	return NULL;
    }

    output[produced] = '\0';
    return output;
}
