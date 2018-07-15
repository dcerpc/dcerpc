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
 * Packard Company or Digital Equipment Corporation be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.  Neither Open Software
 * Foundation, Inc., Hewlett-Packard Company nor Digital
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
 * 3.  Neither the name of Novell Inc. nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     this software without specific prior written permission.
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

/*++                                                                          */
/*!                                                                           */
/*!  NAME:                                                                    */
/*!                                                                           */
/*!      nidlmsg.msg                                                          */
/*!                                                                           */
/*!  FACILITY:                                                                */
/*!                                                                           */
/*!      Interface Definition Language (IDL) Compiler                         */
/*!                                                                           */
/*!  ABSTRACT:                                                                */
/*!                                                                           */
/*!  RPC IDL Compiler messages.                                               */
/*!                                                                           */
/*!                                                                           */
/*!                                                                           */
/*!                                                                           */
/*--                                                                          */
/*+                                                                           */
/* These two symbols must have the same integer value.                        */
/*-                                                                           */
#define NIDL_MESSAGE_VERSION_USED 2074

/* Error codes literals for IDL */

#define CAT_SET 1
#define NIDL_MESSAGE_VERSION 1
#define NIDL_CMDERR 2
#define NIDL_DEFAUTOHAN 3
#define NIDL_FILESOURCE 4
#define NIDL_FLOATPROM 5
#define NIDL_IMPORTIDL 6
#define NIDL_INCLCREATE 7
#define NIDL_LEGALVALS 8
#define NIDL_LINEFILE 9
#define NIDL_NAMEDECLAT 10
#define NIDL_NAMEREFAT 11
#define NIDL_NEWUUID 12
#define NIDL_OPTIONSTABLE 13
#define NIDL_PROCESSACF 14
#define NIDL_RUNCPP 15
#define NIDL_STUBCOMPILE 16
#define NIDL_STUBCREATE 17
#define NIDL_STUBDELETE 18
#define NIDL_TYPEREPAS 19
#define NIDL_USAGE 20
#define NIDL_VERSION 21
#define NIDL_DUPPROTOCOL 22
#define NIDL_ENDPOINTSYNTAX 23
#define NIDL_EXTRAPUNCT 24
#define NIDL_FPHANATTR 25
#define NIDL_IDTOOLONG 26
#define NIDL_INCLUDEXT 27
#define NIDL_INCLTYPE 28
#define NIDL_INTSIZEREQ 29
#define NIDL_LINENONSCAL 30
#define NIDL_MISSPTRCLASS 31
#define NIDL_MIXEDARRATTR 32
#define NIDL_MULATTRDEF 33
#define NIDL_NAMETOOLONG 34
#define NIDL_NOCODEOPS 35
#define NIDL_NOENDPOINT 36
#define NIDL_NONPORTCHAR 37
#define NIDL_NOSEMCHECK 38
#define NIDL_OLDUUID 39
#define NIDL_OUTDIRIGN 40
#define NIDL_REFUNIQUE 41
#define NIDL_SRVNOCODE 42
#define NIDL_SYSIDLNAME 43
#define NIDL_ANONPIPE 44
#define NIDL_ANONTYPE 45
#define NIDL_ARMREFPTR 46
#define NIDL_ARRELEMCFMT 47
#define NIDL_ARRELEMCTX 48
#define NIDL_ARRELEMPIPE 49
#define NIDL_ARRSIZEINFO 50
#define NIDL_ARRCFMTDIM 51
#define NIDL_ARRPTRPRM 52
#define NIDL_ARRSYNTAX 53
#define NIDL_ARRVARYDIM 54
#define NIDL_ARRXMITOPEN 55
#define NIDL_ATTRTRANS 56
#define NIDL_ATTRVALIND 57
#define NIDL_BADTAGREF 58
#define NIDL_BROADPIPE 59
#define NIDL_CASEDISCTYPE 60
#define NIDL_CASECONENUM 61
#define NIDL_CFMTARRREF 62
#define NIDL_CFMTBASETYP 63
#define NIDL_CFMTFLDLAST 64
#define NIDL_CFMTUNION 65
#define NIDL_CONFHANATTR 66
#define NIDL_CONFLINEATTR 67
#define NIDL_CONFLICTATTR 68
#define NIDL_CONFREPRTYPE 69
#define NIDL_CONSTNOTFND 70
#define NIDL_CONSTTYPE 71
#define NIDL_HYPERCONST 72
#define NIDL_MISSONINTER 73
#define NIDL_MISSONATTR 74
#define NIDL_MISSONARR 75
#define NIDL_MISSONOP 76
#define NIDL_MISSONPARAM 77
#define NIDL_CTXBASETYP 78
#define NIDL_CTXPTRVOID 79
#define NIDL_CTXSTRFLD 80
#define NIDL_CTXUNIMEM 81
#define NIDL_DEFNOTCOMP 82
#define NIDL_DUPCASEVAL 83
#define NIDL_EOF 84
#define NIDL_EOFNEAR 85
#define NIDL_ERRINATTR 86
#define NIDL_ERRSTATDEF 87
#define NIDL_FILENOTDIR 88
#define NIDL_FILENOTFND 89
#define NIDL_FIRSTINATTR 90
#define NIDL_FIRSTYPEINT 91
#define NIDL_FLOATCONSTNOSUP 92
#define NIDL_FPCFMTARR 93
#define NIDL_FPLOCINT 94
#define NIDL_FPHANPRM 95
#define NIDL_FPINPRM 96
#define NIDL_FPPIPEBASE 97
#define NIDL_FPSTRFLD 98
#define NIDL_FPUNIMEM 99
#define NIDL_FUNTYPDCL 100
#define NIDL_HANARRELEM 101
#define NIDL_HANDLEIN 102
#define NIDL_HANDLEPTR 103
#define NIDL_HANFIRSTPRM 104
#define NIDL_HANPIPEBASE 105
#define NIDL_HANPRMIN 106
#define NIDL_HANSTRFLD 107
#define NIDL_HANUNIMEM 108
#define NIDL_HANXMITAS 109
#define NIDL_IDEMPIPE 110
#define NIDL_IGNARRELEM 111
#define NIDL_IGNATTRPTR 112
#define NIDL_ILLFIELDATTR 113
#define NIDL_ILLPARAMATTR 114
#define NIDL_ILLTYPEATTR 115
#define NIDL_ILLOPATTR 116
#define NIDL_ILLINTATTR 117
#define NIDL_ILLMEMATTR 118
#define NIDL_IMPHANVAR 119
#define NIDL_IMPORTLOCAL 120
#define NIDL_INCOMPATV1 121
#define NIDL_INTCODEATTR 122
#define NIDL_INTDIVBY0 123
#define NIDL_INTLINEATTR 124
#define NIDL_INTNAMDIF 125
#define NIDL_INTOVERFLOW 126
#define NIDL_INTCONSTINVAL 127
#define NIDL_INTUUIDREQ 128
#define NIDL_INVARRIND 129
#define NIDL_INVCASETYP 130
#define NIDL_INVCHARLIT 131
#define NIDL_INVOCTDIGIT 132
#define NIDL_INVOKECPP 133
#define NIDL_INVOOLPRM 134
#define NIDL_INVOPTION 135
#define NIDL_INVPARAMS 136
#define NIDL_INVPTRCTX 137
#define NIDL_INVPTRPIPE 138
#define NIDL_LASTINATTR 139
#define NIDL_LASTLENCONF 140
#define NIDL_LASTYPEINT 141
#define NIDL_LBLESSUB 142
#define NIDL_LENINATTR 143
#define NIDL_LENTYPEINT 144
#define NIDL_MAJORTOOLARGE 145
#define NIDL_MAXCFMTYPE 146
#define NIDL_MAXIDINTF 147
#define NIDL_MAXIDTYPTA 148
#define NIDL_MAXIDTYPHAN 149
#define NIDL_MAXIDTYPCH 150
#define NIDL_MAXIDTYPPT 151
#define NIDL_MAXIDTYPPIPE 152
#define NIDL_MAXIDTYPRA 153
#define NIDL_MAXIDTYPOOL 154
#define NIDL_MAXINATTR 155
#define NIDL_MAXSIZEATTR 156
#define NIDL_MAXSIZECONF 157
#define NIDL_MAXTYPEINT 158
#define NIDL_MAYBEOUTPRM 159
#define NIDL_MINATTREQ 160
#define NIDL_MINCFMTYPE 161
#define NIDL_MININATTR 162
#define NIDL_MINORTOOLARGE 163
#define NIDL_MINTYPEINT 164
#define NIDL_NAMEALRDEC 165
#define NIDL_NAMENOTCONST 166
#define NIDL_NAMENOTFIELD 167
#define NIDL_NAMENOTFND 168
#define NIDL_NAMENOTPARAM 169
#define NIDL_NAMENOTTYPE 170
#define NIDL_NAMEPREVDECLAT 171
#define NIDL_NLSCATVER 172
#define NIDL_NLSWRONG 173
#define NIDL_NONINTEXP 174
#define NIDL_NYSALIGN 175
#define NIDL_NYSINSHAPE 176
#define NIDL_NYSNONZEROLB 177
#define NIDL_NYSOUTSHAPE 178
#define NIDL_NYSUNIQUE 179
#define NIDL_OPCODEATTR 180
#define NIDL_OPENREAD 181
#define NIDL_OPENWRITE 182
#define NIDL_OPNOTDEF 183
#define NIDL_OUTCFMTARR 184
#define NIDL_OUTPRMREF 185
#define NIDL_OUTPTRPRM 186
#define NIDL_OUTUNIQUE 187
#define NIDL_OPRESPIPE 188
#define NIDL_OUTSTAR 189
#define NIDL_OUTUNIQPRM 190
#define NIDL_PIPEBASETYP 191
#define NIDL_PIPESTRFLD 192
#define NIDL_PIPEUNIMEM 193
#define NIDL_PIPEXMITAS 194
#define NIDL_PRMBYREF 195
#define NIDL_PRMINOROUT 196
#define NIDL_PRMLINEATTR 197
#define NIDL_PRMNOTDEF 198
#define NIDL_PTRATTRHAN 199
#define NIDL_PTRATTRPTR 200
#define NIDL_PTRBASETYP 201
#define NIDL_PTRCFMTARR 202
#define NIDL_PTRCTXHAN 203
#define NIDL_PTRPIPE 204
#define NIDL_PTRV1ENUM 205
#define NIDL_PTRVARYARR 206
#define NIDL_PTRVOIDCTX 207
#define NIDL_REFATTRPTR 208
#define NIDL_REFFUNRES 209
#define NIDL_RENAMEFAILED 210
#define NIDL_REPASNEST 211
#define NIDL_SCOPELVLS 212
#define NIDL_SIZEARRTYPE 213
#define NIDL_SIZECFMTYPE 214
#define NIDL_SIZEINATTR 215
#define NIDL_SIZEMISMATCH 216
#define NIDL_SIZEPRMPTR 217
#define NIDL_SIZETYPEINT 218
#define NIDL_SIZEVARREPAS 219
#define NIDL_SIZEVARXMITAS 220
#define NIDL_SMALLARRSYN 221
#define NIDL_SMALLCFMT 222
#define NIDL_SMALLINV 223
#define NIDL_SMALLMINFIRST 224
#define NIDL_SMALLMULTID 225
#define NIDL_SMALLOPENLB 226
#define NIDL_STRARRAY 227
#define NIDL_STRARRAYV1 228
#define NIDL_STRCHARBYTE 229
#define NIDL_STRUCTXMITCFMT 230
#define NIDL_STRUNTERM 231
#define NIDL_STRV1ARRAY 232
#define NIDL_STRV1FIXED 233
#define NIDL_STRVARY 234
#define NIDL_STSATTRONCE 235
#define NIDL_STSPRMOUT 236
#define NIDL_STSRETVAL 237
#define NIDL_STSVARTYPE 238
#define NIDL_SYNTAXERR 239
#define NIDL_SYNTAXNEAR 240
#define NIDL_SYNTAXUUID 241
#define NIDL_SYSERRMSG 242
#define NIDL_TOOMANYELEM 243
#define NIDL_TOOMANYPORT 244
#define NIDL_TYPENOTFND 245
#define NIDL_TYPLINEATTR 246
#define NIDL_TYPNOTDEF 247
#define NIDL_UNBALPARENS 248
#define NIDL_UNBALBRACKETS 249
#define NIDL_UNBALBRACES 250
#define NIDL_UNIDISCTYP 251
#define NIDL_UNIQATTRHAN 252
#define NIDL_UNIQATTRPTR 253
#define NIDL_UNIQCTXHAN 254
#define NIDL_UNIQFUNRES 255
#define NIDL_UNKNOWNATTR 256
#define NIDL_USETRANS 257
#define NIDL_UUIDINV 258
#define NIDL_VARDECLNOSUP 259
#define NIDL_VOIDOPPTR 260
#define NIDL_XMITASREP 261
#define NIDL_XMITCFMTARR 262
#define NIDL_XMITPIPEBASE 263
#define NIDL_XMITPTR 264
#define NIDL_XMITTYPEATTRS 265
#define NIDL_BUGNOBUG 266
#define NIDL_COMMENTEOF 267
#define NIDL_COMPABORT 268
#define NIDL_INTERNAL_ERROR 269
#define NIDL_INVBUG 270
#define NIDL_INVNOBUG 271
#define NIDL_MAXWARN 272
#define NIDL_OPTNOVAL 273
#define NIDL_OUTOFMEM 274
#define NIDL_SRCFILELEN 275
#define NIDL_SRCFILEREQ 276
#define NIDL_UNKFLAG 277
#define NIDL_NOPORTNEU 278
#define NIDL_NOPORTUNIQUE 279
#define NIDL_DISCRIMIN 280
#define NIDL_DISCRIMOUT 281
#define NIDL_DISCRIMREPAS 282
#define NIDL_DISCRIMXMITAS 283
#define NIDL_EUMEMATTR 284
#define NIDL_NEUARRAY 285
#define NIDL_NEUREPAS 286
#define NIDL_NEUREPTYPE 287
#define NIDL_NEUSWATTR 288
#define NIDL_NEUSWPTR 289
#define NIDL_NEUSWTYPE 290
#define NIDL_NEUXMITAS 291
#define NIDL_NEUXMITYPE 292
#define NIDL_PTRNEUNION 293
#define NIDL_SWATTRNEU 294
#define NIDL_SWDATATYPE 295
#define NIDL_SWTYPENEU 296
#define NIDL_STDLTYPREQ 297
#define NIDL_FLDXMITCFMT 298
#define NIDL_TYPEREPCFMT 299
#define NIDL_ARMUNIQUEPTR 300
#define NIDL_FORPOINTER 301
#define NIDL_FORSIGNINT 302
#define NIDL_LANGCFMTSTRCT 303
#define NIDL_LANGCFMTSTRNG 304
#define NIDL_LANGMAPCHAR 305
#define NIDL_LANGPIPESNS 306
#define NIDL_LANGUNSFNRS 307
#define NIDL_LANGMAXDIM 308
#define NIDL_LANGMIXCASE 309
#define NIDL_LANGATTRNS 310
#define NIDL_ARRFUNRES 311
#define NIDL_ATTRPTRVOID 312
#define NIDL_HANATTRTRAN 313
#define NIDL_FWDTAGREF 314
#define NIDL_ATTRUSEMULT 315
#define NIDL_TYPEATTRUSE 316
#define NIDL_NOPORTNZLB 317
#define NIDL_TEMPLATECREATE 318
#define NIDL_NOPORTCFMT 319
#define NIDL_NOPORTVARY 320
#define NIDL_REPAS_COMMENT 321
#define NIDL_XMITAS_COMMENT 322
#define NIDL_BINDING_COMMENT 323
#define NIDL_RUNDOWN_COMMENT 324
#define NIDL_CLIENTTEMPLATE_COMMENT 325
#define NIDL_MANAGERTEMPLATE_COMMENT 326
#define NIDL_MANAGER_COMMENT 327
#define NIDL_ENCNOPARAMS 328
#define NIDL_DECNOPARAMS 329
#define NIDL_OPREFDELIN 330
#define NIDL_ENCOUTONLY 331
#define NIDL_DECINONLY 332
#define NIDL_ENCDECDIR 333
#define NIDL_ENCDECPIPE 334
#define NIDL_ENCDECBIND 335
#define NIDL_EXCNOTDEF 336
#define NIDL_INVFILESPEC 337
#define NIDL_FILESPECREQ 338
#define NIDL_OPNOTAGS 339
#define NIDL_TYPENEST 340
#define NIDL_DUPPRMATTR 341
#define NIDL_OPINCSCHAR 342
#define NIDL_OPOUTCSCHAR 343
#define NIDL_ARRATTRSHR 344
#define NIDL_ATTROUTCFMTCS 345
#define NIDL_CSARRSYN 346
#define NIDL_ARRPTRUNIQ 347
#define NIDL_XMITCTYPE 348
#define NIDL_TAGBEFDATA 349
#define NIDL_TAGAFTDATA 350
#define NIDL_HANCTYPE 351
#define NIDL_PIPECTYPE 352
#define NIDL_ARRMULTID 353
#define NIDL_ARRTYPATTR 354
#define NIDL_TYPECTYPE 355
#define NIDL_TYPEOFBYTES 356
#define NIDL_TAGPRMTYPE 357
#define NIDL_MAXIDTYPE 358
#define NIDL_NOPORTEXCEP 359
#define NIDL_NOPORTATTR 360
#define NIDL_PRMDEPATTR 361
#define NIDL_CPPCMDOPT 362
#define NIDL_NOPORTANON 363
#define NIDL_NOFLTPARAM 364
#define NIDL_ANCREQSOBJ 365
#define NIDL_INTREFNOTALO 366
#define NIDL_PTRATTBIGN 367
#define NIDL_INHERITNOTDEF 368
#define NIDL_EXPNOTCONST	369
#define NIDL_EXP_IS_NULL	370
#define NIDL_ONLYSIMPLEEXP	371
#define NIDL_INVALIDRANGE	372
#define NIDL_RANGEATTR		373
#define NIDL_CONSTREQ		374
#define NIDL_NOCORRELCHECK      375
