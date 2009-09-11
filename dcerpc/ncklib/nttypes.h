/*
 * Copyright (c) 2008-2009 Apple Inc. All rights reserved.
 *
 */

#ifndef NTTYPES_H_32C6F7D1_F6C7_4EB2_999A_EB2EF3B82A57
#define NTTYPES_H_32C6F7D1_F6C7_4EB2_999A_EB2EF3B82A57

//#include "dtyp.h"
//#include "ntobject.hpp"

#if 0
typedef enum _COMPUTER_NAME_FORMAT {
    ComputerNameNetBIOS,
    ComputerNameDnsHostname,
    ComputerNameDnsDomain,
    ComputerNameDnsFullyQualified,
    ComputerNamePhysicalNetBIOS,
    ComputerNamePhysicalDnsHostname,
    ComputerNamePhysicalDnsDomain,
    ComputerNamePhysicalDnsFullyQualified,
    ComputerNameMax
} COMPUTER_NAME_FORMAT;

/*
 * MS-DTYP 2.4.1
 *
 * The SID_IDENTIFIER_AUTHORITY structure represents the top-level
 * authority of a security identifier (SID)
 */
typedef struct _SID_IDENTIFIER_AUTHORITY {
    uint8_t Value[6];
} SID_IDENTIFIER_AUTHORITY;

/*
 * MS-DTYP 2.4.2
 *
 * The SID structure defines a security identifier (SID), which is a
 * variable-length byte array that uniquely identifies a security
 * principal
 */
typedef struct _SID {
    uint8_t Revision;
    uint8_t SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    uint32_t SubAuthority[];
} SID;

/*
 * MS-DTYP 2.4.5
 *
 * The access control list, or ACL, is used to specify a list of individual
 * access control entries (ACEs).
 */
typedef struct _ACL {
    uint8_t AclRevision;
    uint8_t Sbz1;
    uint16_t AclSize;
    uint16_t AceCount;
    uint16_t Sbz2;
} ACL;

/*
 * MS-DTYP 2.4.4.1
 *
 * The ACE_HEADER structure defines the type and size of an access
 * control entry (ACE).
 */
typedef struct _ACE_HEADER {
    uint8_t AceType;
    uint8_t AceFlags;
    uint16_t AceSize;
} ACE_HEADER;

/*
 * MS-DTYP 2.4.4.2
 *
 * The ACCESS_ALLOWED_ACE structure defines an ACE for the discretionary
 * access control list (DACL) that controls access to an object. An
 * access-allowed ACE allows access to an object for a specific trustee
 * identified by a security identifier (SID).
 */
typedef struct _ACCESS_ALLOWED_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
} ACCESS_ALLOWED_ACE;

/*
 * MS-DTYP 2.4.4.4
 *
 * The ACCESS_DENIED_ACE structure defines an ACE for the discretionary
 * access-control list (DACL) that controls access to an object. An
 * access-denied ACE denies access to an object for a specific trustee
 * identified by a security identifier (SID).
 */
typedef struct _ACCESS_DENIED_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
} ACCESS_DENIED_ACE;

/*
 * MS-DTYP 2.4.4.9
 *
 * The SYSTEM_AUDIT_ACE structure defines an access control entry (ACE)
 * for the system access control list (SACL) that specifies what types
 * of access cause system-level notifications. A system- audit ACE
 * causes an audit message to be logged when a specified trustee
 * attempts to gain access to an object. The trustee is identified by
 * a security identifier (SID).
 */
typedef struct _SYSTEM_AUDIT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask ;
    uint32_t SidStart;
} SYSTEM_AUDIT_ACE;

typedef enum
{
    AclRevisionInformation,
    AclSizeInformation
} ACL_INFORMATION_CLASS;

typedef struct _ACL_REVISION_INFORMATION {
    uint32_t AclRevision;
} ACL_REVISION_INFORMATION;

typedef struct _ACL_SIZE_INFORMATION {
    uint32_t AceCount;
    uint32_t AclBytesInUse;
    uint32_t AclBytesFree;
} ACL_SIZE_INFORMATION;

typedef struct _GENERIC_MAPPING {
    ACCESS_MASK GenericRead;
    ACCESS_MASK GenericWrite;
    ACCESS_MASK GenericExecute;
    ACCESS_MASK GenericAll;
} GENERIC_MAPPING;

/*
 * MS-DTYP 2.4.6
 *
 * The SECURITY_DESCRIPTOR structure defines an object's security
 * attributes. These attributes specify who owns the object, who can
 * access the object and what they can do with it, what level of audit
 * logging should be applied to the object, and what kind of restrictions
 * apply to the use of the security descriptor.
 */

typedef struct _SECURITY_DESCRIPTOR {
    uint8_t Revision;
    uint8_t Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    SID * Owner;
    SID * Group;
    ACL * Sacl;
    ACL * Dacl;
} SECURITY_DESCRIPTOR;

/*
 * MS-NRPC 2.2.1.4.7 NETLOGON_SID_AND_ATTRIBUTES
 * MS-PAC 2.2.1 KERB_SID_AND_ATTRIBUTES
 */

typedef struct _SID_AND_ATTRIBUTES {
    SID * Sid;
    uint32_t Attributes;
} SID_AND_ATTRIBUTES;

typedef struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    uint32_t Attributes;
} LUID_AND_ATTRIBUTES;

#endif

typedef enum _CREATE_DISPOSITION
{
    FILE_SUPERSEDE      = 0,
    FILE_OPEN           = 1,
    FILE_CREATE         = 2,
    FILE_OPEN_IF        = 3,
    FILE_OVERWRITE      = 4,
    FILE_OVERWRITE_IF   = 5
} CREATE_DISPOSITION;

typedef enum _CREATE_ACTION
{
    FILE_SUPERSEDED     = 0,
    FILE_OPENED         = 1,
    FILE_CREATED        = 2,
    FILE_OVERWRITTEN    = 3
} CREATE_ACTION;

/* MS-SMB2 2.2.13. CreateOptions. */
typedef enum _CREATE_OPTIONS
{
    FILE_DIRECTORY_FILE             = 0x00000001,
    FILE_WRITE_THROUGH              = 0x00000002,
    FILE_SEQUENTIAL_ONLY            = 0x00000004,
    FILE_NO_INTERMEDIATE_BUFFERING  = 0x00000008,
    FILE_SYNCHRONOUS_IO_ALERT       = 0x00000010,
    FILE_SYNCHRONOUS_IO_NONALERT    = 0x00000020,
    FILE_NON_DIRECTORY_FILE         = 0x00000040,
    FILE_CREATE_TREE_CONNECTION     = 0x00000080,
    FILE_COMPLETE_IF_OPLOCKED       = 0x00000100,
    FILE_NO_EA_KNOWLEDGE            = 0x00000200,
    FILE_OPEN_FOR_RECOVERY          = 0x00000400,
    FILE_RANDOM_ACCESS              = 0x00000800,
    FILE_DELETE_ON_CLOSE            = 0x00001000,
    FILE_OPEN_BY_FILE_ID            = 0x00002000,
    FILE_OPEN_FOR_BACKUP_INTENT     = 0x00004000,
    FILE_NO_COMPRESSION             = 0x00008000,
    FILE_RESERVE_OPFILTER           = 0x00100000,
    FILE_OPEN_REPARSE_POINT         = 0x00200000,
    FILE_OPEN_NO_RECALL             = 0x00400000,
    FILE_OPEN_FOR_FREE_SPACE_QUERY  = 0x00800000
} CREATE_OPTIONS;

typedef enum _SHARE_ACCESS
{
    FILE_SHARE_READ     = 0x0001,
    FILE_SHARE_WRITE    = 0x0002,
    FILE_SHARE_DELETE   = 0x0004
} SHARE_ACCESS;


#if 0

/* MS-FSCC 2.5 FileSystem Information Classes.
 * Also see MSDN for ZwQueryVolumeInformationFile.
 */
typedef enum _FS_INFORMATION_CLASS
{
    FileFsVolumeInformation     = 1, /* Query */
    FileFsLabelInformation      = 2, /* Set */
    FileFsSizeInformation       = 3, /* Query */
    FileFsDeviceInformation     = 4, /* Query */
    FileFsAttributeInformation  = 5, /* Query */
    FileFsControlInformation    = 6, /* Query, Set */
    FileFsFullSizeInformation   = 7, /* Query */
    FileFsObjectIdInformation   = 8, /* Query, Set */
    FileFsDriverPathInformation = 9 /* Query */
} FS_INFORMATION_CLASS;

typedef enum _FS_ATTRIBUTES
{
    FILE_SUPPORTS_TRANSACTIONS      = 0x00200000,
    FILE_SEQUENTIAL_WRITE_ONCE      = 0x00100000,
    FILE_READ_ONLY_VOLUME           = 0x00080000,
    FILE_NAMED_STREAMS              = 0x00040000,
    FILE_SUPPORTS_ENCRYPTION        = 0x00020000,
    FILE_SUPPORTS_OBJECT_IDS        = 0x00010000,
    FILE_VOLUME_IS_COMPRESSED       = 0x00008000,
    FILE_SUPPORTS_REMOTE_STORAGE    = 0x00000100,
    FILE_SUPPORTS_REPARSE_POINTS    = 0x00000080,
    FILE_SUPPORTS_SPARSE_FILES      = 0x00000040,
    FILE_VOLUME_QUOTAS              = 0x00000020,
    FILE_FILE_COMPRESSION           = 0x00000010,
    FILE_PERSISTENT_ACLS            = 0x00000008,
    FILE_UNICODE_ON_DISK            = 0x00000004,
    FILE_CASE_PRESERVED_NAMES       = 0x00000002,
    FILE_CASE_SENSITIVE_SEARCH      = 0x00000001
} FS_ATTRIBUTES;

/*
 * MS-FSCC 2.6 File Attributes
 */
typedef enum _FILE_ATTRIBUTES
{
    FILE_ATTRIBUTE_READONLY     = 0x00000001,
    FILE_ATTRIBUTE_HIDDEN       = 0x00000002,
    FILE_ATTRIBUTE_SYSTEM       = 0x00000004,
    FILE_ATTRIBUTE_NORMAL       = 0x00000080,
    FILE_ATTRIBUTE_DIRECTORY    = 0x00000010,
    FILE_ATTRIBUTE_ARCHIVE      = 0x00000020,
    FILE_ATTRIBUTE_TEMPORARY    = 0x00000100,
    FILE_ATTRIBUTE_SPARSE_FILE  = 0x00000200,
    FILE_ATTRIBUTE_REPARSE_POINT= 0x00000400,
    FILE_ATTRIBUTE_COMPRESSED   = 0x00000800,
    FILE_ATTRIBUTE_OFFLINE      = 0x00001000,
    FILE_ATTRIBUTE_ENCRYPTED    = 0x00004000,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000,
} FILE_ATTRIBUTES;

typedef enum _FS_CONTROL_FLAGS
{
    FILE_VC_CONTENT_INDEX_DISABLED  = 0x00000008,
    FILE_VC_LOG_QUOTA_LIMIT         = 0x00000020,
    FILE_VC_LOG_QUOTA_THRESHOLD     = 0x00000010,
    FILE_VC_LOG_VOLUME_LIMIT        = 0x00000080,
    FILE_VC_LOG_VOLUME_THRESHOLD    = 0x00000040,
    FILE_VC_QUOTA_ENFORCE           = 0x00000002,
    FILE_VC_QUOTA_TRACK             = 0x00000001,
    FILE_VC_QUOTAS_INCOMPLETE       = 0x00000100,
    FILE_VC_QUOTAS_REBUILDING       = 0x00000200
} FS_CONTROL_FLAGS;

typedef enum _FS_DEVICE_CHARACTERISTICS
{
    FILE_REMOVABLE_MEDIA            = 0x00000001,
    FILE_READ_ONLY_DEVICE           = 0x00000002,
    FILE_FLOPPY_DISKETTE            = 0x00000004,
    FILE_WRITE_ONCE_MEDIA           = 0x00000008,
    FILE_REMOTE_DEVICE              = 0x00000010,
    FILE_DEVICE_IS_MOUNTED          = 0x00000020,
    FILE_VIRTUAL_VOLUME             = 0x00000040,
    FILE_AUTOGENERATED_DEVICE_NAME  = 0x00000080,
    FILE_DEVICE_SECURE_OPEN         = 0x00000100,
    FILE_CHARACTERISTIC_PNP_DEVICE  = 0x00000800,
    FILE_CHARACTERISTIC_TS_DEVICE   = 0x00001000,
    FILE_CHARACTERISTIC_WEBDAV_DEVICE=0x00002000
} FS_DEVICE_CHARACTERISTICS;

/* MS-FSCC 2.4.9 FileFsDeviceInformation, DeviceTypr
 * Also see Windows Driver Kit "Specifying Device Types".
 */
typedef enum _FS_DEVICE_TYPE
{
    FILE_DEVICE_CD_ROM              = 0x00000002,
    FILE_DEVICE_DISK                = 0x00000007

    /* There are many more device types, but according to MS-FSCC, only these
     * two are used. This smells fishy to me. I would not be surprised to see
     * DEVICE_TYPE_DVD on the wire, for example. -- jpeach
     */
} FS_DEVICE_TYPE;

/* MS-FSCC 2.4 File Information Classes */
typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation        = 1,
    FileFullDirectoryInformation    = 2,
    FileBothDirectoryInformation    = 3,
    FileBasicInformation            = 4,
    FileStandardInformation         = 5,
    FileInternalInformation         = 6,
    FileEaInformation               = 7,
    FileAccessInformation           = 8,
    FileNameInformation             = 9,
    FileRenameInformation           = 10,
    FileLinkInformation             = 11,
    FileNamesInformation            = 12,
    FileDispositionInformation      = 13,
    FilePositionInformation         = 14,
    FileFullEaInformation           = 15,
    FileModeInformation             = 16,
    FileAlignmentInformation        = 17,
    FileAllInformation              = 18,
    FileAllocationInformation       = 19,
    FileEndOfFileInformation        = 20,
    FileAlternateNameInformation    = 21,
    FileStreamInformation           = 22,
    FilePipeInformation             = 23,
    FilePipeLocalInformation        = 24,
    FilePipeRemoteInformation       = 25,
    FileMailslotQueryInformation    = 26,
    FileMailslotSetInformation      = 27,
    FileCompressionInformation      = 28,
    FileObjectIdInformation         = 29,
    FileMoveClusterInformation      = 31,
    FileQuotaInformation            = 32,
    FileReparsePointInformation     = 33,
    FileNetworkOpenInformation      = 34,
    FileAttributeTagInformation     = 35,
    FileTrackingInformation         = 36,
    FileIdBothDirectoryInformation  = 37,
    FileIdFullDirectoryInformation  = 38,
    FileValidDataLengthInformation  = 39,
    FileShortNameInformation        = 40,
    FileSfioReserveInformation      = 44,
    FileSfioVolumeInformation       = 45,
    FileHardLinkInformation         = 46,
    FileNormalizedNameInformation   = 48,
    FileIdGlobalTxDirectoryInformation = 50,
    FileStandardLinkInformation     = 54
} FILE_INFORMATION_CLASS;
#endif

#endif /* NTTYPES_H_32C6F7D1_F6C7_4EB2_999A_EB2EF3B82A57 */
/* vim: set sw=4 ts=4 tw=79 et: */
