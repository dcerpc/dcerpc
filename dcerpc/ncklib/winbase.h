/*
 * Copyright (c) 2008-2009 Apple Inc. All rights reserved.
 *
 */

#ifndef WINBASE_H_96F89FB8_DEB7_425D_8EF1_A396B1642F61
#define WINBASE_H_96F89FB8_DEB7_425D_8EF1_A396B1642F61

#if 0

struct timespec;

/*
 * Return the system time converted to a FILETIME based on the
 * Coordinated Universal Time,
 */
void GetSystemTimeAsFileTime(FILETIME *);

void ConvertTimespecToFileTime(const struct timespec *, FILETIME *);

/*
 * Returns the requested computer name. This works just like GetComputerNameEx
 * on Windows except that if the buffer is too small, it returns
 * STATUS_BUFFER_TOO_SMALL.
 */
NTSTATUS GetComputerNameEx(COMPUTER_NAME_FORMAT, utf8_t *, unsigned *);

/*
 * Allocate a new LUID.
 */
NTSTATUS AllocateLocallyUniqueId(LUID *luid);

#define SECURITY_NULL_SID_AUTHORITY 0
#define SECURITY_WORLD_SID_AUTHORITY    1
#define SECURITY_LOCAL_SID_AUTHORITY    2
#define SECURITY_CREATOR_SID_AUTHORITY  3
#define SECURITY_NON_UNIQUE_AUTHORITY   4
#define SECURITY_NT_AUTHORITY   5
#define SECURITY_RESOURCE_MANAGER_AUTHORITY 9

#define SID_MAX_SUB_AUTHORITIES 15

NTSTATUS
AllocateAndInitializeSid(
    const SID_IDENTIFIER_AUTHORITY * pIdentifierAuthority,
    uint8_t nSubAuthorityCount,
    uint32_t dwSubAuthority0,
    uint32_t dwSubAuthority1,
    uint32_t dwSubAuthority2,
    uint32_t dwSubAuthority3,
    uint32_t dwSubAuthority4,
    uint32_t dwSubAuthority5,
    uint32_t dwSubAuthority6,
    uint32_t dwSubAuthority7,
    SID ** pSid
);

void FreeSid(SID *);
void FreeSidString(utf8_t *);

bool IsValidSid(const SID *);

NTSTATUS CopySid(
    uint32_t    nDestinationSidLength,
    SID *       pDestinationSid,
    const SID * pSourceSid
);

bool EqualSid(const SID *, const SID *);

uint32_t GetLengthSid(const SID * pSid);
uint32_t GetSidLengthRequired(uint8_t nSubAuthorityCount);

/*
 * ConvertStringSidToSid and ConvertSidToStringSid
 *
 * Normally, we would expect these functions to operate with UTF16
 * strings, however we most commonly deal with SIDs in binary form,
 * so the onus is on the caller to convert from UTF16 if necessary.
 *
 * XXX we may need to revisit this decision -- jpeach
 */

NTSTATUS ConvertStringSidToSid(
    const utf8_t * stringsid,
    SID ** Sid
);

NTSTATUS ConvertSidToStringSid(
    const SID * Sid,
    utf8_t ** StringSid
);

/*
 * MS-DTYPE 2.4.4.1 AceFlags
 */
#define OBJECT_INHERIT_ACE          0x01
#define CONTAINER_INHERIT_ACE       0x02
#define NO_PROPAGATE_INHERIT_ACE    0x04
#define INHERIT_ONLY_ACE            0x08
#define INHERITED_ACE               0x10

#define SUCCESSFUL_ACCESS_ACE_FLAG  0x40
#define FAILED_ACCESS_ACE_FLAG      0x80

/*
 * MS-DTYPE 2.4.4.1 AceType
 */
#define ACCESS_ALLOWED_ACE_TYPE     0x0
#define ACCESS_DENIED_ACE_TYPE      0x1
#define SYSTEM_AUDIT_ACE_TYPE       0x2

#define ACL_REVISION 2

NTSTATUS InitializeAcl(
    ACL * pAcl,
    uint32_t nAclLength,
    uint32_t dwAclRevision
);

NTSTATUS IsValidAcl(const ACL * pAcl);

NTSTATUS GetAce(
    const ACL * pAcl,
    unsigned dwAceIndex,
    const ACE_HEADER ** pAce
);

NTSTATUS GetAclInformation(
    const ACL * pAcl,
    void * pAclInformation,
    size_t nAclInformationLength,
    ACL_INFORMATION_CLASS dwAclInformationClass
);

NTSTATUS AddAccessAllowedAceEx(
    ACL * pAcl,
    uint32_t dwAceRevision,
    uint32_t AceFlags,
    uint32_t AccessMask,
    const SID * pSid
);

static inline NTSTATUS
AddAccessAllowedAce(
        ACL * pAcl,
        uint32_t dwAceRevision,
        uint32_t AccessMask,
        const SID * pSid)
{
    return AddAccessAllowedAceEx(pAcl, dwAceRevision, 0, AccessMask, pSid);
}

NTSTATUS AddAccessDeniedAceEx(
    ACL * pAcl,
    uint32_t dwAceRevision,
    uint32_t AceFlags,
    uint32_t AccessMask,
    const SID * pSid
);

static inline NTSTATUS
AddAccessDeniedAce(
        ACL * pAcl,
        uint32_t dwAceRevision,
        uint32_t AccessMask,
        const SID * pSid)
{
    return AddAccessDeniedAceEx(pAcl, dwAceRevision, 0, AccessMask, pSid);
}

NTSTATUS AddAuditAccessAceEx(
    ACL * pAcl,
    uint32_t dwAceRevision,
    uint32_t AceFlags,
    ACCESS_MASK dwAccessMask,
    const SID * pSid,
    bool bAuditSuccess,
    bool bAuditFailure
);

static inline NTSTATUS
AddAuditAccessAce(
        ACL * pAcl,
        uint32_t dwAceRevision,
        uint32_t dwAccessMask,
        const SID * pSid,
        bool bAuditSuccess,
        bool bAuditFailure)
{
    return AddAuditAccessAceEx(pAcl, dwAceRevision, 0, dwAccessMask,
            pSid, bAuditSuccess, bAuditFailure);
}

NTSTATUS FindFirstFreeAce(
    const ACL * pAcl,
    void ** pAce
);


#endif


/*
 * Access mask encoding:
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | | | | | | | | | | |1| | | | | | | | | |2| | | | | | | | | |3| |
 * |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |R|W|E|A|   |M|S|  standard     |  specific                     |
 * +-------+-------+---------------+-------------------------------+
 *
 * R => generic read
 * W => generic write
 * E => generic execute
 * A => generic all
 * S => SACL access (ACCESS_SYSTEM_SECURITY)
 * M => maximal access
 */

/* Generic rights. */
#define GENERIC_ALL             0x10000000
#define GENERIC_EXECUTE         0x20000000
#define GENERIC_WRITE           0x40000000
#define GENERIC_READ            0x80000000
#define ACCESS_SYSTEM_SECURITY  0x01000000
#define MAXIMUM_ALLOWED         0x02000000

/* Standard rights. */
#define DELETE                  0x00010000
#define READ_CONTROL            0x00020000
#define WRITE_DAC               0x00040000
#define WRITE_OWNER             0x00080000
#define SYNCHRONIZE             0x00100000

#define STANDARD_RIGHTS_REQUIRED ( \
    DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER \
)

#define STANDARD_RIGHTS_ALL ( \
    DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE \
)

/* File-specific rights. */
#define FILE_LIST_DIRECTORY         0x00000001
#define FILE_READ_DATA              0x00000001
#define FILE_ADD_FILE               0x00000002
#define FILE_WRITE_DATA             0x00000002
#define FILE_ADD_SUBDIRECTORY       0x00000004
#define FILE_APPEND_DATA            0x00000004
#define FILE_CREATE_PIPE_INSTANCE   0x00000004
#define FILE_READ_EA                0x00000008
#define FILE_READ_PROPERTIES        0x00000008
#define FILE_WRITE_EA               0x00000010
#define FILE_WRITE_PROPERTIES       0x00000010
#define FILE_EXECUTE                0x00000020
#define FILE_TRAVERSE               0x00000020
#define FILE_DELETE_CHILD           0x00000040
#define FILE_READ_ATTRIBUTES        0x00000080
#define FILE_WRITE_ATTRIBUTES       0x00000100

#define FILE_ALL_ACCESS (STANDARD_RIGHTS_ALL | 0x000001FF)

#define FILE_GENERIC_EXECUTE ( \
        READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE )

#define FILE_GENERIC_READ ( \
    READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_DATA | \
    FILE_READ_EA | SYNCHRONIZE \
)

#define FILE_GENERIC_WRITE ( \
    READ_CONTROL | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | \
    FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE \
)



#if 0

#define SECURITY_DESCRIPTOR_REVISION 1

/*
 * MS-DTYPE 2.4.6 Security Descriptor Control Flags
 */
#define SE_OWNER_DEFAULTED          0x0001
#define SE_GROUP_DEFAULTED          0x0002
#define SE_DACL_PRESENT             0x0004
#define SE_DACL_DEFAULTED           0x0008
#define SE_SACL_PRESENT             0x0010
#define SE_SACL_DEFAULTED           0x0020
#define SE_SERVER_SECURITY          0x0040
#define SE_DACL_TRUSTED             0x0080
#define SE_DACL_AUTO_INHERIT_REQ    0x0100
#define SE_SACL_AUTO_INHERIT_REQ    0x0200
#define SE_DACL_AUTO_INHERITED      0x0400
#define SE_SACL_AUTO_INHERITED      0x0800
#define SE_DACL_PROTECTED           0x1000
#define SE_SACL_PROTECTED           0x2000
#define SE_RM_CONTROL_VALID         0x4000
#define SE_SELF_RELATIVE            0x8000

NTSTATUS InitializeSecurityDescriptor(
    SECURITY_DESCRIPTOR * pSecurityDescriptor,
    uint32_t dwRevision
);

NTSTATUS
SetSecurityDescriptorDacl(
    SECURITY_DESCRIPTOR * pSecurityDescriptor,
    bool bDaclPresent,
    ACL * pDacl,
    bool bDaclDefaulted
);

NTSTATUS
SetSecurityDescriptorSacl(
    SECURITY_DESCRIPTOR * pSecurityDescriptor,
    bool bSaclPresent,
    ACL * pSacl,
    bool bSaclDefaulted
);

NTSTATUS
SetSecurityDescriptorGroup(
    SECURITY_DESCRIPTOR * pSecurityDescriptor,
    SID * pGroup,
    bool bGroupDefaulted
);

NTSTATUS
SetSecurityDescriptorOwner(
    SECURITY_DESCRIPTOR * pSecurityDescriptor,
    SID * pOwner,
    bool bOwnerDefaulted
);

NTSTATUS
MakeAbsoluteSD(
    SECURITY_DESCRIPTOR * pSelfRelativeSD,
    SECURITY_DESCRIPTOR * pAbsoluteSD,
    uint32_t *  lpdwAbsoluteSDSize,
    ACL *       pDacl,
    uint32_t *  lpdwDaclSize,
    ACL *       pSacl,
    uint32_t *  lpdwSaclSize,
    SID *       pOwner,
    uint32_t *  lpdwOwnerSize,
    SID *       pPrimaryGroup,
    uint32_t *  lpdwPrimaryGroupSize
);

NTSTATUS
MakeSelfRelativeSD(
    const SECURITY_DESCRIPTOR * pAbsoluteSD,
    SECURITY_DESCRIPTOR * pSelfRelativeSD,
    uint32_t * lpdwBufferLength
);

NTSTATUS
GetSecurityDescriptorControl(
    const SECURITY_DESCRIPTOR * pSecurityDescriptor,
    SECURITY_DESCRIPTOR_CONTROL * pControl,
    uint32_t * lpdwRevision
);

NTSTATUS
GetSecurityDescriptorDacl(
    SECURITY_DESCRIPTOR * pSecurityDescriptor,
    bool * lpbDaclPresent,
    ACL ** pDacl,
    bool * lpbDaclDefaulted
);

NTSTATUS
GetSecurityDescriptorGroup(
    SECURITY_DESCRIPTOR * pSecurityDescriptor,
    SID ** pGroup,
    bool * lpbGroupDefaulted
);

NTSTATUS
GetSecurityDescriptorOwner(
    SECURITY_DESCRIPTOR * pSecurityDescriptor,
    SID ** pOwner,
    bool * lpbOwnerDefaulted
);

NTSTATUS
GetSecurityDescriptorSacl(
    SECURITY_DESCRIPTOR * pSecurityDescriptor,
    bool * lpbSaclPresent,
    ACL ** pSacl,
    bool * lpbSaclDefaulted
);

uint32_t GetSecurityDescriptorLength(
    const SECURITY_DESCRIPTOR * pSecurityDescriptor
);

void MapGenericMask(
    ACCESS_MASK * AccessMask,
    const GENERIC_MAPPING * GenericMapping
);

NTSTATUS
ConvertStringSecurityDescriptorToSecurityDescriptor(
    const utf8_t *          StringSecurityDescriptor,
    uint32_t                StringSDRevision,
    SECURITY_DESCRIPTOR **  SecurityDescriptor,
    uint32_t *              SecurityDescriptorSize
);

NTSTATUS
ConvertSecurityDescriptorToStringSecurityDescriptor(
    const SECURITY_DESCRIPTOR * SecurityDescriptor,
    uint32_t                    RequestedStringSDRevision,
    uint32_t                    SecurityInformation,
    utf8_t **                   StringSecurityDescriptor,
    uint32_t *                  StringSecurityDescriptorLen
);

NTSTATUS
ImpersonateLoggedOnUser(
    const HANDLE& TokenHandle
);

// In real Win32, we would pass a thread HANDLE to ImpersonateAnonymousToken,
// but I don't know of any Unix system that allows you to set the credentials
// on a thread other than your own, so I've left the parameter out for now.
//      -- jpeach

NTSTATUS
ImpersonateAnonymousToken();

NTSTATUS
RevertToSelf(void);
#endif


#endif /* WINBASE_H_96F89FB8_DEB7_425D_8EF1_A396B1642F61 */
/* vim: set sw=4 ts=4 tw=79 et: */
