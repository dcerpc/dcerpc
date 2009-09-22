/*
 * Copyright (c) 2008-2009 Apple Inc. All rights reserved.
 *
 */

#ifndef _NTTYPES_H
#define _NTTYPES_H

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

#endif /* _NTTYPES_H */
/* vim: set sw=4 ts=4 tw=79 et: */
