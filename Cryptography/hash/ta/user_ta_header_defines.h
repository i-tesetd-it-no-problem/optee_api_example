/*
 * The name of this file must not be modified
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <include/hash.h>

#define TA_UUID			TA_HASH_UUID

#define TA_FLAGS			(TA_FLAG_EXEC_DDR | TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION)

#define TA_STACK_SIZE		(2 * 1024)

#define TA_DATA_SIZE		(32 * 1024)

#endif /* USER_TA_HEADER_DEFINES_H */
