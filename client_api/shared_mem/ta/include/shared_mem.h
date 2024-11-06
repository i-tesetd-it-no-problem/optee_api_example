#ifndef _SHARED_MEM_H
#define _SHARED_MEM_H

#define TA_SHARED_MEM_UUID \
	{ 0x79457d8a, 0xe919, 0x46f4, \
		{ 0x8a, 0xd1, 0xbb, 0x72, 0x43, 0x38, 0x8c, 0xc5} }

/* 
 * @brief : CA to TA
 *
 * param[0] (memref-input) : CA message
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define SHARED_MEM_CA_TO_TA 	0

/* 
 * @brief : TA to CA
 *
 * param[0] (memref-output) : TA message
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define SHARED_MEM_TA_TO_CA 	1

#endif /* _SHARED_MEM_H */
