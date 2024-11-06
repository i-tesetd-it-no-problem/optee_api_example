#ifndef _SECURE_STORAGE_H
#define _SECURE_STORAGE_H

#define TA_SECURE_STORAGE_UUID \
	{ 0xef83682b, 0x8a80, 0x45e0, \
		{ 0x99, 0x93, 0xae, 0x58, 0x3a, 0x38, 0x66, 0x28} }

/* 
 * @brief : create a persistent object in TEE
 *
 * param[0] (memerf-input) 		: object name
 * param[1] (value-input)		: a : size
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define SECURE_STORAGE_CMD_CREATE			0

/* 
 * @brief : rename a persistent object
 *
 * param[0] (memerf-input) 		: origin name of the object
 * param[0] (memerf-input) 		: new name of the object
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define SECURE_STORAGE_CMD_RENAME			1

/* 
 * @brief : seek
 *
 * param[0] (memerf-input) 		: object name
 * param[0] (value-input) 		: a : offset, b : whence
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define SECURE_STORAGE_CMD_SEEK				2

/* 
 * @brief : write data to a persistent object
 *
 * param[0] (memerf-input) 		: object name
 * param[1] (memerf-input) 		: data to be written
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define SECURE_STORAGE_CMD_WRITE			3

/* 
 * @brief : read data from a persistent object
 *
 * param[0] (memerf-input)		: object name
 * param[1] (memerf-output)		: data read from the object
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define SECURE_STORAGE_CMD_READ				4


/* 
 * @brief : delete a persistent object
 *
 * param[0] (memerf-input)		: object name
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define SECURE_STORAGE_CMD_DELETE			5

#endif /* _SECURE_STORAGE_H */
