#ifndef _AES_CBC_MAC_NOPAD_H
#define _AES_CBC_MAC_NOPAD_H

#define TA_AES_CBC_MAC_NOPAD_UUID \
	{ 0x035ee898, 0xc6cb, 0x412a, \
		{ 0x95, 0x65, 0x32, 0x01, 0x74, 0xfe, 0x4b, 0xde} }

/* 
 * @brief : generate key by AES-CBC-NOPAD algorithm to do mac
 *
 * param[0] (memref-output) : 	the mac key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define AES_CBC_MAC_NOPAD_GEN_KEY			0

/* 
 * @brief : do mac
 *
 * param[0] (memref-input) 	: the message
 * param[1] (memref-output) : the MAC
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define AES_CBC_MAC_NOPAD_GEN_MAC			1

/* 
 * @brief : verify the mac
 *
 * param[0] (memref-input) 	: the message
 * param[1] (memref-input) 	: the MAC
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define AES_CBC_MAC_NOPAD_VERIFY			2

#endif /* _AES_CBC_MAC_NOPAD_H */
