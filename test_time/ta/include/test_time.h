#ifndef _TEST_TIME_H
#define _TEST_TIME_H

#define TA_TEST_TIME_UUID \
	{ 0x13010e37, 0x4220, 0x4a0f, \
		{ 0xbb, 0x68, 0x88, 0x2f, 0x91, 0xd9, 0x34, 0x9b} }

#define WAIT_COUNTS (3)
#define TEST_TIMESTAMP (1730822400 + 3600 * 8) // 2024:11:06:00:00:00

/* 
 * @brief : get system time
 *
 * param[0] (value-output) : a : second(timestamp), b : millis
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TIME_CMD_GET_SYSTIME			0

/* 
 * @brief : wait time
 *
 * param[0] (value-input) : a : second count to wait
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TIME_CMD_TIME_WAIT				1

/* 
 * @brief : set persistant time
 *
 * param[0] (value-input) : a : second(timestamp), b : millis
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TIME_CMD_SET_PERSISTANT_TIME	2

/* 
 * @brief : get persistant time
 *
 * param[0] (value-output) : a : second(timestamp), b : millis
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TIME_CMD_GET_PERSISTANT_TIME	3

/* 
 * @brief : get REE time
 *
 * param[0] (unsued)
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TIME_CMD_GET_REE_TIME			4

#endif /* _TEST_TIME_H */
