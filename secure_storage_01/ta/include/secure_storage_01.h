#ifndef _SECURE_STORAGE_01_H
#define _SECURE_STORAGE_01_H

#define TA_SECURE_STORAGE_01_UUID \
	{ 0x7d5ff833, 0x23db, 0x4a52, \
		{ 0x9d, 0xc3, 0x8a, 0x04, 0x16, 0x00, 0x2a, 0xef} }

/*
 * TA_SECURE_STORAGE_01_CMD_CREATE_OBJECT - 创建一个空的持久化对象
 * param[0] (memref) object_id - 要创建的持久化对象ID 字符串形式
 * param[1] value object_size - 要创建的持久化对象大小
 * param[2] unused
 * param[3] unused
 */
#define TA_SECURE_STORAGE_01_CMD_CREATE_OBJECT (0)

/*
 * TA_SECURE_STORAGE_01_CMD_UPDATE_OBJECT - 更新持久化对象中的数据
 * param[0] (memref) object_id - 持久化对象ID 字符串形式
 * param[1] (memref) write_buffer - 要写入的数据
 * param[2] unused
 * param[3] unused
 */
#define TA_SECURE_STORAGE_01_CMD_UPDATE_OBJECT (1)

/*
 * TA_SECURE_STORAGE_01_CMD_READ_OBJECT - 读取持久化对象中的数据
 * param[0] (memref) object_id - 持久化对象ID 字符串形式
 * param[1] (memref) read_buffer - 存储读取到的数据
 * param[2] unused
 * param[3] unused
 */
#define TA_SECURE_STORAGE_01_CMD_READ_OBJECT (2)

/*
 * TA_SECURE_STORAGE_01_CMD_DELETE_OBJECT - 删除持久化对象
 * param[0] (memref) object_id - 持久化对象ID 字符串形式
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_SECURE_STORAGE_01_CMD_DELETE_OBJECT (3)

#endif /* _SECURE_STORAGE_01_H */
