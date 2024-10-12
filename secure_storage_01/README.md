# 安全存储API使用示例1

## 1. 创建持久化存储对象
 - `TEE_CreatePersistentObject` : 创建持久化存储对象
 - `TEE_TruncateObjectData` : 设置久化存储对象大小

## 2. 写入数据到持久化存储对象
 - `TEE_OpenPersistentObject` : 打开持久化存储对象
 - `TEE_GetObjectInfo1` : 获取持久化存储对象信息，用于判断缓冲区大小是否足够
 - `TEE_WriteObjectData` : 写入数据到持久化存储对象
 - `TEE_CloseObject` : 关闭持久化存储对象

## 3. 从持久化存储对象读取数据
 - `TEE_OpenPersistentObject` : 打开持久化存储对象
 - `TEE_GetObjectInfo1` : 获取持久化存储对象信息，用于判断缓冲区大小是否足够
 - `TEE_ReadObjectData` : 从持久化存储对象中读取数据
 - `TEE_CloseObject` : 关闭持久化存储对象

## 4. 删除持久化存储对象
 - `TEE_OpenPersistentObject` : 打开持久化存储对象
 - `TEE_CloseAndDeletePersistentObject1` : 关闭并删除持久化存储对象