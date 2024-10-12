#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/secure_storage_01.h"

static TEE_Result create_persistent_object(uint32_t param_type, TEE_Param params[4])
{
    // 验证参数类型, 详情参考头文件中的宏定义
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("create_persistent_object failed: bad parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret;
    TEE_ObjectHandle obj_handle = TEE_HANDLE_NULL; // 持久化对象句柄
    size_t obj_size = params[1].value.a; // 持久化对象大小

    // GP规范中建议复制CA传入的缓冲区内容到TEE侧的内存中再进行处理,因为REE与TEE共享同一块内存,
    // REE侧随时可以修改缓冲区的内容，导致TEE侧的内存内容也随之改变，造成不可预知的后果.
    size_t obj_id_len = params[0].memref.size;
    char *obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO);
    if (obj_id == NULL) {
        EMSG("create_persistent_object failed: out of memory");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    // 创建持久化对象
    uint32_t obj_flags = TEE_DATA_FLAG_ACCESS_WRITE | /* 可写 */
                         TEE_DATA_FLAG_ACCESS_READ | /* 可读 */
                         TEE_DATA_FLAG_ACCESS_WRITE_META | /* 可删除, 可重命名 */
                         TEE_DATA_FLAG_OVERWRITE; /* 存在时覆盖 */

    ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_len, obj_flags,
                                     TEE_HANDLE_NULL, NULL, 0, &obj_handle); // 创建时不能传入大小

    if (ret != TEE_SUCCESS) {
        EMSG("create_persistent_object failed: TEE_CreatePersistentObject failed ret = 0x%x", ret);
        return ret;
    }

    IMSG("object %s create successful", obj_id);

    TEE_Free(obj_id); // 已经无效了, 释放内存

    // 调整持久化对象大小
    ret = TEE_TruncateObjectData(obj_handle, obj_size);
    if (ret != TEE_SUCCESS) {
        EMSG("create_persistent_object failed: TEE_TruncateObjectData failed ret = 0x%x", ret);
        TEE_CloseObject(obj_handle);
        return ret;
    }

    TEE_CloseObject(obj_handle);

    return TEE_SUCCESS;
}

static TEE_Result update_persistent_object(uint32_t param_type, TEE_Param params[4])
{
    // 验证参数类型, 详情参考头文件中的宏定义
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("update_persistent_object failed: bad parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = TEE_SUCCESS; // 返回值
    TEE_ObjectHandle obj_handle = TEE_HANDLE_NULL; // 持久化对象句柄
    char *obj_id = NULL; // 持久化对象ID
    size_t obj_id_len = params[0].memref.size; // 持久化对象ID长度
    char *data = NULL; // 待写入的数据
    size_t data_len = params[1].memref.size; // 待写入的数据长度

    // GP规范中建议复制CA传入的缓冲区内容到TEE侧的内存中再进行处理,因为REE与TEE共享同一块内存,
    // REE侧随时可以修改缓冲区的内容，导致TEE侧的内存内容也随之改变，造成不可预知的后果.
    obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO);
    if (obj_id == NULL) {
        EMSG("update_persistent_object failed: out of memory");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    data = TEE_Malloc(data_len, TEE_MALLOC_FILL_ZERO);
    if (data == NULL) {
        EMSG("update_persistent_object failed: out of memory");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto err_free_obj_id;
    }
    TEE_MemMove(data, params[1].memref.buffer, data_len);

    // 打开持久化对象
    uint32_t obj_flags = TEE_DATA_FLAG_ACCESS_WRITE; // 设置访问权限只写
    ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_len, obj_flags, &obj_handle);
    if (ret != TEE_SUCCESS) {
        EMSG("update_persistent_object failed: TEE_OpenPersistentObject failed ret = 0x%x", ret);
        goto err_free_data;
    }

    // 获取持久化对象信息
    TEE_ObjectInfo obj_info;
    ret = TEE_GetObjectInfo1(obj_handle, &obj_info);
    if (ret != TEE_SUCCESS) {
        EMSG("update_persistent_object failed: TEE_GetObjectInfo1 failed ret = 0x%x", ret);
        goto err_close_obj;
    }

    // 验证数据长度是否小于等于持久化对象大小
    if (obj_info.dataSize < data_len) {
        EMSG("update_persistent_object failed: dataSize < params[1].memref.size");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto err_close_obj;
    }

    // 写入数据
    ret = TEE_WriteObjectData(obj_handle, data, data_len);
    if (ret != TEE_SUCCESS) {
        EMSG("update_persistent_object failed: TEE_WriteObjectData failed ret = 0x%x", ret);
    }

    IMSG("object %s write successful", obj_id);

    TEE_CloseObject(obj_handle);

    return TEE_SUCCESS;

err_close_obj:
    TEE_CloseObject(obj_handle);
err_free_data:
    TEE_Free(data);
err_free_obj_id:
    TEE_Free(obj_id);

    return ret;
}

static TEE_Result read_persistent_object(uint32_t param_type, TEE_Param params[4])
{
    // 验证参数类型, 详情参考头文件中的宏定义
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("read_persistent_object failed: bad parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = TEE_SUCCESS; // 返回值
    TEE_ObjectHandle obj_handle = TEE_HANDLE_NULL; // 持久化对象句柄
    size_t obj_id_len = params[0].memref.size; // 持久化对象ID长度
    char *obj_id = NULL; // 持久化对象ID
    size_t data_len = params[1].memref.size; // 待读取的数据长度
    char *data = NULL; // 用于读取的数据缓冲区
    size_t read_bytes = 0; // 实际读取的字节数

    // GP规范中建议复制CA传入的缓冲区内容到TEE侧的内存中再进行处理, 因为REE与TEE共享同一块内存,
    // REE侧随时可以修改缓冲区的内容，导致TEE侧的内存内容也随之改变，造成不可预知的后果.
    obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO);
    if (obj_id == NULL) {
        EMSG("read_persistent_object failed: out of memory");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    data = TEE_Malloc(data_len, TEE_MALLOC_FILL_ZERO);
    if (data == NULL) {
        EMSG("read_persistent_object failed: out of memory");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto err_free_obj_id;
    }

    // 打开持久化对象
    uint32_t obj_flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ;
    ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_len, obj_flags, &obj_handle);
    if (ret != TEE_SUCCESS) {
        EMSG("read_persistent_object failed: TEE_OpenPersistentObject failed ret = 0x%x", ret);
        goto err_free_data;
    }

    // 获取持久化对象信息
    TEE_ObjectInfo obj_info;
    ret = TEE_GetObjectInfo1(obj_handle, &obj_info);
    if (ret != TEE_SUCCESS) {
        EMSG("read_persistent_object failed: TEE_GetObjectInfo1 failed ret = 0x%x", ret);
        goto err_close_obj;
    }

    // 验证接受数据缓冲是否足够大
    if (obj_info.dataSize > data_len) {
        EMSG("read_persistent_object failed: obj size is %u , recieve size is %u", obj_info.dataSize, data_len);
        ret = TEE_ERROR_SHORT_BUFFER;
        goto err_close_obj;
    }

    // 读取数据
    ret = TEE_ReadObjectData(obj_handle, data, data_len, &read_bytes);
    if (ret == TEE_SUCCESS && read_bytes == obj_info.dataSize) {
        // 读取成功且读取字节数等于持久化对象大小
        TEE_MemMove(params[1].memref.buffer, data, read_bytes);
    } else {
        EMSG("read_persistent_object failed: TEE_ReadObjectData failed ret = 0x%x", ret);
        goto err_close_obj;
    }

    IMSG("object %s read successful", obj_id);

    TEE_CloseObject(obj_handle);
    TEE_Free(obj_id);
    TEE_Free(data);

    return TEE_SUCCESS;

err_close_obj:
    TEE_CloseObject(obj_handle);
err_free_data:
    TEE_Free(data);
err_free_obj_id:
    TEE_Free(obj_id);

    return ret;
}

static TEE_Result delete_persistent_object(uint32_t param_type, TEE_Param params[4])
{
    // 验证参数类型, 详情参考头文件中的宏定义
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("delete_persistent_object failed: bad parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = TEE_SUCCESS; // 返回值
    TEE_ObjectHandle obj_handle = TEE_HANDLE_NULL; // 持久化对象句柄
    size_t obj_id_len = params[0].memref.size; // 持久化对象ID长度
    char *obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO); // 持久化对象ID

    // GP规范中建议复制CA传入的缓冲区内容到TEE侧的内存中再进行处理, 因为REE与TEE共享同一块内存,
    // REE侧随时可以修改缓冲区的内容，导致TEE侧的内存内容也随之改变，造成不可预知的后果.
    if (obj_id == NULL) {
        EMSG("delete_persistent_object failed: out of memory");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    // 打开持久化对象
    uint32_t obj_flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META; // 设置访问权限只写元数据
    ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_len, obj_flags, &obj_handle);
    if (ret != TEE_SUCCESS) {
        EMSG("delete_persistent_object failed: TEE_OpenPersistentObject failed ret = 0x%x", ret);
        goto err_free_obj_id;
    }

    // 删除持久化对象
    ret = TEE_CloseAndDeletePersistentObject1(obj_handle);
    if (ret != TEE_SUCCESS) {
        EMSG("delete_persistent_object failed: TEE_CloseAndDeletePersistentObject1 failed ret = 0x%x", ret);
    }

    IMSG("object %s delete successful", obj_id);

    TEE_Free(obj_id);
    return ret;

err_free_obj_id:
    TEE_Free(obj_id);
    return ret;
}

/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_type, TEE_Param params[4], void **sess_ctx)
{
    (void)param_type;
    (void)params;
    (void)sess_ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    (void)sess_ctx;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    (void)sess_ctx;

    switch (cmd) {
    case TA_SECURE_STORAGE_01_CMD_CREATE_OBJECT:
        return create_persistent_object(param_type, params);

    case TA_SECURE_STORAGE_01_CMD_UPDATE_OBJECT:
        return update_persistent_object(param_type, params);

    case TA_SECURE_STORAGE_01_CMD_READ_OBJECT:
        return read_persistent_object(param_type, params);

    case TA_SECURE_STORAGE_01_CMD_DELETE_OBJECT:
        return delete_persistent_object(param_type, params);

    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
