#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/secure_storage.h"

struct secure_storage_ctx {
    TEE_ObjectHandle persistant_object;
    TEE_ObjectEnumHandle enum_handle;
    uint8_t *obj_id;
    uint32_t obj_len;
};

static void free_enum_handle(struct secure_storage_ctx *ctx)
{
    if(ctx->enum_handle != TEE_HANDLE_NULL) {
        TEE_FreePersistentObjectEnumerator(ctx->enum_handle);
        ctx->enum_handle = TEE_HANDLE_NULL;
    }
}

static void close_persistent_object(struct secure_storage_ctx *ctx)
{
    if(ctx->persistant_object != TEE_HANDLE_NULL) {
        TEE_CloseObject(ctx->persistant_object);
        ctx->persistant_object = TEE_HANDLE_NULL;
    }
}

static void free_ctx_obj(struct secure_storage_ctx *ctx)
{
    if(ctx->obj_id) {
        TEE_Free(ctx->obj_id);
        ctx->obj_id = NULL;
    }
    ctx->obj_len = 0;
}

static bool check_obj_correct(struct secure_storage_ctx *ctx, uint8_t *obj_id, uint32_t obj_id_len)
{
    if(!obj_id || !ctx->obj_id || !ctx->obj_len)
        return false;

    return (ctx->obj_len == obj_id_len) && (TEE_MemCompare(ctx->obj_id, obj_id, ctx->obj_len) == 0);
}

static TEE_Result check_object_exists(struct secure_storage_ctx *ctx, uint8_t *obj_id, uint32_t obj_id_len)
{
    TEE_Result res;

    res = TEE_StartPersistentObjectEnumerator(ctx->enum_handle, TEE_STORAGE_PRIVATE);
    if (res == TEE_ERROR_ITEM_NOT_FOUND) {
        return res;
    } else if((res == TEE_ERROR_CORRUPT_OBJECT) || (res == TEE_ERROR_CORRUPT_OBJECT_2)) {
        EMSG("the storage is corrupt, res is 0x%x\n\n", res);
        return res;
    } else if (res == TEE_ERROR_STORAGE_NOT_AVAILABLE) {
        EMSG("the object is not avaliable\n\n");
        return res;
    }

    TEE_ObjectInfo tmp_info;
    uint8_t tmp_obj_id[256];
    uint32_t tmp_obj_id_len;

    while (true) {
        tmp_obj_id_len = sizeof(tmp_obj_id);

        res = TEE_GetNextPersistentObject(ctx->enum_handle, &tmp_info, tmp_obj_id, &tmp_obj_id_len);

        if (res == TEE_SUCCESS) {
            if (obj_id_len == tmp_obj_id_len && TEE_MemCompare(tmp_obj_id, obj_id, obj_id_len) == 0) {
                IMSG("object is already existed\n\n");
                return res;
            }
        } else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
            return res;
        } else if (res == TEE_ERROR_CORRUPT_OBJECT || res == TEE_ERROR_CORRUPT_OBJECT_2) {
            EMSG("there is a corrupt object\n\n");
            continue;;
        } else if (res == TEE_ERROR_STORAGE_NOT_AVAILABLE) {
            EMSG("the object is not avaliable\n\n");
            continue;
        }
    }
}

static TEE_Result open_persistent_object(struct secure_storage_ctx *ctx, uint8_t *obj_id, uint32_t obj_id_len)
{
    TEE_Result res;

    if (ctx->persistant_object != TEE_HANDLE_NULL) {
        if (check_obj_correct(ctx, obj_id, obj_id_len)) 
            return TEE_SUCCESS;
        else 
            close_persistent_object(ctx);
    }

    uint32_t access_flag = TEE_DATA_FLAG_ACCESS_READ|
                            TEE_DATA_FLAG_ACCESS_WRITE|
                            TEE_DATA_FLAG_ACCESS_WRITE_META;
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_len, access_flag, &ctx->persistant_object);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to obj_open object, res is 0x%x\n\n", res);
        return res;
    }

    if (ctx->obj_len < obj_id_len) {
        uint8_t *new_obj_id = TEE_Realloc(ctx->obj_id, obj_id_len);
        if (!new_obj_id) {
            EMSG("Out of memory\n\n");
            close_persistent_object(ctx);
            return TEE_ERROR_OUT_OF_MEMORY;
        }
        ctx->obj_id = new_obj_id;
    }

    TEE_MemMove(ctx->obj_id, obj_id, obj_id_len);
    ctx->obj_len = obj_id_len;

    return TEE_SUCCESS;
}

/**********************************File Operation**********************************/
static TEE_Result obj_exists(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;
    TEE_Result res;
    
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, 
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error for obj_exists\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t obj_id_len = params[0].memref.size;
    uint8_t *obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO);
    if (!obj_id) {
        EMSG("out of memory in obj_exists\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    res = TEE_AllocatePersistentObjectEnumerator(&ctx->enum_handle);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate enumerator in obj_exists, res: 0x%x\n", res);
        TEE_Free(obj_id);
        return res;
    }

    res = check_object_exists(ctx, obj_id, obj_id_len);
    TEE_Free(obj_id);
    free_enum_handle(ctx);

    if (res == TEE_SUCCESS) 
        return TEE_SUCCESS;
    else if (res == TEE_ERROR_ITEM_NOT_FOUND) 
        return TEE_ERROR_ITEM_NOT_FOUND;
    else {
        EMSG("Error checking object existence, res: 0x%x\n", res);
        return res;
    }
}

static TEE_Result obj_create(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t obj_id_len = params[0].memref.size;
    uint8_t *obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO);
    if(!obj_id) {
        EMSG("out of memory\n\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    uint32_t obj_size = params[1].value.a;

    free_enum_handle(ctx);
    res = TEE_AllocatePersistentObjectEnumerator(&ctx->enum_handle);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate enumerator, res is 0x%x\n\n", res);
        goto err_free_obj_id;
    }

    res = check_object_exists(ctx, obj_id, obj_id_len);
    if (res != TEE_ERROR_ITEM_NOT_FOUND && res != TEE_ERROR_CORRUPT_OBJECT) {
        goto err_free_enum_handle;
    }

    uint32_t access_flag = TEE_DATA_FLAG_ACCESS_READ |
                          TEE_DATA_FLAG_ACCESS_WRITE |
                          TEE_DATA_FLAG_ACCESS_WRITE_META;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                    obj_id, obj_id_len,
                                    access_flag,
                                    TEE_HANDLE_NULL,
                                    NULL, 0,
                                    &ctx->persistant_object);
    if(res != TEE_SUCCESS) {
        EMSG("Failed to obj_create object, res is 0x%x\n\n", res);
        goto err_free_enum_handle;
    }

    IMSG("Object created success\n\n");

    res = TEE_TruncateObjectData(ctx->persistant_object, obj_size);
    if(res != TEE_SUCCESS) {
        EMSG("Failed to truncate object, res is 0x%x\n\n", res);
        goto err_close;
    }

    IMSG("set object size success\n\n");

    free_enum_handle(ctx);
    TEE_Free(obj_id);
    
    return TEE_SUCCESS;

err_close:
   close_persistent_object(ctx);

err_free_enum_handle:
    free_enum_handle(ctx);

err_free_obj_id:
    TEE_Free(obj_id);

    return res;
}

static TEE_Result obj_open(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t obj_id_len = params[0].memref.size;
    uint8_t *obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO);
    if(!obj_id) {
        EMSG("out of memory\n\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    res = open_persistent_object(ctx, obj_id, obj_id_len);
    if(res != TEE_SUCCESS) {
        goto err_free_obj_id;
    }

    TEE_Free(obj_id);
    return TEE_SUCCESS;

err_free_obj_id:
    TEE_Free(obj_id);

    return res;
}

static TEE_Result obj_rename(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    uint32_t old_obj_id_len = params[0].memref.size;
    uint8_t *old_obj_id = TEE_Malloc(old_obj_id_len, TEE_MALLOC_FILL_ZERO);
    if(!old_obj_id) {
        EMSG("out of memory\n\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(old_obj_id, params[0].memref.buffer, old_obj_id_len);

    uint32_t new_obj_id_len = params[1].memref.size;
    uint8_t *new_obj_id = TEE_Malloc(new_obj_id_len, TEE_MALLOC_FILL_ZERO);
    if(!new_obj_id) {
        EMSG("out of memory\n\n");
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto err_free_old_obj_id;
    }
    TEE_MemMove(new_obj_id, params[1].memref.buffer, new_obj_id_len);

    res = open_persistent_object(ctx, old_obj_id, old_obj_id_len);
    if(res != TEE_SUCCESS) {
        goto err_free_new_obj_id;
    }

    res = TEE_RenamePersistentObject(ctx->persistant_object, new_obj_id, new_obj_id_len);
    if(res == TEE_ERROR_ACCESS_CONFLICT) {
        goto err_close;
    }else if(res != TEE_SUCCESS) {
        EMSG("Failed to obj_rename object, res is 0x%x\n\n", res);
        goto err_close;
    }

    TEE_Free(new_obj_id);
    TEE_Free(old_obj_id);
    return TEE_SUCCESS;

err_close:
   close_persistent_object(ctx);

err_free_new_obj_id:
    TEE_Free(new_obj_id);

err_free_old_obj_id:
    TEE_Free(old_obj_id);

    return res;
}

static TEE_Result obj_seek(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t offset = params[1].value.a;
    TEE_Whence whence = (TEE_Whence)params[1].value.b;
    if(whence != TEE_DATA_SEEK_SET && whence != TEE_DATA_SEEK_CUR && whence != TEE_DATA_SEEK_END) {
        EMSG("whence error\n\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_SeekObjectData(ctx->persistant_object, offset, whence);
    if(res != TEE_SUCCESS) {
        EMSG("Failed to obj_seek object, res is 0x%x\n\n", res);
        return res;
    }
    
    return TEE_SUCCESS;
}

static TEE_Result obj_write(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t data_len = params[1].memref.size;
    uint8_t *data = TEE_Malloc(data_len, TEE_MALLOC_FILL_ZERO);
    if(!data) {
        EMSG("Out of memory\n\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(data, params[1].memref.buffer, data_len);

    res = TEE_WriteObjectData(ctx->persistant_object, data, data_len);
    if(res != TEE_SUCCESS) {
        EMSG("Failed to obj_write object, res is 0x%x\n\n", res);
        goto err_free_data;
    }

    TEE_Free(data);
    return TEE_SUCCESS;

err_free_data:
    TEE_Free(data);

    return res;
}

static TEE_Result obj_read(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t data_len = params[1].memref.size;
    uint8_t *data = TEE_Malloc(data_len, TEE_MALLOC_FILL_ZERO);
    if(!data) {
        EMSG("Out of memory\n\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    uint32_t read_count;
    res = TEE_ReadObjectData(ctx->persistant_object, data, data_len, &read_count);
    if(res != TEE_SUCCESS) {
        EMSG("Failed to obj_read object, res is 0x%x\n\n", res);
        goto err_free_data;
    }

    TEE_MemMove(params[1].memref.buffer, data, read_count);
    params[1].memref.size = read_count;

    TEE_Free(data);
    return TEE_SUCCESS;

err_free_data:
    TEE_Free(data);

    return res;
}

static TEE_Result obj_get_all(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;
    TEE_Result res;

    uint32_t exp_param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_type != exp_param_type) {
        EMSG("Parameter type error: obj_get_all\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t obj_id_len = params[0].memref.size;
    uint8_t *obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO);
    if (!obj_id) {
        EMSG("Memory allocation failed: obj_get_all\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);
    res = open_persistent_object(ctx, obj_id, obj_id_len);
    TEE_Free(obj_id);

    if (res != TEE_SUCCESS) {
        EMSG("Failed to open object: obj_get_all, res: 0x%x\n", res);
        return res;
    }

    TEE_ObjectInfo obj_info;
    res = TEE_GetObjectInfo1(ctx->persistant_object, &obj_info);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to get object info: obj_get_all, res: 0x%x\n", res);
        close_persistent_object(ctx);
        return res;
    }

    uint32_t data_size = obj_info.dataSize;
    uint8_t *data_buffer = TEE_Malloc(data_size, TEE_MALLOC_FILL_ZERO);
    if (!data_buffer) {
        EMSG("Memory allocation failed for data_buffer: obj_get_all\n");
        close_persistent_object(ctx);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    uint32_t read_bytes = 0;
    res = TEE_ReadObjectData(ctx->persistant_object, data_buffer, data_size, &read_bytes);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to read object data: obj_get_all, res: 0x%x\n", res);
        TEE_Free(data_buffer);
        close_persistent_object(ctx);
        return res;
    }

    if (read_bytes != data_size) {
        EMSG("Mismatch in read bytes: obj_get_all, expected: %u, read: %u\n", data_size, read_bytes);
        TEE_Free(data_buffer);
        close_persistent_object(ctx);
        return TEE_ERROR_GENERIC;
    }

    if (params[1].memref.size < data_size) {
        EMSG("Output buffer too small: obj_get_all, expected: %u, provided: %u\n", data_size, params[1].memref.size);
        TEE_Free(data_buffer);
        close_persistent_object(ctx);
        return TEE_ERROR_SHORT_BUFFER;
    }

    TEE_MemMove(params[1].memref.buffer, data_buffer, data_size);
    params[1].memref.size = read_bytes;

    TEE_Free(data_buffer);
    close_persistent_object(ctx);

    return TEE_SUCCESS;
}


static TEE_Result obj_close(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    (void)params;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    TEE_CloseObject(ctx->persistant_object);
    ctx->persistant_object = TEE_HANDLE_NULL;
    free_ctx_obj(ctx);

    return TEE_SUCCESS;
}

static TEE_Result obj_delete(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    uint32_t obj_id_len = params[0].memref.size;
    uint8_t *obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO);
    if(!obj_id) {
        EMSG("out of memory\n\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    res = open_persistent_object(ctx, obj_id, obj_id_len);
    if(res != TEE_SUCCESS) {
        goto err_free_obj_id;
    }

    res = TEE_CloseAndDeletePersistentObject1(ctx->persistant_object);
    if(res != TEE_SUCCESS) {
        EMSG("Failed to obj_delete object, res is 0x%x\n\n", res);
        goto err_free_obj_id;
    }
    ctx->persistant_object = TEE_HANDLE_NULL;

    free_ctx_obj(ctx);
    return TEE_SUCCESS;

err_free_obj_id:
    TEE_Free(obj_id);

    return res;
}
/**********************************File Operation**********************************/

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

    struct secure_storage_ctx *ctx = TEE_Malloc(sizeof(struct secure_storage_ctx), TEE_MALLOC_FILL_ZERO);
    if(!ctx) {
        EMSG("Out of memory\n\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct secure_storage_ctx *ctx = sess_ctx;

    close_persistent_object(ctx);
    free_enum_handle(ctx);
    free_ctx_obj(ctx);

    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        case SECURE_STORAGE_CMD_CREATE:
            return obj_create(sess_ctx, param_type, params);

        case SECURE_STORAGE_CMD_OPEN:
            return obj_open(sess_ctx, param_type, params);

        case SECURE_STORAGE_CMD_RENAME:
            return obj_rename(sess_ctx, param_type, params);

        case SECURE_STORAGE_CMD_SEEK:
            return obj_seek(sess_ctx, param_type, params);

        case SECURE_STORAGE_CMD_WRITE:
            return obj_write(sess_ctx, param_type, params);

        case SECURE_STORAGE_CMD_READ:
            return obj_read(sess_ctx, param_type, params);

        case SECURE_STORAGE_CMD_CLOSE:
            return obj_close(sess_ctx, param_type, params);

        case SECURE_STORAGE_CMD_DELETE:
            return obj_delete(sess_ctx, param_type, params);

        case SECURE_STORAGE_CMD_EXISTS:
            return obj_exists(sess_ctx, param_type, params);
        
        case SECURE_STORAGE_CMD_GET_ALL:
            return obj_get_all(sess_ctx, param_type, params);

        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
}

/**
 * @brief 配置到开发板指令

 * 注意: 开发本需提前配置好SSH环境, 
 * 根文件系统也需要支持OPTEE, buildroot自行配置

 * /lib/optee_armtz 是OPTEE寻找TA的默认地址
 * /usr/bin 让CA目标文件可以直接当作命令运行
 
 * scp secure_storage/ta/ef83682b-8a80-45e0-9993-ae583a386628.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp secure_storage/host/secure_storage wenshuyu@192.168.1.6:/usr/bin
 */

