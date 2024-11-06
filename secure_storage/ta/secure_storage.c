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

static TEE_Result open_persistent_object(struct secure_storage_ctx *ctx, uint8_t *obj_id, uint32_t obj_id_len)
{
    TEE_Result res;

    if (ctx->persistant_object != TEE_HANDLE_NULL) {
        if (ctx->obj_len == obj_id_len && TEE_MemCompare(ctx->obj_id, obj_id, ctx->obj_len) == 0) {
            return TEE_SUCCESS;
        } else {
            close_persistent_object(ctx);
        }
    }

    uint32_t access_flag = TEE_DATA_FLAG_ACCESS_READ|
                            TEE_DATA_FLAG_ACCESS_WRITE|
                            TEE_DATA_FLAG_ACCESS_WRITE_META;
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_len, access_flag, &ctx->persistant_object);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to open object, res is 0x%x\n", res);
        return res;
    }

    if (ctx->obj_len < obj_id_len) {
        uint8_t *new_obj_id = TEE_Realloc(ctx->obj_id, obj_id_len);
        if (!new_obj_id) {
            EMSG("Out of memory\n");
            close_persistent_object(ctx);
            return TEE_ERROR_OUT_OF_MEMORY;
        }
        ctx->obj_id = new_obj_id;
    }

    TEE_MemMove(ctx->obj_id, obj_id, obj_id_len);
    ctx->obj_len = obj_id_len;

    return TEE_SUCCESS;
}

static TEE_Result check_object_exists(struct secure_storage_ctx *ctx, uint8_t *obj_id, uint32_t obj_id_len)
{
    TEE_Result res;

    res = TEE_StartPersistentObjectEnumerator(ctx->enum_handle, TEE_STORAGE_PRIVATE);
    if (res == TEE_ERROR_ITEM_NOT_FOUND) {
        return res;
    } else if((res == TEE_ERROR_CORRUPT_OBJECT) || (res == TEE_ERROR_CORRUPT_OBJECT_2)) {
        EMSG("the storage is corrupt, res is 0x%x\n", res);
        return res;
    } else if (res == TEE_ERROR_STORAGE_NOT_AVAILABLE) {
        EMSG("the object is not avaliable\n");
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
                IMSG("object is already existed\n");
                return res;
            }
        } else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
            return res;
        } else if (res == TEE_ERROR_CORRUPT_OBJECT || res == TEE_ERROR_CORRUPT_OBJECT_2) {
            EMSG("there is a corrupt object\n");
            continue;;
        } else if (res == TEE_ERROR_STORAGE_NOT_AVAILABLE) {
            EMSG("the object is not avaliable\n");
            continue;
        }
    }
}

static TEE_Result create_persistent_object(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t obj_id_len = params[0].memref.size;
    uint8_t *obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO);
    if(!obj_id) {
        EMSG("out of memory\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    uint32_t obj_size = params[1].value.a;

    free_enum_handle(ctx);
    res = TEE_AllocatePersistentObjectEnumerator(&ctx->enum_handle);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate enumerator, res is 0x%x\n", res);
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
        EMSG("Failed to create object, res is 0x%x\n", res);
        goto err_free_enum_handle;
    }

    IMSG("Object created success\n");

    res = TEE_TruncateObjectData(ctx->persistant_object, obj_size);
    if(res != TEE_SUCCESS) {
        EMSG("Failed to truncate object, res is 0x%x\n", res);
        goto err_close;
    }

    IMSG("set object size success\n");

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

static TEE_Result rename_persistent_object(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    uint32_t old_obj_id_len = params[0].memref.size;
    uint8_t *old_obj_id = TEE_Malloc(old_obj_id_len, TEE_MALLOC_FILL_ZERO);
    if(!old_obj_id) {
        EMSG("out of memory\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(old_obj_id, params[0].memref.buffer, old_obj_id_len);

    uint32_t new_obj_id_len = params[1].memref.size;
    uint8_t *new_obj_id = TEE_Malloc(new_obj_id_len, TEE_MALLOC_FILL_ZERO);
    if(!new_obj_id) {
        EMSG("out of memory\n");
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
        EMSG("the destinated object name is already existed\n");
        goto err_close;
    }else if(res != TEE_SUCCESS) {
        EMSG("Failed to rename object, res is 0x%x\n", res);
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

static TEE_Result seek(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t offset = params[1].value.a;
    TEE_Whence whence = (TEE_Whence)params[1].value.b;
    if(whence != TEE_DATA_SEEK_SET && whence != TEE_DATA_SEEK_CUR && whence != TEE_DATA_SEEK_END) {
        EMSG("whence error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    uint32_t obj_id_len = params[0].memref.size;
    uint8_t *obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO);
    if(!obj_id) {
        EMSG("out of memory\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    res = open_persistent_object(ctx, obj_id, obj_id_len);
    if(res != TEE_SUCCESS) {
        goto err_free_obj_id;
    }

    res = TEE_SeekObjectData(ctx->persistant_object, offset, whence);
    if(res != TEE_SUCCESS) {
        EMSG("Failed to seek object, res is 0x%x\n", res);
        goto err_close;
    }

    TEE_Free(obj_id);
    return TEE_SUCCESS;

err_close:
   close_persistent_object(ctx); 

err_free_obj_id:
    TEE_Free(obj_id);

    return res;
}

static TEE_Result write(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    uint32_t obj_id_len = params[0].memref.size;
    uint8_t *obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO);
    if(!obj_id) {
        EMSG("out of memory\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    uint32_t data_len = params[1].memref.size;
    uint8_t *data = TEE_Malloc(data_len, TEE_MALLOC_FILL_ZERO);
    if(!data) {
        EMSG("Out of memory\n");
        goto err_free_obj_id;
    }
    TEE_MemMove(data, params[1].memref.buffer, data_len);

    res = open_persistent_object(ctx, obj_id, obj_id_len);
    if(res != TEE_SUCCESS) {
        goto err_free_data;
    }

    res = TEE_WriteObjectData(ctx->persistant_object, data, data_len);
    if(res != TEE_SUCCESS) {
        EMSG("Failed to write object, res is 0x%x\n", res);
        goto err_close;
    }

    TEE_Free(data);
    TEE_Free(obj_id);
    return TEE_SUCCESS;

err_close:
   close_persistent_object(ctx);

err_free_data:
    TEE_Free(data);

err_free_obj_id:
    TEE_Free(obj_id);

    return res;
}

static TEE_Result read(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    uint32_t obj_id_len = params[0].memref.size;
    uint8_t *obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO);
    if(!obj_id) {
        EMSG("out of memory\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    uint32_t data_len = params[1].memref.size;
    uint8_t *data = TEE_Malloc(data_len, TEE_MALLOC_FILL_ZERO);
    if(!data) {
        EMSG("Out of memory\n");
        goto err_free_obj_id;
    }

    res = open_persistent_object(ctx, obj_id, obj_id_len);
    if(res != TEE_SUCCESS) {
        goto err_free_data;
    }

    uint32_t read_count;
    res = TEE_ReadObjectData(ctx->persistant_object, data, data_len, &read_count);
    if(res != TEE_SUCCESS) {
        EMSG("Failed to read object, res is 0x%x\n", res);
        goto err_close;
    }

    TEE_MemMove(params[1].memref.buffer, data, read_count);
    params[1].memref.size = read_count;

    TEE_Free(data);
    TEE_Free(obj_id);
    return TEE_SUCCESS;

err_close:
   close_persistent_object(ctx);

err_free_data:
    TEE_Free(data);

err_free_obj_id:
    TEE_Free(obj_id);

    return res;
}

static TEE_Result delete(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct secure_storage_ctx *ctx = (struct secure_storage_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    uint32_t obj_id_len = params[0].memref.size;
    uint8_t *obj_id = TEE_Malloc(obj_id_len, TEE_MALLOC_FILL_ZERO);
    if(!obj_id) {
        EMSG("out of memory\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    res = open_persistent_object(ctx, obj_id, obj_id_len);
    if(res != TEE_SUCCESS) {
        goto err_free_obj_id;
    }

    res = TEE_CloseAndDeletePersistentObject1(ctx->persistant_object);
    if(res != TEE_SUCCESS) {
        EMSG("Failed to delete object, res is 0x%x\n", res);
        goto err_free_obj_id;
    }
    ctx->persistant_object = TEE_HANDLE_NULL;


    return TEE_SUCCESS;

err_free_obj_id:
    TEE_Free(obj_id);

    return res;
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

    struct secure_storage_ctx *ctx = TEE_Malloc(sizeof(struct secure_storage_ctx), TEE_MALLOC_FILL_ZERO);
    if(!ctx) {
        EMSG("Out of memory\n");
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
    if(ctx->obj_id) {
        TEE_Free(ctx->obj_id);
    }

    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        case SECURE_STORAGE_CMD_CREATE:
            return create_persistent_object(sess_ctx, param_type, params);

        case SECURE_STORAGE_CMD_RENAME:
            return rename_persistent_object(sess_ctx, param_type, params);

        case SECURE_STORAGE_CMD_SEEK:
            return seek(sess_ctx, param_type, params);

        case SECURE_STORAGE_CMD_WRITE:
            return write(sess_ctx, param_type, params);

        case SECURE_STORAGE_CMD_READ:
            return read(sess_ctx, param_type, params);

        case SECURE_STORAGE_CMD_DELETE:
            return delete(sess_ctx, param_type, params);

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

