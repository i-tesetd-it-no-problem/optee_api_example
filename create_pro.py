import os
import sys
import uuid

##################################################用户配置区域##################################################
DEFAULT_HOST_NAME = "wenshuyu"  # 开发板主机名
DEFAULT_IP = "192.168.1.6"      # 开发板IP地址
##############################################################################################################

CA_DIR_NAME = "host"
TA_DIR_NAME = "ta"

def generate_uuid_define(define_name):
    u = uuid.uuid4()
    uuid_str = str(u)

    node_hex = f"{u.node:012x}"
    node_bytes = [node_hex[i:i + 2] for i in range(0, 12, 2)]
    n = [', 0x'] * 11
    n[::2] = node_bytes

    define_str = (
        f"#define {define_name} \\\n\t{{ "
        f"0x{u.time_low:08x}, "
        f"0x{u.time_mid:04x}, "
        f"0x{u.time_hi_version:04x}, \\\n\t\t{{ "
        f"0x{u.clock_seq_hi_variant:02x}, "
        f"0x{u.clock_seq_low:02x}, "
        f"0x{''.join(n)}"
        f"}} }}"
    )

    return uuid_str, define_str


def create_dir(parent_dir, dir_name):
    target_dir = os.path.join(parent_dir, dir_name)

    if os.path.exists(target_dir):
        print(f"{target_dir} already exists")
        return False

    try:
        os.makedirs(target_dir)
        return True
    except Exception as e:
        print(f"Failed to create directory '{dir_name}': {e}")
        return False


def write_file(file_path, content):
    try:
        with open(file_path, 'w') as fd:
            fd.write(content)
        return True
    except Exception as e:
        print(f"Failed to write to file '{file_path}': {e}")
        return False


def create_root_makefile(dir_path):
    makefile_content = """export V?=0

# If _HOST or _TA specific compilers are not specified, then use CROSS_COMPILE
HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)
TA_CROSS_COMPILE ?= $(CROSS_COMPILE)

.PHONY: all
all:
\t$(MAKE) -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables
\t$(MAKE) -C ta CROSS_COMPILE="$(TA_CROSS_COMPILE)" LDFLAGS=""

.PHONY: clean
clean:
\t$(MAKE) -C host clean
\t$(MAKE) -C ta clean
"""

    makefile_path = os.path.join(dir_path, "Makefile")
    return write_file(makefile_path, makefile_content)


def create_host(parent_dir, pro_name, define_name, uuid):
    if not create_dir(parent_dir, CA_DIR_NAME):
        return False

    ca_path = os.path.join(parent_dir, CA_DIR_NAME)

    # Create main.c
    main_content = f"""#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/{pro_name}.h"

struct {pro_name}_ctx {{
	TEEC_Context ctx;
	TEEC_Session sess;
}};

static void prepare_tee_session(struct {pro_name}_ctx *ctx)
{{
	TEEC_UUID uuid = {define_name};
	uint32_t origin;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS) {{
	    printf("TEEC_InitializeContext failed with code 0x%x", res);
	    exit(0);
	}}

	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS) {{
	    printf("TEEC_Opensession failed with code 0x%x origin 0x%x", res, origin);
	    exit(0);
	}}
}}

static void terminate_tee_session(struct {pro_name}_ctx *ctx)
{{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}}

int main()
{{
    struct {pro_name}_ctx ctx;

    prepare_tee_session(&ctx);

    /* TODO TEEC_InvokeCommand */

    terminate_tee_session(&ctx);

    return 0;
}}

/**
 * @brief 配置到开发板指令

 * 注意: 开发本需提前配置好SSH环境, 
 * 根文件系统也需要支持OPTEE, buildroot自行配置

 * /lib/optee_armtz 是OPTEE寻找TA的默认地址
 * /usr/bin 让CA目标文件可以直接当作命令运行

 * scp {pro_name}/ta/{uuid}.ta {DEFAULT_HOST_NAME}@{DEFAULT_IP}:/lib/optee_armtz
 * scp {pro_name}/host/{pro_name} {DEFAULT_HOST_NAME}@{DEFAULT_IP}:/usr/bin
 */

"""

    main_file = os.path.join(ca_path, "main.c")
    if not write_file(main_file, main_content):
        return False

    # Create Makefile
    makefile_content = f"""CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

OBJS = main.o

CFLAGS += -Wall -I../ta/include -I$(TEEC_EXPORT)/include -I./include
# Add/link other required libraries here
LDADD += -lteec -L$(TEEC_EXPORT)/lib

BINARY = {pro_name}

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
\t$(CC) $(LDFLAGS) -o $@ $< $(LDADD)

.PHONY: clean
clean:
\trm -f $(OBJS) $(BINARY)

%.o: %.c
\t$(CC) $(CFLAGS) -c $< -o $@
"""

    make_file = os.path.join(ca_path, "Makefile")
    return write_file(make_file, makefile_content)


def create_ta(parent_dir, pro_name, define_name, define_str, uuid_str):
    if not create_dir(parent_dir, TA_DIR_NAME):
        return False

    ta_path = os.path.join(parent_dir, TA_DIR_NAME)
    include_path = os.path.join(ta_path, "include")
    if not create_dir(ta_path, "include"):
        return False

    # Create header file
    include_content = f"""#ifndef _{pro_name.upper()}_H
#define _{pro_name.upper()}_H

{define_str}

#endif /* _{pro_name.upper()}_H */
"""

    include_file = os.path.join(include_path, f"{pro_name}.h")
    if not write_file(include_file, include_content):
        return False

    # Create TA source file
    ta_src_content = f"""#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/{pro_name}.h"

/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/

TEE_Result TA_CreateEntryPoint(void)
{{
    return TEE_SUCCESS;
}}

void TA_DestroyEntryPoint(void)
{{
}}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_type, TEE_Param params[4], void **sess_ctx)
{{
    return TEE_SUCCESS;
}}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{{
}}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{{
    switch(cmd) {{
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }}
}}

/**
 * @brief 配置到开发板指令

 * 注意: 开发本需提前配置好SSH环境, 
 * 根文件系统也需要支持OPTEE, buildroot自行配置

 * /lib/optee_armtz 是OPTEE寻找TA的默认地址
 * /usr/bin 让CA目标文件可以直接当作命令运行
 
 * scp {pro_name}/ta/{uuid_str}.ta {DEFAULT_HOST_NAME}@{DEFAULT_IP}:/lib/optee_armtz
 * scp {pro_name}/host/{pro_name} {DEFAULT_HOST_NAME}@{DEFAULT_IP}:/usr/bin
 */

"""

    ta_src_path = os.path.join(ta_path, f"{pro_name}.c")
    if not write_file(ta_src_path, ta_src_content):
        return False

    # Create user_ta_header_defines.h
    ta_hdr_content = f"""/*
 * The name of this file must not be modified
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <include/{pro_name}.h>

#define TA_UUID\t\t\t{define_name}

#define TA_FLAGS\t\t\t(TA_FLAG_EXEC_DDR | TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION)

#define TA_STACK_SIZE\t\t(2 * 1024)

#define TA_DATA_SIZE\t\t(32 * 1024)

#endif /* USER_TA_HEADER_DEFINES_H */
"""

    ta_hdr_path = os.path.join(ta_path, "user_ta_header_defines.h")
    if not write_file(ta_hdr_path, ta_hdr_content):
        return False

    # Create Makefile
    ta_makefile_content = f"""CFG_TEE_TA_LOG_LEVEL ?= 4
CFG_TA_OPTEE_CORE_API_COMPAT_1_1=y

# The UUID for the Trusted Application
BINARY={uuid_str}

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
\t@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
\t@echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
"""

    ta_makefile_path = os.path.join(ta_path, "Makefile")
    if not write_file(ta_makefile_path, ta_makefile_content):
        return False

    # Create sub.mk
    sub_make_content = f"""global-incdirs-y += include
srcs-y += {pro_name}.c

# To remove a certain compiler flag, add a line like this
# cflags-template_ta.c-y += -Wno-strict-prototypes
"""

    sub_make_path = os.path.join(ta_path, "sub.mk")
    if not write_file(sub_make_path, sub_make_content):
        return False

    return True


def create_ca_ta_project(pro_name):
    root_path = os.getcwd()

    if not create_dir(root_path, pro_name):
        return False

    pro_path = os.path.join(root_path, pro_name)

    define_name = f"TA_{pro_name.upper()}_UUID"
    uuid_str, define_str = generate_uuid_define(define_name)

    if not create_host(pro_path, pro_name, define_name, uuid_str):
        return False

    if not create_ta(pro_path, pro_name, define_name, define_str, uuid_str):
        return False

    if not create_root_makefile(pro_path):
        return False

    return True


def main():
    if len(sys.argv) != 2:
        print("Usage: create_ca_ta_project.py [project name]")
        sys.exit(1)

    project_name = sys.argv[1]
    if create_ca_ta_project(project_name):
        print("Project created successfully")
    else:
        print("Failed to create project")


if __name__ == '__main__':
    main()
