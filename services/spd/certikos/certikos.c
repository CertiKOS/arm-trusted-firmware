/*
 * Copyright (c) 2016-2019, ARM Limited and Contributors. All rights reserved.
 * Copyright (c) 2020, NVIDIA Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <lib/xlat_tables/xlat_tables_v2.h>
#include <stdbool.h>
#include <string.h>

#include <arch_helpers.h>
#include <bl31/bl31.h>
#include <bl31/interrupt_mgmt.h>
#include <common/bl_common.h>
#include <common/debug.h>
#include <common/runtime_svc.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <lib/smccc.h>
#include <plat/common/platform.h>
#include <tools_share/uuid.h>

#include "sm_err.h"
#include "smcall.h"


typedef struct {
	uint8_t space[PLATFORM_STACK_SIZE] __aligned(16);
	uint32_t end;
} certikos_el3_stack;

//struct trusty_cpu_ctx {
typedef struct {
	cpu_context_t	    cpu_ctx;
	void		        *saved_sp;
	uint32_t	        saved_security_state;
	int32_t		        fiq_handler_active;
	uint64_t	        fiq_handler_pc;
	uint64_t	        fiq_handler_cpsr;
	uint64_t	        fiq_handler_sp;
	uint64_t	        fiq_pc;
	uint64_t	        fiq_cpsr;
	uint64_t	        fiq_sp_el1;
	gp_regs_t	        fiq_gpregs;
	certikos_el3_stack  secure_stack;
} certikos_el3_cpu_ctx;


static certikos_el3_cpu_ctx cpu_ctx[PLATFORM_CORE_COUNT];

static certikos_el3_cpu_ctx *
get_cpu_ctx(void)
{
    return &cpu_ctx[plat_my_core_pos()];
}



static uint64_t
certikos_el3_fiq(uint32_t id, uint32_t flags, void *handle, void *cookie)
{


    SMC_RET0(handle);
}

static void
certikos_el3_boot_normal_world(void)
{
}


static int32_t
certikos_el3_setup(void)
{
    NOTICE("BL3-1: Starting CertiKOS Service");

    /* Tell the framework to route Secure World FIQs to EL3 during NS execution */
    uint32_t flags = 0;
    set_interrupt_rm_flag(flags, SECURE);
    if(register_interrupt_type_handler(INTR_TYPE_NS, certikos_el3_fiq, flags) != 0) {
    }

    return 1;
}


static uintptr_t
certikos_el3_smc_handler(
        uint32_t smc_fid,
        u_register_t x1,
        u_register_t x2,
        u_register_t x3,
        u_register_t x4,
        void *cookie,
        void *handle,
        u_register_t flags)
{
    if(is_caller_secure(flags)) {
        SMC_RET1(handle, SMC_UNK);
    } else {
        switch(smc_fid) {
            default:
                NOTICE("Unknown SMC (id=0x%x)\n", smc_fid);
                SMC_RET1(handle, SMC_UNK);
                break;
        }
    }
}


/* Define a SPD runtime service descriptor for fast SMC calls */
DECLARE_RT_SVC(
	certikos_el3_fast,

	OEN_TAP_START,
	OEN_TOS_END,
	SMC_TYPE_FAST,
	certikos_el3_setup,
	certikos_el3_smc_handler
);

/* Define a SPD runtime service descriptor for yielding SMC calls */
DECLARE_RT_SVC(
	certikos_el3_std,

	OEN_TAP_START,
	OEN_TOS_END,
	SMC_TYPE_YIELD,
	NULL,
	trusty_smc_handler
);
