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
#include "certikos_private.h"


typedef struct {
	uint8_t space[PLATFORM_STACK_SIZE] __aligned(16);
	uint32_t end;
} certikos_el3_stack;


typedef struct {
	cpu_context_t	    cpu_ctx;
	void		        *saved_sp;
	uint32_t	        saved_security_state;
    uintptr_t           el1_fiq_handler;
    uintptr_t           el1_smc_handler;
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
    //NOTICE("BL3-1: Certikos FIQ\n");

    /* Switch to secure world */
    //fpregs_context_save(get_fpregs_ctx(cm_get_context(NON_SECURE)));
    cm_el1_sysregs_context_save(NON_SECURE);

    el3_state_t *el3_state = get_el3state_ctx(handle);

    certikos_el3_cpu_ctx *ctx = get_cpu_ctx();
    cm_set_elr_el3(SECURE, ctx->el1_fiq_handler);

    write_ctx_reg(get_el1_sysregs_ctx(ctx), CTX_ESR_EL1, read_ctx_reg(el3_state, CTX_ESR_EL1));

    cm_el1_sysregs_context_restore(SECURE);
    //fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
    cm_set_next_eret_context(SECURE);



    SMC_RET0(&ctx->cpu_ctx);
}

static int32_t
certikos_el3_boot_certikos(void)
{
    NOTICE("BL3-1: Booting CertiKOS\n");

    entry_point_info_t* certikos_ep = bl31_plat_get_next_image_ep_info(SECURE);
    assert(certikos_ep != NULL);

    certikos_ep->spsr = SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS);
    memset(&certikos_ep->args, 0, sizeof(certikos_ep->args));

    EP_SET_ST(certikos_ep->h.attr, EP_ST_ENABLE);

    //fpregs_context_save(get_fpregs_ctx(cm_get_context(NON_SECURE)));
    cm_el1_sysregs_context_save(NON_SECURE);

    certikos_el3_cpu_ctx *ctx = get_cpu_ctx();
    cm_set_context(&ctx->cpu_ctx, SECURE);
    cm_init_my_context(certikos_ep);

    cm_el1_sysregs_context_restore(SECURE);
    //fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
    cm_set_next_eret_context(SECURE);

    certikos_el3_world_switch_return(&ctx->saved_sp);


    NOTICE("BL3-1: Booting Normal World\n");
    entry_point_info_t* ns_ep = bl31_plat_get_next_image_ep_info(NON_SECURE);
    assert(ns_ep != NULL);

    cm_el1_sysregs_context_restore(NON_SECURE);
    //fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
    cm_set_next_eret_context(NON_SECURE);

    return 1;
}


static int32_t
certikos_el3_setup(void)
{
    NOTICE("BL3-1: Starting CertiKOS Service\n");

    /* Tell the framework to route Secure World FIQs to EL3 during NS execution */
    uint32_t flags = 0;
    set_interrupt_rm_flag(flags, NON_SECURE);
    if(register_interrupt_type_handler(INTR_TYPE_S_EL1, certikos_el3_fiq, flags) != 0) {
    }

    bl31_register_bl32_init(certikos_el3_boot_certikos);

    return 0;
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
    cpu_context_t *ns_ctx;
    certikos_el3_cpu_ctx * ctx;


    if(is_caller_secure(flags)) {
        switch(smc_fid) {
            case SMC_FC_FIQ_EXIT:
            case SMC_FC64_FIQ_EXIT:
                ns_ctx = cm_get_context(NON_SECURE);
                cm_el1_sysregs_context_restore(NON_SECURE);
                cm_set_next_eret_context(NON_SECURE);

                SMC_RET0(ns_ctx);

            case SMC_FC64_ENTRY_DONE:
                ctx = get_cpu_ctx();
                ctx->el1_fiq_handler = x1;
                ctx->el1_smc_handler = x2;
                certikos_el3_world_switch_enter(ctx->saved_sp);

                NOTICE("BACK HERE?\n");
                SMC_RET1(handle, SMC_UNK);

            default:
                NOTICE("Unknown SMC (id=0x%x)\n", smc_fid);
                SMC_RET1(handle, SMC_UNK);
        }
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
	certikos_el3_smc_handler
);
