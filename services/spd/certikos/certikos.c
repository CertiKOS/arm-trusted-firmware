/*
 * Copyright (c) 2016-2019, ARM Limited and Contributors. All rights reserved.
 * Copyright (c) 2020, NVIDIA Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <xlat_tables/xlat_tables_v2.h>
#include <stdbool.h>
#include <string.h>

#include <arch_helpers.h>
#include <bl31.h>
#include <interrupt_mgmt.h>
#include <bl_common.h>
#include <debug.h>
#include <runtime_svc.h>
#include <el3_runtime/context_mgmt.h>
#include <smccc.h>
#include <platform.h>
#include <uuid.h>

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
    uintptr_t           el1_start_ap;
	gp_regs_t	        fiq_gpregs;
	//certikos_el3_stack  secure_stack;
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
    /* Switch to secure world */
    //fpregs_context_save(get_fpregs_ctx(cm_get_context(NON_SECURE)));
    cm_el1_sysregs_context_save(NON_SECURE);

    el3_state_t *el3_state = get_el3state_ctx(handle);

    certikos_el3_cpu_ctx *ctx = get_cpu_ctx();
    cm_set_elr_el3(SECURE, ctx->el1_fiq_handler);

    write_ctx_reg(get_sysregs_ctx(ctx), CTX_ESR_EL1, read_ctx_reg(el3_state, CTX_ESR_EL1));
    //NOTICE("BL31: SCR=0x%lx\n", read_ctx_reg(el3_state, CTX_SCR_EL3));
    //NOTICE("BL31: FIQ %x\n", flags);

    cm_el1_sysregs_context_restore(SECURE);
    //fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
    cm_set_next_eret_context(SECURE);

    SMC_RET0(&ctx->cpu_ctx);
}

static int32_t
certikos_el3_boot_certikos(void)
{
    NOTICE("BL31: Booting CertiKOS\n");

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


    if(plat_my_core_pos() != 0)
    {
        certikos_ep->pc = ctx->el1_start_ap;
    }

    //cm_write_scr_el3_bit(SECURE, __builtin_ctz(SCR_SIF_BIT), 0);
    //cm_write_scr_el3_bit(SECURE, __builtin_ctz(SCR_EA_BIT), 1);
    //cm_write_scr_el3_bit(SECURE, __builtin_ctz(SCR_FIQ_BIT), 1);
    //cm_write_scr_el3_bit(SECURE, __builtin_ctz(SCR_IRQ_BIT), 1);

    //cm_write_scr_el3_bit(NON_SECURE, __builtin_ctz(SCR_EA_BIT), 1);
    //cm_write_scr_el3_bit(NON_SECURE, __builtin_ctz(SCR_FIQ_BIT), 1);
    //cm_write_scr_el3_bit(NON_SECURE, __builtin_ctz(SCR_IRQ_BIT), 1);

    NOTICE("BL31: CertiKOS SCR=0x%lx\n", read_ctx_reg(get_el3state_ctx(ctx), CTX_SCR_EL3));
    NOTICE("BL31: CertiKOS PC=%p\n", (void*)certikos_ep->pc);

    certikos_el3_world_switch_return(&ctx->saved_sp);


    NOTICE("BL31: Booting Normal World\n");
    entry_point_info_t* ns_ep = bl31_plat_get_next_image_ep_info(NON_SECURE);
    assert(ns_ep != NULL);

    //NOTICE("BL31: Cboot PC=%p\n", (void*)ns_ep->pc);

    cm_el1_sysregs_context_restore(NON_SECURE);
    //fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
    cm_set_next_eret_context(NON_SECURE);


    return 1;
}


static int32_t
certikos_el3_cpu_off(uint64_t v)
{
    NOTICE("certikos el3 cpu off %u\n", plat_my_core_pos());
    return 0;
}

static void
certikos_el3_cpu_on_finish(uint64_t v)
{
    NOTICE("BL31: Booting CertiKOS on core %u\n", plat_my_core_pos());

    certikos_el3_cpu_ctx *ctx = get_cpu_ctx();
    if(ctx->saved_sp == NULL)
    {
        certikos_el3_boot_certikos();
    }
}

static void
certikos_el3_cpu_suspend(uint64_t max_off_lvl)
{
    NOTICE("certikos el3 cpu suspend %u\n", plat_my_core_pos());
}

static void
certikos_el3_cpu_suspend_finish(uint64_t max_off_lvl)
{
    NOTICE("certikos el3 cpu suspend finish %u\n", plat_my_core_pos());
}



static int32_t
certikos_el3_setup(void)
{
    NOTICE("BL31: Starting CertiKOS Service\n");

    static const spd_pm_ops_t certikos_pm = {
        .svc_off = certikos_el3_cpu_off,
        .svc_suspend = certikos_el3_cpu_suspend,
        .svc_on_finish = certikos_el3_cpu_on_finish,
        .svc_suspend_finish = certikos_el3_cpu_suspend_finish,
    };
    psci_register_spd_pm_hook(&certikos_pm);

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

    (void)(ns_ctx);



    if(is_caller_secure(flags)) {
        switch(smc_fid) {
            case SMC_FC_FIQ_EXIT:
            case SMC_FC64_FIQ_EXIT:
                cm_el1_sysregs_context_save(SECURE);

                ns_ctx = cm_get_context(NON_SECURE);
                cm_el1_sysregs_context_restore(NON_SECURE);
                cm_set_next_eret_context(NON_SECURE);

                SMC_RET0(ns_ctx);

            case SMC_FC64_ENTRY_DONE:
                ctx = get_cpu_ctx();
                ctx->el1_fiq_handler = x1;
                ctx->el1_smc_handler = x2;
                ctx->el1_start_ap = x3;

                cm_el1_sysregs_context_save(SECURE);

                certikos_el3_world_switch_enter(ctx->saved_sp);

                NOTICE("BACK HERE?\n");
                SMC_RET1(handle, SMC_UNK);

            default:
                NOTICE("Unknown SMC (id=0x%x)\n", smc_fid);
                SMC_RET1(handle, SMC_UNK);
        }
    } else {
        NOTICE("BL31: SMC fid:%x, x1:%lx, x2:%lx, x3:%lx, x4:%lx\n", smc_fid, x1, x2, x3, x4);
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
