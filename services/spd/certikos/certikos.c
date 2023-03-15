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

/* Set this to zero to disable */
#define MULTICORE_ENABLE        (1)

typedef struct {
    uint8_t space[PLATFORM_STACK_SIZE] __aligned(16);
    uint32_t end;
} certikos_el3_stack;


typedef struct {
    cpu_context_t       cpu_ctx;
    void                *saved_sp;
    uint32_t            saved_security_state;
    uintptr_t           el1_fiq_handler;
    uintptr_t           el1_smc_handler;
    gp_regs_t           fiq_gpregs;
    uint64_t            pmuserenr_el0;
    certikos_el3_stack  secure_stack;
} certikos_el3_cpu_ctx __attribute__((aligned(64)));




uintptr_t start_ap_global;
static certikos_el3_cpu_ctx cpu_ctx[PLATFORM_CORE_COUNT];

static certikos_el3_cpu_ctx *
get_cpu_ctx(void)
{
    return &cpu_ctx[plat_my_core_pos()];
}


static void certkos_el3_swap_extra_regs(certikos_el3_cpu_ctx * ctx)
{
    uint64_t saved = ctx->pmuserenr_el0;
    uint64_t current;
    asm volatile("mrs %0, pmuserenr_el0" : "=r"(current));
    asm volatile("msr pmuserenr_el0, %0":: "r"(saved));
    ctx->pmuserenr_el0 = current;
}


extern uint8_t certikos_kernel_start[];
extern uint8_t certikos_kernel_end[];
extern int certikos_kernel_size;



static uint64_t
certikos_el3_fiq(uint32_t id, uint32_t flags, void *handle, void *cookie)
{
    /* Switch to secure world */

#if CTX_INCLUDE_FPREGS
    fpregs_context_save(get_fpregs_ctx(cm_get_context(NON_SECURE)));
#endif
    cm_el1_sysregs_context_save(NON_SECURE);


    certikos_el3_cpu_ctx *ctx = get_cpu_ctx();
    certkos_el3_swap_extra_regs(ctx);
    cm_set_elr_el3(SECURE, ctx->el1_fiq_handler);

#if CTX_INCLUDE_FPREGS
    fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
#endif
    cm_el1_sysregs_context_restore(SECURE);
    cm_set_next_eret_context(SECURE);

    SMC_RET0(&ctx->cpu_ctx);
}


static int32_t
certikos_el3_boot_certikos(void)
{
    entry_point_info_t * certikos_ep = bl31_plat_get_next_image_ep_info(SECURE);
    certikos_el3_cpu_ctx * ctx = get_cpu_ctx();

    entry_point_info_t * linux_ep = bl31_plat_get_next_image_ep_info(NON_SECURE);
    NOTICE("BL31: LINUX PC=%p\n", (void*)linux_ep->pc);
    NOTICE("BL31: LINUX ARG0=%p\n", (void*)linux_ep->args.arg0);
    NOTICE("BL31: LINUX ARG1=%p\n", (void*)linux_ep->args.arg1);
    NOTICE("BL31: LINUX ARG2=%p\n", (void*)linux_ep->args.arg2);
    NOTICE("BL31: LINUX ARG3=%p\n", (void*)linux_ep->args.arg3);

    NOTICE("BL31: Booting CertiKOS on core %u\n", plat_my_core_pos());


    certikos_ep->spsr = SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS);
    memset(&certikos_ep->args, 0, sizeof(certikos_ep->args));

    char * certikos_link_addr = (char *)(CERTIKOS_KERNEL_BIN_LINK_ADDR);

    memcpy(certikos_link_addr, certikos_kernel_start, certikos_kernel_size);
    flush_dcache_range((uintptr_t)certikos_link_addr, certikos_kernel_size);
    inv_dcache_range((uintptr_t)certikos_link_addr, certikos_kernel_size);

    certikos_ep->pc = (uintptr_t)certikos_link_addr;

    EP_SET_ST(certikos_ep->h.attr, EP_ST_ENABLE);


#if CTX_INCLUDE_FPREGS
    fpregs_context_save(get_fpregs_ctx(cm_get_context(NON_SECURE)));
#endif
    cm_el1_sysregs_context_save(NON_SECURE);

    cm_set_context(&ctx->cpu_ctx, SECURE);
    cm_init_my_context(certikos_ep);

#if CTX_INCLUDE_FPREGS
    fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
#endif
    cm_el1_sysregs_context_restore(SECURE);
    cm_set_next_eret_context(SECURE);

    uint64_t scr = read_ctx_reg(get_el3state_ctx(ctx), CTX_SCR_EL3);
    write_ctx_reg(get_el3state_ctx(ctx), CTX_SCR_EL3, scr & ~(SCR_SIF_BIT));

    NOTICE("BL31: CertiKOS SCR=0x%llx\n", read_ctx_reg(get_el3state_ctx(ctx), CTX_SCR_EL3));
    NOTICE("BL31: CertiKOS SCTLR=0x%llx\n", read_ctx_reg(get_el1_sysregs_ctx(ctx), CTX_SCTLR_EL1));
    NOTICE("BL31: CertiKOS PC=%p\n", (void*)certikos_ep->pc);

    certikos_el3_world_switch_return(&ctx->saved_sp);


    NOTICE("BL31: Booting Normal World\n");
    //entry_point_info_t* ns_ep = bl31_plat_get_next_image_ep_info(NON_SECURE);
    //assert(ns_ep != NULL);

#if CTX_INCLUDE_FPREGS
    fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
#endif
    cm_el1_sysregs_context_restore(NON_SECURE);
    cm_set_next_eret_context(NON_SECURE);

    return 1;
}

static int32_t
certikos_el3_cpu_off(u_register_t v)
{
    NOTICE("certikos el3 cpu off %u\n", plat_my_core_pos());
    return 0;
}

static void
certikos_el3_cpu_on_finish(u_register_t v)
{
    NOTICE("BL31: CPU on, core %u\n", plat_my_core_pos());

    certikos_el3_cpu_ctx *ctx = get_cpu_ctx();
    if(ctx->saved_sp == NULL)
    {
        assert(MULTICORE_ENABLE && "Multicore Disabled");

        NOTICE("BL31: Booting CertiKOS on core %u\n", plat_my_core_pos());
        entry_point_info_t core_ep;

        core_ep.pc = start_ap_global;
        core_ep.spsr = SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS);
        memset(&core_ep.args, 0, sizeof(core_ep.args));
        SET_PARAM_HEAD(&core_ep, PARAM_EP, VERSION_1, SECURE | EP_ST_ENABLE |
            ((read_sctlr_el3() & SCTLR_EE_BIT) ? EP_EE_BIG : 0));

        fpregs_context_save(get_fpregs_ctx(cm_get_context(NON_SECURE)));

        cm_set_context(&ctx->cpu_ctx, SECURE);
        cm_init_my_context(&core_ep);

        cm_el1_sysregs_context_restore(SECURE);
        fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
        cm_set_next_eret_context(SECURE);

        NOTICE("BL31: CertiKOS SCR=0x%llx\n", read_ctx_reg(get_el3state_ctx(ctx), CTX_SCR_EL3
));
        NOTICE("BL31: CertiKOS PC=%p\n", (void*)core_ep.pc);

        uint64_t ret = certikos_el3_world_switch_return(&ctx->saved_sp);
        (void)(ret);

        NOTICE("BL31: Finished booting CertiKOS on core %u\n", plat_my_core_pos());

        //cm_el1_sysregs_context_restore(NON_SECURE);
        //fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
        //cm_set_next_eret_context(NON_SECURE);
    }
}

static void
certikos_el3_cpu_suspend(u_register_t max_off_lvl)
{
    NOTICE("certikos el3 cpu suspend %u\n", plat_my_core_pos());
}

static void
certikos_el3_cpu_suspend_finish(u_register_t max_off_lvl)
{
    NOTICE("certikos el3 cpu suspend finish %u\n", plat_my_core_pos());
}


static int32_t
certikos_el3_setup(void)
{
    static const spd_pm_ops_t certikos_pm = {
        .svc_off = certikos_el3_cpu_off,
        .svc_suspend = certikos_el3_cpu_suspend,
        .svc_on_finish = certikos_el3_cpu_on_finish,
        .svc_suspend_finish = certikos_el3_cpu_suspend_finish,
    };
    psci_register_spd_pm_hook(&certikos_pm);


    NOTICE("BL31: Starting CertiKOS Service\n");
    NOTICE("BL31: CertiKOS BIN ADDR %p\n", certikos_kernel_start);
    NOTICE("BL31: CertiKOS BIN SIZE %d\n", certikos_kernel_size);

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
    cpu_context_t *ns_ctx = cm_get_context(NON_SECURE);
    certikos_el3_cpu_ctx * ctx = get_cpu_ctx();

    if(is_caller_secure(flags)) {
        switch(smc_fid) {
            case SMC_FC_FIQ_EXIT:
            case SMC_FC64_FIQ_EXIT:
                cm_el1_sysregs_context_save(SECURE);
#if CTX_INCLUDE_FPREGS
                fpregs_context_save(get_fpregs_ctx(cm_get_context(SECURE)));
                fpregs_context_restore(get_fpregs_ctx(ns_ctx));
#endif
                cm_el1_sysregs_context_restore(NON_SECURE);
                cm_set_next_eret_context(NON_SECURE);

                certkos_el3_swap_extra_regs(ctx);

                SMC_RET0(ns_ctx);

            case SMC_FC64_ENTRY_DONE:

                ctx->el1_fiq_handler = x1;
                ctx->el1_smc_handler = x2;
                start_ap_global = x3;

                cm_el1_sysregs_context_save(SECURE);
#if CTX_INCLUDE_FPREGS
                fpregs_context_save(get_fpregs_ctx(cm_get_context(SECURE)));
#endif
                certkos_el3_swap_extra_regs(ctx);

                certikos_el3_world_switch_enter(ctx->saved_sp, 0);

                NOTICE("BACK HERE?\n");
                SMC_RET1(handle, SMC_UNK);

            case SMC_FC64_NEW_VECTOR_TABLE:
                {
                    //u_register_t asid_el3   = read_asid_el3();
                    //u_register_t vbar_el3   = read_vbar_el3();
                    //u_register_t tcr_el3    = read_tcr_el3();
                    //u_register_t mair_el3   = read_mair_el3();
                    //u_register_t ttbr0_el3  = read_ttbr0_el3();
                    //u_register_t ttbr1_el3  = read_ttbr1_el3();
                    u_register_t sctlr_el3  = read_sctlr_el3();

                    //u_register_t asid_el1   = read_asid_el1();
                    //u_register_t vbar_el1   = read_vbar_el1();
                    //u_register_t tcr_el1    = read_tcr_el1();
                    u_register_t mair_el1   = read_mair_el1();
                    u_register_t ttbr0_el1  = read_ttbr0_el1();
                    //u_register_t ttbr1_el1  = read_ttbr1_el1();
                    //u_register_t sctlr_el1  = read_sctlr_el1();
                    //

                    flush_dcache_range((uintptr_t)ns_ctx, sizeof(cpu_context_t));
                    flush_dcache_range((uintptr_t)ctx, sizeof(certikos_el3_cpu_ctx));

                    //NOTICE("Disabling MMU...\n");
                    write_sctlr_el3(sctlr_el3 & ~(SCTLR_M_BIT));

                    //NOTICE("Swapping EL3 and EL1 Registers...\n");

                    //NOTICE("vbar_el3 : 0x%zx -> 0x%zx\n", vbar_el3 , x4 );
                    write_vbar_el3(x4);
                    isb();

                    //NOTICE("mair_el3 : 0x%zx -> 0x%zx\n", mair_el3 , mair_el1 );
                    write_mair_el3(mair_el1);
                    isb();

                    //NOTICE("ttbr0_el3: 0x%zx -> 0x%zx\n", ttbr0_el3, ttbr0_el1);
                    write_ttbr0_el3(ttbr0_el1);
                    isb();

                    //NOTICE("sctlr_el3: 0x%zx -> 0x%zx\n", sctlr_el3, sctlr_el1);
                    //write_sctlr_el3(sctlr_el1);

                    //NOTICE("Enabling MMU...\n");
                    write_sctlr_el3(sctlr_el3
                        & ~(SCTLR_A_BIT | SCTLR_nAA_BIT | SCTLR_WXN_BIT));

                    isb();
                    tlbialle3();
                    isb();
                    inv_dcache_range((uintptr_t)ns_ctx, sizeof(cpu_context_t));
                    inv_dcache_range((uintptr_t)ctx, sizeof(certikos_el3_cpu_ctx));
                    isb();


                    //NOTICE("tcr_el3  : 0x%zx -> 0x%zx\n", tcr_el3  , tcr_el1  );
                    //NOTICE("ttbr1_el3: %p -> %p\n", ttbr1_el3, ttbr1_el1);


                    //while(1);

                    cm_el1_sysregs_context_save(SECURE);
#if CTX_INCLUDE_FPREGS
                    fpregs_context_save(get_fpregs_ctx(cm_get_context(SECURE)));
                    fpregs_context_restore(get_fpregs_ctx(ns_ctx));
#endif
                    cm_el1_sysregs_context_restore(NON_SECURE);
                    cm_set_next_eret_context(NON_SECURE);

                    certkos_el3_swap_extra_regs(ctx);

                    SMC_RET0(ns_ctx);
                }

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
