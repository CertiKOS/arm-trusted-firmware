/*
 * Copyright (c) 2016-2019, ARM Limited and Contributors. All rights reserved.
 * Copyright (c) 2020, NVIDIA Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
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
#include <memctrl.h>
#include <xlat_tables_v2.h>

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
	cpu_context_t	        cpu_ctx;
	void		            *saved_sp;
    uintptr_t               el1_fiq_handler;
    uintptr_t               el1_smc_handler;
    uintptr_t               el1_start_ap;
	gp_regs_t	            fiq_gpregs;
    uint64_t                pmuserenr_el0;
	//certikos_el3_stack  secure_stack;
} certikos_el3_cpu_ctx;


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


//static void debug_putc_uartc(char c)
//{
//    uintptr_t base = 0x0c280000u;
//    while((volatile char*)(base + 0x14) == 0);
//
//    *((volatile char*) base) = c;
//}

//#define ELR_HIST_SIZE (5000)
//
//typedef struct {
//    size_t prev_elr_count;
//    size_t prev_elr;
//} core_debug_info;
//
//static core_debug_info debug_info[PLATFORM_CORE_COUNT] = {0};
//
//void core_debug_handle_fiq(core_debug_info* debug_info)
//{
//    cpu_context_t* ns_context = cm_get_context(NON_SECURE);
//
//    uintptr_t elr_el3 = read_ctx_reg(get_el3state_ctx(ns_context), CTX_ELR_EL3);
//
//    if(elr_el3 == debug_info->prev_elr)
//    {
//        debug_info->prev_elr_count++;
//
//        if(debug_info->prev_elr_count >= ELR_HIST_SIZE)
//        {
//            NOTICE("CORE %u STUCK FOR %u TICKS AT %p\n",
//                plat_my_core_pos(),
//                ELR_HIST_SIZE,
//                (void*)debug_info->prev_elr);
//
//
//            uintptr_t ttbr1_el1 = read_ctx_reg(get_sysregs_ctx(ns_context), CTX_TTBR1_EL1);
//
//            NOTICE("  - ESR_EL1 %p\n",
//                (void*)read_ctx_reg(get_sysregs_ctx(ns_context), CTX_ESR_EL1));
//            NOTICE("  - TTBR1_EL1 %p\n", (void*)ttbr1_el1);
//
//            size_t l1_index = (debug_info->prev_elr >> 30) & 0x1FF;
//            size_t l2_index = (debug_info->prev_elr >> 21) & 0x1FF;
//            size_t l3_index = (debug_info->prev_elr >> 12) & 0x1FF;
//
//            NOTICE("  - l1_index=%lu, l2_index=%lu, l3_index=%lu\n",
//                l1_index, l2_index, l3_index);
//
//            uint32_t ret =
//                mmap_add_dynamic_region(ttbr1_el1, ttbr1_el1, 0x1000, MT_RO_DATA);
//
//            uint64_t l1_desc = ((uint64_t*)ttbr1_el1)[l1_index];
//            uintptr_t l2_addr = (l1_desc) & 0xFFFFFF000ull;
//            NOTICE("  - l1_desc=%lx, l2_addr=%lx\n", l1_desc, l2_addr);
//
//            ret = mmap_add_dynamic_region(l2_addr, l2_addr, 0x1000, MT_RO_DATA);
//
//            uint64_t l2_desc = ((uint64_t*)l2_addr)[l2_index];
//
//            if((l2_desc & 0x3) == 0x1)
//            {
//                uintptr_t mem_addr = (l2_desc & 0xFFFFFFE00000llu) | (debug_info->prev_elr & 0x1FFFFFllu);
//                uintptr_t mem_addr_pg = mem_addr & (~0xFFFllu);
//
//                NOTICE("  - l2_desc=%lx, mem_addr=%lx, mem_addr_pg=%lx\n", l2_desc, mem_addr, mem_addr_pg);
//                ret = mmap_add_dynamic_region(mem_addr_pg, mem_addr_pg, 0x1000, MT_RO_DATA);
//
//                NOTICE("  - mem: %x\n", *(uint32_t *)mem_addr);
//
//            }
//            else
//            {
//                uintptr_t l3_addr = (l2_desc) & 0xFFFFFF000ull;
//                NOTICE("  - l2_desc=%lx, l3_addr=%lx\n", l2_desc, l3_addr);
//            }
//
//
//
//            (void)ret;
//
//            debug_info->prev_elr_count = 0;
//        }
//    }
//    debug_info->prev_elr = elr_el3;
//}


static uint64_t
certikos_el3_fiq(uint32_t id, uint32_t flags, void *handle, void *cookie)
{
    /* Switch to secure world */
    //putchar('F');
    //debug_putc_uartc('<');

#if CTX_INCLUDE_FPREGS
    fpregs_context_save(get_fpregs_ctx(cm_get_context(NON_SECURE)));
#endif
    cm_el1_sysregs_context_save(NON_SECURE);

    //static int64_t counter[8] = {0};
    //if(counter[plat_my_core_pos()] == 0)
    //{
    //    cpu_context_t* ns_context = cm_get_context(NON_SECURE);
    //    NOTICE(">>>>>>>>EL3 FIQ Heartbeat(%u): ELR_EL3=%p SP_EL1=%p LR=%p\n",
    //        plat_my_core_pos(),
    //        (void*)read_ctx_reg(get_el3state_ctx(ns_context), CTX_ELR_EL3),
    //        (void*)read_ctx_reg(get_sysregs_ctx(ns_context), CTX_SP_EL1),
    //        (void*)read_ctx_reg(get_gpregs_ctx(ns_context), CTX_GPREG_LR));
    //}
    //counter[plat_my_core_pos()] = (counter[plat_my_core_pos()] + 1) % 2000;

    //core_debug_handle_fiq(&debug_info[plat_my_core_pos()]);
        //cpu_context_t* ns_context = cm_get_context(NON_SECURE);
        //NOTICE(">>>>>>>>EL3 FIQ Heartbeat(%u): ELR_EL3=%p SP_EL1=%p LR=%p\n",
        //    plat_my_core_pos(),
        //    (void*)read_ctx_reg(get_el3state_ctx(ns_context), CTX_ELR_EL3),
        //    (void*)read_ctx_reg(get_sysregs_ctx(ns_context), CTX_SP_EL1),
        //    (void*)read_ctx_reg(get_gpregs_ctx(ns_context), CTX_GPREG_LR));


    certikos_el3_cpu_ctx *ctx = get_cpu_ctx();
    certkos_el3_swap_extra_regs(ctx);
    cm_set_elr_el3(SECURE, ctx->el1_fiq_handler);


    cm_el1_sysregs_context_restore(SECURE);
#if CTX_INCLUDE_FPREGS
    fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
#endif
    cm_set_next_eret_context(SECURE);

    SMC_RET0(&ctx->cpu_ctx);
}

static int32_t
certikos_el3_boot_certikos(void)
{

    entry_point_info_t * certikos_ep = bl31_plat_get_next_image_ep_info(SECURE);
    certikos_el3_cpu_ctx *ctx = get_cpu_ctx();

    NOTICE("BL31: Booting CertiKOS on core %u\n", plat_my_core_pos());

    certikos_ep->spsr = SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS);
    memset(&certikos_ep->args, 0, sizeof(certikos_ep->args));

    EP_SET_ST(certikos_ep->h.attr, EP_ST_ENABLE);
    cm_set_context(&ctx->cpu_ctx, SECURE);
    cm_init_my_context(certikos_ep);

#if CTX_INCLUDE_FPREGS
    fpregs_context_save(get_fpregs_ctx(cm_get_context(NON_SECURE)));
    fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
#endif
    cm_el1_sysregs_context_save(NON_SECURE);
    cm_el1_sysregs_context_restore(SECURE);

    cm_set_next_eret_context(SECURE);

    /* take Aborts and SErrors to EL3 */
    //uint64_t scr_el3 = read_ctx_reg(get_el3state_ctx(ctx), CTX_SCR_EL3);
    //scr_el3 |= SCR_EA_BIT;
    //write_ctx_reg(get_el3state_ctx(ctx), CTX_SCR_EL3, scr_el3);

    NOTICE("BL31: CertiKOS SCR=0x%lx\n",
        read_ctx_reg(get_el3state_ctx(ctx), CTX_SCR_EL3));
    NOTICE("BL31: CertiKOS PC=%p\n", (void*)certikos_ep->pc);

    certikos_el3_world_switch_return(&ctx->saved_sp);

    NOTICE("BL31: Booting Normal World\n");

    cm_el1_sysregs_context_restore(NON_SECURE);
#if CTX_INCLUDE_FPREGS
    fpregs_context_restore(get_fpregs_ctx(cm_get_context(NON_SECURE)));
#endif
    cm_set_next_eret_context(NON_SECURE);

    /* take Aborts and SErrors to EL3 */


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
    NOTICE("BL31: CPU on, core %u\n", plat_my_core_pos());

    certikos_el3_cpu_ctx *ctx = get_cpu_ctx();
    if(ctx->saved_sp == NULL)
    {
        //assert(MULTICORE_ENABLE && "Multicore Disabled");

        NOTICE("BL31: Booting CertiKOS on core %u\n", plat_my_core_pos());
        entry_point_info_t core_ep;

        memset(&core_ep, 0, sizeof(core_ep));

        core_ep.pc = start_ap_global;
        core_ep.spsr = SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS);
//        memset(&core_ep.args, 0, sizeof(core_ep.args));
        SET_PARAM_HEAD(&core_ep, PARAM_EP, VERSION_1, SECURE | EP_ST_ENABLE |
            ((read_sctlr_el3() & SCTLR_EE_BIT) ? EP_EE_BIG : 0));

//#if CTX_INCLUDE_FPREGS
//        fpregs_context_save(get_fpregs_ctx(cm_get_context(NON_SECURE)));
//#endif

        cm_set_context(&ctx->cpu_ctx, SECURE);
        cm_init_my_context(&core_ep);

        cm_el1_sysregs_context_restore(SECURE);
#if CTX_INCLUDE_FPREGS
        fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
#endif
        cm_set_next_eret_context(SECURE);

        /* take Aborts and SErrors to EL3 */
        //uint64_t scr_el3 = read_ctx_reg(get_el3state_ctx(ctx), CTX_SCR_EL3);
        //scr_el3 |= SCR_EA_BIT;
        //write_ctx_reg(get_el3state_ctx(ctx), CTX_SCR_EL3, scr_el3);

        NOTICE("BL31: CertiKOS SCR=0x%lx\n", read_ctx_reg(get_el3state_ctx(ctx), CTX_SCR_EL3));
        NOTICE("BL31: CertiKOS PC=%p\n", (void*)core_ep.pc);


#if MULTICORE_ENABLE
        certikos_el3_world_switch_return(&ctx->saved_sp);
        NOTICE("BL31: Finished booting CertiKOS on core %u\n", plat_my_core_pos());
#else
        NOTICE("BL31: Skipped booting CertiKOS on core %u\n", plat_my_core_pos());
#endif
        //cm_el1_sysregs_context_restore(NON_SECURE);
        //fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
        //cm_set_next_eret_context(NON_SECURE);
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
    certikos_el3_cpu_ctx * ctx = get_cpu_ctx();

    //u_register_t scr_el3;

    (void)(ns_ctx);



    if(is_caller_secure(flags)) {
        switch(smc_fid) {
            case SMC_FC_FIQ_EXIT:
            case SMC_FC64_FIQ_EXIT:
                ns_ctx = cm_get_context(NON_SECURE);
                assert(ns_ctx);

                cm_el1_sysregs_context_save(SECURE);
                cm_el1_sysregs_context_restore(NON_SECURE);

#if CTX_INCLUDE_FPREGS
                fpregs_context_save(get_fpregs_ctx(cm_get_context(SECURE)));
                fpregs_context_restore(get_fpregs_ctx(ns_ctx));
#endif
                certkos_el3_swap_extra_regs(ctx);

                //scr_el3 = read_ctx_reg(
                //    get_el3state_ctx(cm_get_context(NON_SECURE)), CTX_SCR_EL3);
                //scr_el3 |= SCR_EA_BIT;
                //write_ctx_reg(
                //    get_el3state_ctx(cm_get_context(NON_SECURE)), CTX_SCR_EL3, scr_el3);


                cm_set_next_eret_context(NON_SECURE);
                //debug_putc_uartc('>');
                //putchar('>');
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


                /* restore execution in boot/on_handler */
                certikos_el3_world_switch_enter(ctx->saved_sp, 0);

                assert(0);
                break;

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
