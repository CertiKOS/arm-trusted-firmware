/*
 * Copyright (c) 2016-2017, ARM Limited and Contributors. All rights reserved.
 * Copyright (c) 2020, NVIDIA Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SMCALL_H
#define SMCALL_H

#define SMC_NUM_ENTITIES	64U
#define SMC_NUM_ARGS		4U
#define SMC_NUM_PARAMS		(SMC_NUM_ARGS - 1U)

#define SMC_IS_FASTCALL(smc_nr)	((smc_nr) & 0x80000000U)
#define SMC_IS_SMC64(smc_nr)	((smc_nr) & 0x40000000U)
#define SMC_ENTITY(smc_nr)	(((smc_nr) & 0x3F000000U) >> 24U)
#define SMC_FUNCTION(smc_nr)	((smc_nr) & 0x0000FFFFU)

#define SMC_NR(entity, fn, fastcall, smc64)			\
		(((((uint32_t)(fastcall)) & 0x1U) << 31U) |	\
		(((smc64) & 0x1U) << 30U) |			\
		(((entity) & 0x3FU) << 24U) |			\
		((fn) & 0xFFFFU))

#define SMC_FASTCALL_NR(entity, fn)	SMC_NR((entity), (fn), 1U, 0U)
#define SMC_FASTCALL64_NR(entity, fn)	SMC_NR((entity), (fn), 1U, 1U)
#define SMC_YIELDCALL_NR(entity, fn)	SMC_NR((entity), (fn), 0U, 0U)
#define SMC_YIELDCALL64_NR(entity, fn)	SMC_NR((entity), (fn), 0U, 1U)

#define	SMC_ENTITY_ARCH			0U	/* ARM Architecture calls */
#define	SMC_ENTITY_CPU			1U	/* CPU Service calls */
#define	SMC_ENTITY_SIP			2U	/* SIP Service calls */
#define	SMC_ENTITY_OEM			3U	/* OEM Service calls */
#define	SMC_ENTITY_STD			4U	/* Standard Service calls */
#define	SMC_ENTITY_RESERVED		5U	/* Reserved for future use */
#define	SMC_ENTITY_TRUSTED_APP		48U	/* Trusted Application calls */
#define	SMC_ENTITY_TRUSTED_OS		50U	/* Trusted OS calls */
#define SMC_ENTITY_LOGGING              51U	/* Used for secure -> nonsecure logging */
#define	SMC_ENTITY_SECURE_MONITOR	60U	/* Trusted OS calls internal to secure monitor */

/*
 * Return from secure os to non-secure os with return value in r1
 */

#define SMC_FC64_ENTRY_DONE SMC_FASTCALL64_NR (SMC_ENTITY_SECURE_MONITOR, 0U)
#define SMC_FC64_FIQ_EXIT   SMC_FASTCALL64_NR (SMC_ENTITY_SECURE_MONITOR, 1U)
#define SMC_FC64_SMC_EXIT   SMC_FASTCALL64_NR (SMC_ENTITY_SECURE_MONITOR, 2U)

#define SMC_FC_FIQ_EXIT     SMC_FASTCALL_NR   (SMC_ENTITY_SECURE_MONITOR, 1U)
#define SMC_FC_SMC_EXIT     SMC_FASTCALL_NR   (SMC_ENTITY_SECURE_MONITOR, 2U)


#endif /* SMCALL_H */
