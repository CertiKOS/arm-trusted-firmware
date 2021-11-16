#
# Copyright (c) 2016-2019, ARM Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

SPD_INCLUDES		:=

SPD_SOURCES		:=	services/spd/certikos/certikos.c \
					services/spd/certikos/helpers.S

#ifeq (${TRUSTY_SPD_WITH_GENERIC_SERVICES},1)
#SPD_SOURCES		+=	services/spd/trusty/generic-arm64-smcall.c
#endif

NEED_BL32		:=	yes

CTX_INCLUDE_FPREGS	:=	1
CTX_INCLUDE_AARCH32_REGS := 0
