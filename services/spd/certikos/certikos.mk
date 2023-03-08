#
# Copyright (c) 2016-2019, ARM Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

SPD_INCLUDES		:=

SPD_SOURCES		:=	services/spd/certikos/certikos.c \
					services/spd/certikos/helpers.S \
					services/spd/certikos/bl32.bin.S

.PHONY: services/spd/certikos/bl32.bin.S


#ifeq (${TRUSTY_SPD_WITH_GENERIC_SERVICES},1)
#SPD_SOURCES		+=	services/spd/trusty/generic-arm64-smcall.c
#endif

#NEED_BL32		:=	yes

CTX_INCLUDE_FPREGS	:=	1

ASFLAGS += -DCERTIKOS_KERNEL_BIN_PATH=\"${CERTIKOS_KERNEL_BIN_PATH}\"
CFLAGS += -DCERTIKOS_KERNEL_BIN_LINK_ADDR=${CERTIKOS_KERNEL_BIN_LINK_ADDR}
