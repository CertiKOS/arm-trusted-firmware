#ifdef CERTIKOS_KERNEL_BIN_PATH
		.global certikos_kernel_start
		.align	12
certikos_kernel_start:
        .incbin CERTIKOS_KERNEL_BIN_PATH

        .global certikos_kernel__end
		.align 4
certikos_kernel_end:
        .byte 0

        .global certikos_kernel_size
		.align 4
certikos_kernel_size:
        .int certikos_kernel_end - certikos_kernel_start
#endif
