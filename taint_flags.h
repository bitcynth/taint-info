/*
 *
 * This is a part of taint-info.
 * Copyright (C) 2018 Cynthia Revstrom <me@cynthia.re>
 * 
 * taint-info is licensed under the MIT License.
 * For a full license please refer to the LICENSE file in the root of the taint-info repository.
 *
 * The taint flag info in this file is from the Linux kernel documentation, available at: https://www.kernel.org/doc/Documentation/sysctl/kernel.txt
 *
 */

#ifndef __TAINT_INFO_FLAGS_H
#define __TAINT_INFO_FLAGS_H

#define TAINT_NON_GPL 1
#define TAINT_FORCE_LOAD 2
#define TAINT_UNSAFE_SMP 4
#define TAINT_FORCE_UNLOAD 8
#define TAINT_HW_CHECK_ERR 16
#define TAINT_BAD_PAGE 32
#define TAINT_MARK_TAINT 64
#define TAINT_SYSTEM_DIED 128
#define TAINT_ACPI_DSDT_OVERRIDE 256
#define TAINT_KERNEL_WARN 512
#define TAINT_MOD_STAGING 1024
#define TAINT_SYS_FW_BUG 2048
#define TAINT_OOT_MOD 4096
#define TAINT_UNSIGNED 8192
#define TAINT_SOFT_LOCKUP 16384
#define TAINT_LIVE_PATCHED 32768
#define TAINT_AUX 65536
#define TAINT_STRUCT_RANDOM 131072

#endif
