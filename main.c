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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "taint_flags.h"

void usage() {
	printf("taint-info - Kernel Taint Info\n");
	printf("Copyright (C) 2018 Cynthia Revstrom <me@cynthia.re>\n");
	printf("Usage:\n");
	printf("  -h: this help\n");
	printf("  -i <taint value>: show information based on \"taint\" value.\n");
	printf("  -p: show information based on this computer's taint value.\n");
}

void check_taint_flag(int taintval, int flag, char* flag_name, char* msg) {
	if(taintval & flag) {
		printf("%s: %s\n", flag_name, msg);
	}
}

void check_flags(int taintval) {
	if(taintval != 0) {
		printf("Kernel is tainted :(\n");
		printf("Taint value: %d\n", taintval);
		
		// Check for taint flags
		printf("Taint flags: \n");

		check_taint_flag(taintval, TAINT_NON_GPL, "NON_GPL", "Non-GPL module loaded");
		check_taint_flag(taintval, TAINT_FORCE_LOAD, "FORCE_LOAD", "Kernel module force loaded with insmod -f");
		check_taint_flag(taintval, TAINT_UNSAFE_SMP, "UNSAFE_SMP", "SMP with CPU not designed for SMP");
		check_taint_flag(taintval, TAINT_FORCE_UNLOAD, "FORCE_UNLOAD", "Kernel module force unloaded with rmmod -f");
		check_taint_flag(taintval, TAINT_HW_CHECK_ERR, "HW_CHECK_ERR", "Hardware check error");
		check_taint_flag(taintval, TAINT_BAD_PAGE, "BAD_PAGE", "A bad page was discovered on the system");
		check_taint_flag(taintval, TAINT_MARK_TAINT, "MARK_TAINT", "The user has marked the software as tainted");
		check_taint_flag(taintval, TAINT_SYSTEM_DIED, "SYSTEM_DIED", "The system has died");
		check_taint_flag(taintval, TAINT_ACPI_DSDT_OVERRIDE, "ACPI_DSDT_OVERRIDE", "The ACPI DSDT has been overridden");
		check_taint_flag(taintval, TAINT_KERNEL_WARN, "KERNEL_WARN", "A kernel warning has occured");
		check_taint_flag(taintval, TAINT_MOD_STAGING, "MOD_STAGING", "A module from drivers/staging was loaded");
		check_taint_flag(taintval, TAINT_SYS_FW_BUG, "SYS_FW_BUG", "The system is working around a severe firmware bug");
		check_taint_flag(taintval, TAINT_OOT_MOD, "OOT_MOD", "An out-of-tree-module has been loaded");
		check_taint_flag(taintval, TAINT_UNSIGNED, "UNSIGNED", "An unsigned module has been loaded into a kernel supporting module signatures");
		check_taint_flag(taintval, TAINT_SOFT_LOCKUP, "SOFT_LOCKUP", "A soft lockup has previously  occured on the system");
		check_taint_flag(taintval, TAINT_LIVE_PATCHED, "LIVE_PATCHED", "The kernel has been live patched");
		check_taint_flag(taintval, TAINT_AUX, "AUX", "Auxiliary taint, defined and used by distros");
		check_taint_flag(taintval, TAINT_STRUCT_RANDOM, "STRUCT_RANDOM", "The kernel was built with the struct randomization plugin");
	} else {
		printf("Kernel is not tainted :)\n");
	}
}

void check_proc() {
	char buf[2048];
	FILE* fh;
	size_t size;

	// Read /proc/sys/kernel/tainted
	fh = fopen("/proc/sys/kernel/tainted", "r");
	if (fh == NULL) {
		printf("No kernel taint file found :(\n");
		exit(EXIT_FAILURE);
	}
	size = fread(&buf, 1, sizeof(buf), fh);
	fclose(fh);

	buf[size] = '\0';

	// Parse the string from tainted to an int
	char* end;
	long l = strtol(buf, &end, 10);
	int taintval = (int) l;


	// Check the taint
	check_flags(taintval);
}

void check_flags_cli(char* flagstr) {
	// Parse the string to an int
	char* end;
	long l = strtol(flagstr, &end, 10);
	int taintval = (int) l;


	// Check the taint
	check_flags(taintval);
}

int main(int argc, char** argv) {
	char* flag_input;
	int opt;
	enum { INTEGER_FLAG_MODE, PROC_MODE, HELP_MODE } mode = HELP_MODE;

	while ((opt = getopt(argc, argv, "i:hp")) != -1) {
		switch(opt) {
			case 'i':
				mode = INTEGER_FLAG_MODE;
				flag_input = optarg;
				break;
			case 'h':
				mode = HELP_MODE;
				break;
			case 'p':
				mode = PROC_MODE;
				break;
			default:
				usage();
				exit(EXIT_FAILURE);
		}
	}

	if (mode == INTEGER_FLAG_MODE) {
		check_flags_cli(flag_input);
	} else if (mode == PROC_MODE) {
		check_proc();
	} else if (mode == HELP_MODE) {
		usage();
	}

	return 0;
}
