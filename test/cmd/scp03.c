// SPDX-License-Identifier: GPL-2.0+
/*
 * Test for scp03 command
 *
 * Copyright 2020 Foundries.io
 *
 * Authors:
 *   Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <dm.h>
#include <dm/test.h>
#include <test/test.h>
#include <test/ut.h>

/* Basic test of 'scp03' command */
static int dm_test_scp03_cmd(struct unit_test_state *uts)
{
	ut_assertok(console_record_reset_enable());
	ut_assertok(run_command("scp03 enable", 0));
	ut_assert_console_end();

	ut_assertok(run_command("scp03 provision", 0));
	ut_assert_console_end();

	return 0;
}

DM_TEST(dm_test_scp03_cmd, UT_TESTF_CONSOLE_REC);
