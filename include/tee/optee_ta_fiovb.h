/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2018, Linaro Limited */
/* Copyright (c) 2019, Foundries.IO */

#ifndef __TA_FIOVB_H
#define __TA_FIOVB_H

#define TA_FIOVB_UUID {0x22250a54, 0x0bf1, 0x48fe, \
		      { 0x80, 0x02, 0x7b, 0x20, 0xf1, 0xc9, 0xc9, 0xb1 } }


#define TA_FIOVB_MAX_ROLLBACK_LOCATIONS	256

/*
 * Gets the rollback index corresponding to the given rollback index slot.
 *
 * in	params[0].value.a:	rollback index slot
 * out	params[1].value.a:	upper 32 bits of rollback index
 * out	params[1].value.b:	lower 32 bits of rollback index
 */
#define TA_FIOVB_CMD_READ_ROLLBACK_INDEX	0

/*
 * Updates the rollback index corresponding to the given rollback index slot.
 *
 * Will refuse to update a slot with a lower value.
 *
 * in	params[0].value.a:	rollback index slot
 * in	params[1].value.a:	upper 32 bits of rollback index
 * in	params[1].value.b:	lower 32 bits of rollback index
 */
#define TA_FIOVB_CMD_WRITE_ROLLBACK_INDEX	1

/*
 * Reads a persistent value corresponding to the given name.
 *
 * in	params[0].memref:	persistent value name
 * out	params[1].memref:	read persistent value buffer
 */
#define TA_FIOVB_CMD_READ_PERSIST_VALUE		2

/*
 * Writes a persistent value corresponding to the given name.
 *
 * in	params[0].memref:	persistent value name
 * in	params[1].memref:	persistent value buffer to write
 */
#define TA_FIOVB_CMD_WRITE_PERSIST_VALUE	3

#endif /*__TA_FIOVB_H*/
