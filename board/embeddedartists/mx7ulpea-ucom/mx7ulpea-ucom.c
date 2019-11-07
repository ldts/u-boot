/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright (C) 2019 Foundries.IO
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <fdt_support.h>
#include <asm/io.h>
#include <asm/arch/sys_proto.h>
#include <asm/arch/mx7ulp-pins.h>
#include <asm/arch/iomux.h>
#include <asm/mach-imx/boot_mode.h>
#include <asm/gpio.h>
#include <fs.h>
#include <usb.h>
#include <dm.h>
#include <spi_flash.h>
#include <fpga.h>
#include <mtd.h>
#include <stdlib.h>

DECLARE_GLOBAL_DATA_PTR;

extern enum bt_mode get_boot_mode(void);

enum m4_fw_state {m4_fw_boot, m4_fw_abort, m4_fw_upgrade};

struct hash {
	uint8_t value[FIT_MAX_HASH_LEN];
	int len;
};

#define UART_PAD_CTRL	(PAD_CTL_PUS_UP)
#define QSPI_PAD_CTRL1	(PAD_CTL_PUS_UP | PAD_CTL_DSE)
#define OTG_ID_GPIO_PAD_CTRL	(PAD_CTL_IBE_ENABLE)

int dram_init(void)
{
	gd->ram_size = PHYS_SDRAM_SIZE;

	/* Subtract the defined OPTEE runtime firmware length */
#ifdef CONFIG_OPTEE_TZDRAM_SIZE
	gd->ram_size -= CONFIG_OPTEE_TZDRAM_SIZE;
#endif

	return 0;
}

static iomux_cfg_t const lpuart4_pads[] = {
	MX7ULP_PAD_PTC3__LPUART4_RX | MUX_PAD_CTRL(UART_PAD_CTRL),
	MX7ULP_PAD_PTC2__LPUART4_TX | MUX_PAD_CTRL(UART_PAD_CTRL),
};

static void setup_iomux_uart(void)
{
	mx7ulp_iomux_setup_multiple_pads(lpuart4_pads,
					 ARRAY_SIZE(lpuart4_pads));
}

#ifdef CONFIG_FSL_QSPI
#ifndef CONFIG_DM_SPI
static iomux_cfg_t const qspi_pads[] = {
	MX7ULP_PAD_PTB8__QSPIA_SS0_B | MUX_PAD_CTRL(QSPI_PAD_CTRL1),
	MX7ULP_PAD_PTB15__QSPIA_SCLK  | MUX_PAD_CTRL(QSPI_PAD_CTRL1),
	MX7ULP_PAD_PTB16__QSPIA_DATA3 | MUX_PAD_CTRL(QSPI_PAD_CTRL1),
	MX7ULP_PAD_PTB17__QSPIA_DATA2 | MUX_PAD_CTRL(QSPI_PAD_CTRL1),
	MX7ULP_PAD_PTB18__QSPIA_DATA1 | MUX_PAD_CTRL(QSPI_PAD_CTRL1),
	MX7ULP_PAD_PTB19__QSPIA_DATA0 | MUX_PAD_CTRL(QSPI_PAD_CTRL1),
};
#endif

int board_qspi_init(void)
{
	u32 val;

#ifndef CONFIG_DM_SPI
	mx7ulp_iomux_setup_multiple_pads(qspi_pads, ARRAY_SIZE(qspi_pads));
#endif

	/* enable clock */
	val = readl(PCC1_RBASE + 0x94);

	if (!(val & 0x20000000)) {
		writel(0x03000003, (PCC1_RBASE + 0x94));
		writel(0x43000003, (PCC1_RBASE + 0x94));
	}

	/* Enable QSPI as a wakeup source on B0 */
	if (soc_rev() >= CHIP_REV_2_0)
		setbits_le32(SIM0_RBASE + WKPU_WAKEUP_EN, WKPU_QSPI_CHANNEL);
	return 0;
}
#endif

int board_early_init_f(void)
{
	setup_iomux_uart();

	return 0;
}

#ifdef M4_HASH_DEBUG
void print_hash(char *msg, struct hash *hash)
{
	printf("%s\n", msg);
	printf("\t hash       => ");
	for (i = 0; i < hash->len; i++)
		printf("%02x ", hash->value[i]);
	printf("\n");
	printf("\t hash_len    : 0x%x\n", hash->len);

}

#else
void print_hash(char *msg, struct hash *hash){}
#endif

#if defined(CONFIG_FPGA)
static int m4_do_upgrade(struct spi_flash *flash, const void *data,
			 const size_t size, struct hash *hash)
{
	struct mtd_info *mtd = &flash->mtd;
	size_t len;

	len = round_down(M4_SIZE, mtd->erasesize);
	if (spi_flash_erase(flash, 0, len)) {
		printf("M4: Failed to erase flash\n");
		return -EIO;
	}

	len = round_up(size, mtd->writesize);
	if (spi_flash_write(flash, 0, len, data)) {
		printf("M4: Failed to write image to flash\n");
		return -EIO;
	}

	printf("M4: Firmware upgraded from FIT...\n");

	return 0;
}

static int m4_get_state(struct spi_flash **flash, const void *data, size_t size,
		        struct hash *hash, enum m4_fw_state *action)
{

	struct hash installed_hash;
	struct mtd_info *mtd;
	size_t len;

	/* assume validation error */
	*action = m4_fw_abort;

	/* 1) validate QSPI */
	*flash = spi_flash_probe(CONFIG_ENV_SPI_BUS, CONFIG_ENV_SPI_CS,
				 CONFIG_ENV_SPI_MAX_HZ, CONFIG_ENV_SPI_MODE);
	if (!*flash) {
		printf("M4: Failed to probe QSPI\n");
		return -EIO;
	}

	mtd = &(*flash)->mtd;

	/* 2) validate size */
	if (size < 0x2000) {
		printf("M4: Image size too small (%d < 0x2000)!\n", size);
		return -EINVAL;
	}

	/* 3) check firmware for valid tags: assume the M4 image has IVT head
	 * and padding which should be the same as the one programmed into
	 * QSPI flash
	 */
	if (!M4_FW_VALID(M4_WATERMARK(data))) {
		printf("M4: Invalid image: tag=0x%x\n", M4_WATERMARK(data));
		return -EINVAL;
	}

	/* 4) validate FIT hash against currently installed fw hash */
	if (calculate_hash(data, size, "sha256",
			   hash->value, &hash->len)) {
		printf("M4: unsupported hash algorithm to decode bistream\n");
		return -EINVAL;
	}

	len = round_up(size, mtd->writesize);
	if (spi_flash_read(*flash, 0, len, (void *) M4_BASE)) {
		printf("M4: Failed to read from flash, can't boot\n");
		return -EIO;
	}

	if (calculate_hash((void *) M4_BASE, size, "sha256",
			   installed_hash.value, &installed_hash.len)) {
		printf("M4: unsupported hash algorithm to decode bistream\n");
		return -EINVAL;
	}

	if (installed_hash.len != hash->len ||
	    memcmp(installed_hash.value, hash->value, hash->len)) {
		/* current firmware differs from requested firmware, upgrade */
		if (get_boot_mode() == DUAL_BOOT) {
			printf("M4: Invalid Boot Mode\n");
			return -EINVAL;
		}
		print_hash("Current FW Hash", &installed_hash);
		print_hash("New FIT FW Hash", hash);
		*action = m4_fw_upgrade;
	} else {
		/* current firmware matches requested firmware, boot it */
		*action = m4_fw_boot;
	}

	return 0;
}

static int m4_boot(struct spi_flash *flash, size_t size, struct hash *p)
{
	struct mtd_info *mtd = &flash->mtd;
	int ret = 0;
	size_t len;

	/* check if the M4 is already running */
	if (get_boot_mode() == DUAL_BOOT) {
		printf("M4: already running, continue\n");
		return 0;
	}

	len = round_up(size, mtd->writesize);
	if (spi_flash_read(flash, 0, len, (void *) M4_BASE)) {
		printf("M4: Failed to read from flash, can't boot\n");
		ret = -EIO;
		goto error;
	}

	debug("\tM4 Entry: 0x%x\n", M4_ENTRY(M4_BASE));
	debug("\tM4 Sram : 0x%x\n", M4_BASE);
	debug("\tM4 Size : 0x%x\n", size);

	printf("M4 Firmware hash validated, booting\n");
	writel(M4_ENTRY(M4_BASE), SIM0_RBASE + 0x70);

	return 0;
error:
	printf("M4: boot failed (%d), erasing flash\n", ret);
	/* clear the data in SRAM and flash when we cant boot it */
	memset((void *) M4_BASE, 0x00, M4_SIZE);
	spi_flash_erase(flash, 0, M4_SIZE);

	return ret;
}

/* As part of the boot sequence, SPL checks all images in the FIT; we chose
 * to register the M4 firmware as an FPGA image to benefit from this loading
 * process: ie, before booting the kernel, fpga_loadbistream will get executed
 * allowing the M4 firmware to be loaded and run.
 * If upgrade fails due to hardware or security problems, do not boot a previous
 * firmware already resident in QSPI.
 */
int fpga_loadbitstream(int d, char *bitstream, size_t size, bitstream_type t)
{
	const void *data = (const void *) bitstream;
	struct spi_flash *flash = NULL;
	enum m4_fw_state action;
	struct hash hash;
	int ret;

	ret = m4_get_state(&flash, data, size, &hash, &action);
	switch (action) {
	case m4_fw_abort:
		printf("M4: cant boot or upgrade the M4, rollback\n");
		return ret;
	case m4_fw_boot:
		printf("M4: already installed, booting\n");
		break;
	case m4_fw_upgrade:
		printf("M4: starting upgrade\n");
		ret = m4_do_upgrade(flash, data, size, &hash);
		if (ret) {
			printf("M4: upgrade failed, rollback\n");
			return ret;
		}
		break;
	}

	/* boot the M4 stored in QSPI */
	ret = m4_boot(flash, size, &hash);

	return ret;
}
#endif

int board_init(void)
{
	/* address of boot parameters */
	gd->bd->bi_boot_params = PHYS_SDRAM + 0x100;

#ifdef CONFIG_FSL_QSPI
	board_qspi_init();
#endif
	return 0;
}

#if IS_ENABLED(CONFIG_OF_BOARD_SETUP)
int ft_board_setup(void *blob, bd_t *bd)
{
	const char *path;
	int rc, nodeoff;

	if (get_boot_device() == USB_BOOT) {
		path = fdt_get_alias(blob, "mmc0");
		if (!path) {
			puts("Not found mmc0\n");
			return 0;
		}

		nodeoff = fdt_path_offset(blob, path);
		if (nodeoff < 0)
			return 0;

		printf("Found usdhc0 node\n");
		if (fdt_get_property(blob, nodeoff, "vqmmc-supply",
		    NULL) != NULL) {
			rc = fdt_delprop(blob, nodeoff, "vqmmc-supply");
			if (!rc) {
				puts("Removed vqmmc-supply property\n");
add:
				rc = fdt_setprop(blob, nodeoff,
						 "no-1-8-v", NULL, 0);
				if (rc == -FDT_ERR_NOSPACE) {
					rc = fdt_increase_size(blob, 32);
					if (!rc)
						goto add;
				} else if (rc) {
					printf("Failed to add no-1-8-v property, %d\n", rc);
				} else {
					puts("Added no-1-8-v property\n");
				}
			} else {
				printf("Failed to remove vqmmc-supply property, %d\n", rc);
			}
		}
	}

	return 0;
}
#endif

#ifdef CONFIG_SPL_BUILD
#include <spl.h>

#ifdef CONFIG_SPL_LOAD_FIT
int board_fit_config_name_match(const char *name)
{
	if (!strcmp(name, "imx7ulpea-ucom-kit_v2"))
		return 0;

	return -1;
}
#endif

void spl_board_init(void)
{
	preloader_console_init();
}

void board_init_f(ulong dummy)
{
	arch_cpu_init();

	board_early_init_f();
}
#endif
