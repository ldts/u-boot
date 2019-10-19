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

DECLARE_GLOBAL_DATA_PTR;


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

/* TODO: optee smc calls */
static int optee_get_hash(uint8_t *tee_hash, int *tee_hash_len)
{
	return -EINVAL;
}

static void optee_update_hash(uint8_t *fit_hash, int fit_len)
{

}

static int m4_do_upgrade(char *data, size_t size,
			  uint8_t *fit_hash_value, int fit_hash_len)

{
	struct spi_flash *flash;
	u32 tag;

	/* We assume the M4 image has IVT head and padding which
	 * should be same as the one programmed into QSPI flash
	 */
	if (size < 0x4096) {
		printf("M4 Image size too small (%d)!\n", size);
		return -EINVAL;
	}

	printf("M4 Image Size %d\n", size);

	/* check firmware tags */
	tag = *(u32 *)(data + 4096);
	if (tag != 0x402000d1 && tag !=0x412000d1) {
		printf("Invalid M4 image: tag=0x%x\n", tag);
		return -EINVAL;
	}

	flash = spi_flash_probe(CONFIG_ENV_SPI_BUS, CONFIG_ENV_SPI_CS,
				CONFIG_ENV_SPI_MAX_HZ, CONFIG_ENV_SPI_MODE);
	if (!flash) {
		printf("Failed to probe spi_flash\n");
		return -EINVAL;
	}

	if (spi_flash_erase(flash, 0, 20000))
		printf("Failed to erase spi flash\n");

	if (spi_flash_write(flash, 0, size, data)) {
		printf("Failed to write image to spi flash\n");
		return -EIO;
	}

	printf("M4 Firmware Upgraded\n");
	optee_update_hash(fit_hash_value, fit_hash_len);

	/* TODO: release the flash too boot at this point */

	return 0;
}


static int m4_upgrade_required(uint8_t *fit_hash, int fit_len)
{
	uint8_t tee_hash[FIT_MAX_HASH_LEN];
	int tee_hash_len = -1;

	if (optee_get_hash(tee_hash, &tee_hash_len))
		return false;

	if (tee_hash_len != fit_len || memcmp(tee_hash, fit_hash, fit_len))
		return true;

	return false;
}


static int process_m4_hash(const void *fit, const int image_noffset)
{
	uint8_t *fit_value;
	int fit_value_len;
	const void *data;
	int noffset = 0;
	size_t size;
	int i;

	fdt_for_each_subnode(noffset, fit, image_noffset) {
		const char *name = fit_get_name(fit, noffset, NULL);
		if (!strncmp(name, FIT_HASH_NODENAME,
			     strlen(FIT_HASH_NODENAME)))
			goto process_m4_hash;
	}

	return -EINVAL;

process_m4_hash:

	if (fit_image_hash_get_value(fit, noffset, &fit_value, &fit_value_len)) {
		printf("Can't get hash value property");
		return -EINVAL;
	}

	printf("M4 Hash: ");
	for (i = 0; i < fit_value_len; i++)
		printf("%x", fit_value[i]);
	printf("\n");

	if (m4_upgrade_required(fit_value, fit_value_len) == false) {
		printf("M4 upgrade not required\n");
		return 0;
	}

	if (fit_image_get_data_and_size(fit, image_noffset, &data, &size)) {
		printf("Can't get M4 image data and size\n");
		return -EINVAL;
	}

	return m4_do_upgrade((char *) data, size, fit_value, fit_value_len);
}

static int process_m4_node(const void *fit)
{
	int images_noffset;
	const char *name;
	int noffset;
	int ndepth;
	int count;

	images_noffset = fdt_path_offset(fit, FIT_IMAGES_PATH);
	if (images_noffset < 0) {
		printf("Can't find images parent node '%s' (%s)\n",
		       FIT_IMAGES_PATH, fdt_strerror(images_noffset));
		return 0;
	}

	for (ndepth = 0, count = 0,
	     noffset = fdt_next_node(fit, images_noffset, &ndepth);
			(noffset >= 0) && (ndepth > 0);
			noffset = fdt_next_node(fit, noffset, &ndepth)) {

		if (ndepth == 1) {
			name = fit_get_name(fit, noffset, NULL);
			if (!strncmp(name, "m4", 2)) {
				printf("## Checking hash for M4 Upgrade...\n");
				return process_m4_hash(fit, noffset);
			}
 			count++;
		}
	}

	return -EINVAL;
}

/* TODO: how to select the vmlinuz from ostree */
static void process_m4_upgrade(void)
{
	void *hdr = (void *) CONFIG_SYS_LOAD_ADDR;
	char buffer[12];
	char *const cmd[] = {
		"ext4load",
		"mmc",
		"0:2",
		buffer,
		"boot/ostree/lmp-5bb9917534ead07e2db1754c4c95f5a195e6e96177455214bedd1241b134b274/vmlinuz",
	};

	snprintf(buffer, 12, "0x%x", CONFIG_SYS_LOAD_ADDR);

	if (do_load(NULL, 0, 5, cmd, FS_TYPE_EXT)) {
		printf("Failed to load image\n");
		return;
	}

	if (genimg_get_format(hdr) != IMAGE_FORMAT_FIT) {
		printf("Invalid image format\n");
		return;
	}

	if (!fit_check_format(hdr)) {
		printf("bad FIT image format\n");
		return;
	}

	if (process_m4_node(hdr))
		puts("Bad hash in FIT image!\n");
}


int board_init(void)
{
	/* address of boot parameters */
	gd->bd->bi_boot_params = PHYS_SDRAM + 0x100;

#ifdef CONFIG_FSL_QSPI
	board_qspi_init();
#endif
	process_m4_upgrade();

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
