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

#define M4_BASE			(TCML_BASE)
#define M4_SIZE			(SZ_128K + SZ_64K)
#define M4_ENTRY_OFFSET		0x1004
#define M4_WATERMARK_OFFSET	0x1000
#define M4_WATERMARK(fw)						\
	({								\
		char *__p = (char *) (fw);				\
		u32 __watermark = *(u32 *) (__p + M4_WATERMARK_OFFSET);	\
		__watermark;						\
	})

#define M4_ENTRY(fw)							\
	({								\
		char *__p = (char *) (fw);				\
		u32 __entry = *(u32 *) (__p + M4_ENTRY_OFFSET);		\
		__entry;						\
	})

#define M4_FW_VALID(x) (((x) == 0x402000d1) || ((x) == 0x412000d1))

DECLARE_GLOBAL_DATA_PTR;

extern enum bt_mode get_boot_mode(void);

#define UART_PAD_CTRL	(PAD_CTL_PUS_UP)
#define QSPI_PAD_CTRL1	(PAD_CTL_PUS_UP | PAD_CTL_DSE)
#define OTG_ID_GPIO_PAD_CTRL	(PAD_CTL_IBE_ENABLE)

struct hash {
	uint8_t *value;
	int len;
};

/* the TEE needs to store the payload length so we can recalculate the sha
 * before booting from flash
 */
struct tee_hash {
	struct hash hash;
	int payload_len;
};

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

/* stub until optee ready */
static struct tee_hash t_hash;

static int optee_get_tee_hash(uint8_t *tee_hash, int *tee_hash_len, int *payload_len)
{
	if (t_hash.hash.len) {
		memcpy(tee_hash, t_hash.hash.value, t_hash.hash.len);
		*tee_hash_len = t_hash.hash.len;
		if (payload_len)
			*payload_len = t_hash.payload_len;
	}

	return 0;
}

static void optee_update_tee_hash(struct hash *hash, int payload_len)
{
	int i;

	/* stub code */
	if (t_hash.hash.len) {
		printf("M4: optee hash already updated, update rejected");
		return;
	}

	t_hash.hash.len = hash->len;
	t_hash.payload_len = payload_len;
	memcpy(t_hash.hash.value, hash->value, t_hash.hash.len);

	printf("M4: optee hash update:\n");
	printf("\t value => ");
	for (i = 0; i < t_hash.hash.len; i++)
		printf("%x", t_hash.hash.value[i]);
	printf("\n");
	printf("\t payload : 0x%x\n", t_hash.payload_len);
	printf("\t len     : 0x%x\n", t_hash.hash.len);
}

static int m4_do_upgrade(struct spi_flash *flash,
			 char *data, const size_t size, struct hash *fit_hash)
{
	struct mtd_info *mtd = 	&flash->mtd;
	size_t len;

	/* We assume the M4 image has IVT head and padding which
	 * should be same as the one programmed into QSPI flash
	 */
	if (size < 0x1000) {
		printf("M4: Image size too small (%d)!\n", size);
		return -EINVAL;
	} else
		printf("M4: Fit Image Size %d\n", size);

	/* check FIT firmware tags */
	if (!M4_FW_VALID(M4_WATERMARK(data))) {
		printf("M4: Invalid image: tag=0x%x\n", M4_WATERMARK(data));
		return -EINVAL;
	}

	len = round_down(M4_SIZE, mtd->erasesize);
	if (spi_flash_erase(flash, 0, len))
		printf("M4: Failed to erase spi flash\n");

	len = round_up(size, mtd->writesize);
	if (spi_flash_write(flash, 0, len, data)) {
		printf("M4: Failed to write image to spi flash\n");
		return -EIO;
	}

	optee_update_tee_hash(fit_hash, size);
	printf("M4: Firmware upgraded from FIT\n");

	return 0;
}

static int m4_upgrade_required(struct hash *fit_hash)
{
	uint8_t tee_hash[FIT_MAX_HASH_LEN];
	int tee_hash_len = -1;

	if (optee_get_tee_hash(tee_hash, &tee_hash_len, NULL))
		return false;

	if (tee_hash_len != fit_hash->len ||
	    memcmp(tee_hash, fit_hash->value, tee_hash_len))
		return true;

	return false;
}

static int m4_check_hash(const void *fit, const int image_noffset,
			 struct hash *fit_hash)
{
	int noffset = 0;
	int i;

	fdt_for_each_subnode(noffset, fit, image_noffset) {
		const char *name = fit_get_name(fit, noffset, NULL);
		if (!strncmp(name, FIT_HASH_NODENAME,
			     strlen(FIT_HASH_NODENAME)))
			goto process_m4_hash;
	}

	printf("M4: Can't get hash node\n");
	return -EINVAL;

process_m4_hash:

	if (fit_image_hash_get_value(fit, noffset,
				     &fit_hash->value, &fit_hash->len)) {
		printf("M4: Can't get hash value property\n");
		return -EINVAL;
	}

	printf("M4: FIT hash => ");
	for (i = 0; i < fit_hash->len; i++)
		printf("%x", fit_hash->value[i]);
	printf("\n");

	if (m4_upgrade_required(fit_hash) == false) {
		printf("M4: upgrade not required\n");
		return 0;
	}

	return 1;
}

static int m4_get_fit_node(const void *fit)
{
	int images_noffset;
	const char *name;
	int noffset;
	int ndepth;
	int count;

	images_noffset = fdt_path_offset(fit, FIT_IMAGES_PATH);
	if (images_noffset < 0) {
		printf("M4: Can't find images parent node '%s' (%s)\n",
		       FIT_IMAGES_PATH, fdt_strerror(images_noffset));
		return -EINVAL;
	}

	for (ndepth = 0, count = 0,
	     noffset = fdt_next_node(fit, images_noffset, &ndepth);
			(noffset >= 0) && (ndepth > 0);
			noffset = fdt_next_node(fit, noffset, &ndepth)) {

		if (ndepth == 1) {
			name = fit_get_name(fit, noffset, NULL);
			if (!strncmp(name, "m4", 2))
				return noffset;
 			count++;
		}
	}

	printf("M4: Can't find the FPGA M4 node\n");

	return -EINVAL;
}

static void m4_boot(struct spi_flash *flash)
{
	int hash_len = 0, tee_hash_len = 0, tee_payload_len = 0;
	uint8_t tee_hash[FIT_MAX_HASH_LEN];
	uint8_t hash[FIT_MAX_HASH_LEN];

	if (spi_flash_read(flash, 0, M4_SIZE, (void *) M4_BASE)) {
		printf("M4: Failed to read from flash, can't boot\n");
		return;
	}

	printf("\tM4 Entry: 0x%x\n", M4_ENTRY(M4_BASE));
	printf("\tM4 Sram : 0x%x\n", M4_BASE);
	printf("\tM4 Size : 0x%x\n", M4_SIZE);

	if (optee_get_tee_hash(tee_hash, &tee_hash_len, &tee_payload_len)) {
		printf("M4: cant boot, TEE not accessible\n");
		return;
	}

	/* do not boot if the FPGA is corrupted (ie, sha different than TEE's) */
	if (calculate_hash((const void *) M4_BASE, tee_payload_len, "sha256",
			   hash, &hash_len)) {
		printf("M4: cant boot, unsupported hash algorithm\n");
		return;
	}

	if (hash_len != tee_hash_len) {
		printf("M4: cant boot, invalid hash length\n");
		return;
	} else if (memcmp(hash, tee_hash, tee_hash_len)) {
		printf("M4: cant boot, invalid hash values\n");
		return;
	} else
		printf("   M4 Firmware SHA validated, booting\n");

	writel(M4_ENTRY(M4_BASE), SIM0_RBASE + 0x70);
}

int fpga_loadbitstream(int devnum, char *fpgadata, size_t size,
		       bitstream_type bstype)
{
	struct spi_flash *flash;
	struct hash fit_hash;
	int noffset, ret;

	if (get_boot_mode() == DUAL_BOOT) {
		/* in DUAL mode, the M4 should be already running */
		printf("M4: Cant upgrade or boot M4 in dual boot mode\n");
		return 0;
	}

	flash = spi_flash_probe(CONFIG_ENV_SPI_BUS, CONFIG_ENV_SPI_CS,
			 CONFIG_ENV_SPI_MAX_HZ, CONFIG_ENV_SPI_MODE);
	if (!flash) {
		printf("M4: Failed to probe spi_flash, cant boot or upgrade M4\n");
		return -EINVAL;
	}

	/* get the M4 node in the FIT image */
	noffset = m4_get_fit_node((void *) env_get_ulong("initrd_addr", 16, 0UL));
	if (noffset < 0) {
		printf("M4: invalid FIT image, booting M4 from flash\n");
		goto boot;
	}

	/* compare sha against the value stored in the TEE to determine
	 * whether a firmware upgrade is needed
	 */
	ret = m4_check_hash((void *) env_get_ulong("initrd_addr", 16, 0UL),
			    noffset, &fit_hash);
	if (ret <= 0)
		goto boot;

	/* perform a firmware upgrade (an update the TEE) */
	ret = m4_do_upgrade(flash, fpgadata, size, &fit_hash);
	if (ret)
		printf("M4: upgrade failed\n");
boot:
	/* boot the M4 stored in QSPI (validate sha+ against TEE) */
	m4_boot(flash);
	return 0;
}

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
