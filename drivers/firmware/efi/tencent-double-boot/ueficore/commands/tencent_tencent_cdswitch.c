#include <grub/dl.h>
#include <grub/misc.h>
#include <grub/extcmd.h>
#include <grub/device.h>
#include <grub/i18n.h>
#include <grub/types.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/fs.h>
#include <grub/env.h>
#include <grub/file.h>
#include <grub/normal.h>
#include <grub/lib/envblk.h>
#include <grub/crypto.h>
#include <grub/partition.h>

#include "bootswitch.h"

static void
grub_info_lecrc32 (grub_uint32_t *crc, const void *data, grub_size_t len)
{
    grub_uint32_t val;

    grub_crypto_hash (GRUB_MD_CRC32, &val, data, len);
    *crc = grub_swap_bytes32 (val);
}

static grub_err_t
grub_get_info_offset (const char *disk_name, grub_uint64_t *offset)
{
    grub_device_t dev;

    dev = grub_device_open (disk_name);
    if (!dev) {
        grub_error (GRUB_ERR_BAD_DEVICE, N_("Open %s device failed"), disk_name);
        goto done;
    }

    /* it must be msdos partition */
    if (grub_memcmp(dev->disk->partition->partmap->name, "msdos", 5) != 0) {
        grub_device_close (dev);
        grub_errno = GRUB_ERR_BAD_DEVICE;
        grub_error (GRUB_ERR_BAD_DEVICE, N_("Can't support %s as boot partition"),
                    dev->disk->partition->partmap->name);
        goto done;
    }

    /* the boot info  offset */
    grub_errno = GRUB_ERR_NONE;
    *offset = dev->disk->partition->start + dev->disk->partition->len;
    grub_device_close (dev);

done:
    return grub_errno;
}

static int
grub_find_the_best (grub_info_t *info)
{
    grub_uint32_t crc;
    grub_uint16_t flag;
    grub_uint32_t crc_a, crc_b;
    grub_uint32_t magic_a, magic_b;
    grub_uint32_t order_a, order_b;
    int high_order_idx, low_order_idx;

    /* get magic */
    magic_a = grub_le_to_cpu32(info[BOOTA].magic);
    magic_b = grub_le_to_cpu32(info[BOOTB].magic);

    /* get order */
    order_a = grub_le_to_cpu32(info[BOOTA].order);
    order_b = grub_le_to_cpu32(info[BOOTB].order);

    /* calculate the crc32 value of boota */
    crc = grub_le_to_cpu32(info[BOOTA].csum);
    info[BOOTA].csum = 0;
    grub_info_lecrc32 (&crc_a, &info[BOOTA], sizeof (grub_info_t));
    info[BOOTA].csum = crc;

    /* calculate the crc32 value of bootb */
    crc = grub_le_to_cpu32(info[BOOTB].csum);
    info[BOOTB].csum = 0;
    grub_info_lecrc32 (&crc_b, &info[BOOTB], sizeof (grub_info_t));
    info[BOOTB].csum = crc;

    /* bootb is invalid, start boota directly without checking */
    if (BOOT_MAGIC != magic_b || crc_b != info[BOOTB].csum) {
        return BOOTA;
    }

    /* boota is invalid, start bootb directly without checking */
    if (BOOT_MAGIC != magic_a || crc_a != info[BOOTA].csum) {
        return BOOTB;
    }

    /* differentiate high and low order */
    if ( SEQ_AFTER_EQ (order_a, order_b)) {
        high_order_idx = BOOTA;
        low_order_idx = BOOTB;
    } else {
        high_order_idx = BOOTB;
        low_order_idx = BOOTA;
    }

    /* if "high order" boot fails, use "low order" for boot this time  */
    flag = grub_le_to_cpu16(info[high_order_idx].flag);
    if (flag == BOOT_FAILED) {
        return low_order_idx;
    }

    /* 'BOOT_FIRST' and 'BOOT_SUCCESS' use "high order" to boot */
    return high_order_idx;
}

static grub_err_t
grub_tsenv_setup (const char *root, char **root_env, char **prefix_env, char **rootfs_env)
{
    int flag;
    char *name[2];
    int boot_idx = 0;
    grub_uint32_t crc;
    grub_device_t dev;
    grub_info_t info[2];
    grub_uint64_t offset[2];
    int info_size = sizeof (grub_info_t);

    /* open root disk. */
    dev = grub_device_open (root);
    if (!dev) {
        return grub_errno;
    }

    /* read the grub_info_t offset in boota */
    name[BOOTA] = grub_xasprintf ("%s,%s", root, BOOTA_NAME);
    if (grub_get_info_offset (name[BOOTA], &offset[BOOTA])) {
        goto free_boota;
    }

    /* read boota info */
    if (grub_disk_read (dev->disk, offset[BOOTA], 0, info_size,
                        &info[BOOTA])) {
        goto free_boota;
    }

    /* read the grub_info_t offset in bootb */
    name[BOOTB] = grub_xasprintf ("%s,%s", root, BOOTB_NAME);
    if (grub_get_info_offset (name[BOOTB], &offset[BOOTB])) {
        goto free_bootb;
    }

    /* read bootb info */
    if (grub_disk_read (dev->disk, offset[BOOTB], 0, info_size,
                        &info[BOOTB])) {
        goto free_bootb;
    }

    /* find the partition best for startup */
    boot_idx = grub_find_the_best (info);

    /* if it is the first time to start, set it to fail before starting */
    flag = grub_le_to_cpu16 (info[boot_idx].flag);
    if (flag == BOOT_FIRST) {
        info[boot_idx].flag = grub_cpu_to_le16 (BOOT_FAILED);

        info[boot_idx].csum = 0;
        grub_info_lecrc32 (&crc, &info[boot_idx], info_size);
        info[boot_idx].csum = grub_cpu_to_le32(crc);

        if (grub_disk_write (dev->disk, offset[boot_idx], 0, info_size,
                             &info[boot_idx])) {
            goto free_bootb;
        }
    }

    if (boot_idx == BOOTA) {
        *rootfs_env = BOOTA_ROOT;
    } else {
        *rootfs_env = BOOTB_ROOT;
    }
    grub_errno = GRUB_ERR_NONE;
    *root_env = grub_xasprintf ("%s", name[boot_idx]);
    *prefix_env = grub_xasprintf ("(%s)/boot/grub2", name[boot_idx]);

free_bootb:
    grub_free (name[BOOTB]);
free_boota:
    grub_free (name[BOOTA]);
    grub_device_close (dev);

    return grub_errno;
}

static grub_err_t
grub_cmd_bootswitch (grub_extcmd_context_t ctxt UNUSED, int argc UNUSED, char **args UNUSED)
{
    char *root = NULL, *sep;
    char *rootfs_env = NULL;
    char *prefix_env = NULL, *root_env = NULL;

    /* read root disk. */
    root = grub_strdup (grub_env_get ("root"));
    if (root == NULL) {
        goto boot_normal;
    }

    sep = grub_strchr (root, ',');
    if (sep) {
        *sep = '\0';
    }

    /* get the root env and prefix env */
    if (grub_tsenv_setup (root, &root_env, &prefix_env, &rootfs_env)) {
        goto boot_normal;
    }

    /* set root env */
    if (grub_env_set ("root", root_env)) {
        goto boot_normal;
    }

    /* set prefix env */
    if (grub_env_set ("prefix", prefix_env)) {
        goto boot_normal;
    }

    /* set rootfs env */
    if (grub_env_set ("rootfs", rootfs_env)) {
        goto boot_normal;
    }

    grub_printf ("Tencent setup new new root=%s, prefix=%s, rootfs=%s\n",
                 root_env, prefix_env, rootfs_env);

boot_normal:
    if (root) {
        grub_free (root);
    }

    /* Load the module.    */
    grub_dl_load ("normal");

    /* Print errors if any.    */
    grub_print_error ();
    grub_errno = 0;

    /* jump to normal */
    grub_command_execute ("normal", 0, 0);

    if (root_env) {
        grub_free (root_env);
    }

    if (prefix_env) {
        grub_free (prefix_env);
    }

    return grub_errno;
}

static grub_err_t
grub_cmd_bootshow(grub_extcmd_context_t ctxt UNUSED, int argc UNUSED, char **args UNUSED)
{
    char *name[2];
    grub_device_t dev;
    grub_info_t info[2];
    grub_uint64_t offset[2];
    char *root = NULL, *sep;
    int info_size = sizeof (grub_info_t);

    /* read root disk. */
    root = grub_strdup (grub_env_get ("root"));
    if (root == NULL) {
        return grub_errno;
    }

    sep = grub_strchr (root, ',');
    if (sep) {
        *sep = '\0';
    }

    /* open root disk. */
    dev = grub_device_open (root);
    if (!dev) {
        goto free_root;
    }

    /* read the grub_info_t offset in boota */
    name[BOOTA] = grub_xasprintf ("%s,%s", root, BOOTA_NAME);
    if (grub_get_info_offset (name[BOOTA], &offset[BOOTA])) {
        goto free_boota;
    }

    /* read boota info */
    if (grub_disk_read (dev->disk, offset[BOOTA], 0, info_size,
                        &info[BOOTA])) {
        goto free_boota;
    }

    /* read the grub_info_t offset in bootb */
    name[BOOTB] = grub_xasprintf ("%s,%s", root, BOOTB_NAME);
    if (grub_get_info_offset (name[BOOTB], &offset[BOOTB])) {
        goto free_bootb;
    }

    /* read bootb info */
    if (grub_disk_read (dev->disk, offset[BOOTB], 0, info_size,
                        &info[BOOTB])) {
        goto free_bootb;
    }

    grub_printf ("BOOTA:\n");
    grub_printf ("\tcsum : %x,\tmagic: %x\n", info[BOOTA].csum, info[BOOTA].magic);
    grub_printf ("\torder: %u,\tflag : %x\n", info[BOOTA].order, info[BOOTA].flag);

    grub_printf ("BOOTB:\n");
    grub_printf ("\tcsum : %x,\tmagic: %x\n", info[BOOTB].csum, info[BOOTB].magic);
    grub_printf ("\torder: %u,\tflag : %x\n", info[BOOTB].order, info[BOOTB].flag);

free_bootb:
    grub_free (name[BOOTB]);
free_boota:
    grub_free (name[BOOTA]);
    grub_device_close (dev);
free_root:
    grub_free (root);

    return grub_errno;
}

static grub_extcmd_t bcmd;
static grub_extcmd_t scmd;

GRUB_MOD_INIT(bootswitch)
{
    bcmd = grub_register_extcmd ("bootswitch", grub_cmd_bootswitch, 0,
                                NULL, N_("Boot a tencent operating system."),
                                NULL);
    scmd = grub_register_extcmd ("bootshow", grub_cmd_bootshow, 0,
                                NULL, N_("Show boot partition information."),
                                NULL);
}

GRUB_MOD_FINI(bootswitch)
{
    grub_unregister_extcmd (bcmd);
    grub_unregister_extcmd (scmd);
}

GRUB_MOD_LICENSE ("GPLv3+");
