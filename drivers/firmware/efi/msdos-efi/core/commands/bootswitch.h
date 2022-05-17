#include <stdbool.h>

#define BOOTA_NAME   "msdos2"
#define BOOTB_NAME   "msdos3"
#define BOOTA_ROOT   "/dev/vda2"
#define BOOTB_ROOT   "/dev/vda3"
#define BOOT_MAGIC   0xaa5555aa

#define BOOT_FIRST   0x0000
#define BOOT_FAILED  0x4444
#define BOOT_SUCCESS 0x6666

#define SEQ_AFTER_EQ(a, b) ((grub_int32_t)(b) - (grub_int32_t)(a) <= 0)

enum boot_type {
    BOOTA = 0,
    BOOTB = 1,
};

typedef struct {
    grub_uint32_t csum;
    grub_uint32_t magic;
    grub_uint32_t order;
    grub_uint16_t flag;
    grub_uint16_t res;
} grub_info_t;
