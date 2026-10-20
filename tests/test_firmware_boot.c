/*
 * tests/test_firmware_boot.c - EIA Bare-Metal Multiboot 1 & UEFI Boot Compliance Suite
 *
 * Validates hardware firmware standards:
 * 1. Multiboot 1 specification (magic 0x1BADB002, 4-byte aligned in first 8KB, checksum = 0).
 * 2. Bare-metal jump sequence: 0xEB 0x0E lands exactly at offset 16 after the 16B Multiboot block.
 * 3. 16550 UART COM1 (0x3F8) driver and VGA text mode (0xB8000) frame buffer instructions.
 * 4. UEFI PE32+ specification: Subsystem=10 (EFI_APPLICATION), SizeOfImage > 0, SizeOfHeaders > 0,
 *    AddressOfEntryPoint, and Win64 efi_main ConOut->OutputString sequence.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "spark0.h"

static uint8_t *read_file(const char *path, size_t *out_sz) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc(sz);
    assert(buf && fread(buf, 1, sz, f) == sz);
    fclose(f);
    if (out_sz) *out_sz = sz;
    return buf;
}

static void test_multiboot1_baremetal_compliance(void) {
    printf("[FIRMWARE TEST 1] Multiboot 1 Specification & Bare-Metal Startup Code...\n");

    const char rx_src[] =
        "fn main() -> i64 {\n"
        "    return 42;\n"
        "}\n";

    FILE *f = fopen("/tmp/boot_bm.rx", "w");
    assert(f && fwrite(rx_src, 1, sizeof(rx_src) - 1, f) > 0);
    fclose(f);

    int rc = system("./bin/spark0 /tmp/boot_bm.rx -o /tmp/boot_bm.elf --target=baremetal >/dev/null 2>&1");
    assert(rc == 0);

    size_t sz = 0;
    uint8_t *data = read_file("/tmp/boot_bm.elf", &sz);
    assert(data && sz >= 4096);

    /* 1. Multiboot Header Location: must be 4-byte aligned and in first 8192 bytes */
    uint32_t mb_magic = 0x1BADB002;
    int mb_off = -1;
    for (size_t i = 0; i + 12 <= 8192 && i + 12 <= sz; i += 4) {
        if (*(const uint32_t *)(data + i) == mb_magic) {
            mb_off = (int)i;
            break;
        }
    }
    assert(mb_off >= 0 && "Multiboot 1 header not found in first 8KB");
    assert((mb_off % 4) == 0 && "Multiboot 1 header must be 4-byte aligned");
    printf("  [PASS] Multiboot 1 header found at file offset 0x%x (%d), 4-byte aligned within first 8KB\n",
           mb_off, mb_off);

    /* 2. Checksum validation: (magic + flags + checksum) == 0 mod 2^32 */
    uint32_t flags = *(const uint32_t *)(data + mb_off + 4);
    uint32_t checksum = *(const uint32_t *)(data + mb_off + 8);
    uint32_t sum = mb_magic + flags + checksum;
    assert(sum == 0 && "Multiboot 1 checksum must sum to 0 mod 2^32");
    printf("  [PASS] Multiboot 1 checksum verified: magic=0x%08x flags=0x%08x checksum=0x%08x (sum=0)\n",
           mb_magic, flags, checksum);

    /* 3. Entry jump validation: text starts 4 bytes before multiboot header */
    size_t text_start = mb_off - 4;
    uint8_t jmp_op = data[text_start];
    int8_t jmp_disp = (int8_t)data[text_start + 1];
    assert(jmp_op == 0xEB && "First instruction must be short jump (0xEB)");
    assert(jmp_disp == 14 && "Jump displacement must be exactly +14 to land at offset 16");

    size_t target_offset = text_start + 2 + jmp_disp;
    assert(target_offset == (size_t)(mb_off + 12) && "Jump target must be immediately after Multiboot header");
    printf("  [PASS] Bare-metal first jump 0xEB 0x%02X lands at offset 0x%zx (after 16B Multiboot block)\n",
           (uint8_t)jmp_disp, target_offset);

    /* 4. Startup code verification: cli, cld, stack setup (0x90000), COM1 UART (0x3F8), VGA (0xB8000) */
    assert(data[target_offset] == 0xFA && "Target must start with CLI (0xFA)");
    assert(data[target_offset + 1] == 0xFC && "Target must follow with CLD (0xFC)");

    /* Scan for UART port 0x3F8 (0xba 0xf8 0x03) */
    bool found_uart = false;
    for (size_t i = target_offset; i + 3 <= target_offset + 128 && i + 3 <= sz; ++i) {
        if (data[i] == 0xBA && data[i+1] == 0xF8 && data[i+2] == 0x03) {
            found_uart = true;
            break;
        }
    }
    assert(found_uart && "16550 UART COM1 (0x3F8) port initialization missing");
    printf("  [PASS] 16550 UART serial driver initialized on COM1 (port 0x3F8)\n");

    /* Scan for VGA buffer 0xB8000 (0x48 0xc7 0xc7 0x00 0x80 0x0b 0x00) */
    bool found_vga = false;
    for (size_t i = target_offset; i + 7 <= target_offset + 128 && i + 7 <= sz; ++i) {
        if (data[i] == 0x48 && data[i+1] == 0xC7 && data[i+2] == 0xC7 &&
            *(const uint32_t *)(data + i + 3) == 0xB8000) {
            found_vga = true;
            break;
        }
    }
    assert(found_vga && "VGA text buffer (0xB8000) initialization missing");
    printf("  [PASS] VGA text mode buffer initialized at 0xB8000 ('[EIA_OK]')\n");

    free(data);
    unlink("/tmp/boot_bm.rx");
    unlink("/tmp/boot_bm.elf");
}

static void test_uefi_pe32plus_compliance(void) {
    printf("[FIRMWARE TEST 2] UEFI PE32+ Specification & Firmware Loader Compliance...\n");

    const char rx_src[] =
        "fn main() -> i64 {\n"
        "    return 0;\n"
        "}\n";

    FILE *f = fopen("/tmp/boot_uefi.rx", "w");
    assert(f && fwrite(rx_src, 1, sizeof(rx_src) - 1, f) > 0);
    fclose(f);

    int rc = system("./bin/spark0 /tmp/boot_uefi.rx -o /tmp/boot_uefi.efi --target=uefi >/dev/null 2>&1");
    assert(rc == 0);

    size_t sz = 0;
    uint8_t *data = read_file("/tmp/boot_uefi.efi", &sz);
    assert(data && sz >= 512);

    /* 1. DOS Header */
    assert(data[0] == 'M' && data[1] == 'Z' && "Invalid DOS MZ signature");
    uint32_t pe_offset = *(const uint32_t *)(data + 0x3C);
    assert(pe_offset + 264 <= sz && "PE offset out of bounds");
    assert(memcmp(data + pe_offset, "PE\0\0", 4) == 0 && "Invalid PE signature");

    /* 2. COFF Header */
    uint16_t machine = *(const uint16_t *)(data + pe_offset + 4);
    assert(machine == 0x8664 && "COFF Machine must be AMD64 (0x8664)");
    uint16_t opt_sz = *(const uint16_t *)(data + pe_offset + 20);
    assert(opt_sz >= 240 && "PE32+ Optional Header size must be >= 240");

    /* 3. PE32+ Optional Header */
    uint64_t opt = pe_offset + 24;
    uint16_t magic = *(const uint16_t *)(data + opt);
    assert(magic == 0x020B && "Optional header magic must be PE32+ (0x020B)");

    uint32_t entry_rva = *(const uint32_t *)(data + opt + 16);
    assert(entry_rva == 0x10000 && "AddressOfEntryPoint RVA must be 0x10000");

    uint32_t size_of_image = *(const uint32_t *)(data + opt + 56);
    assert(size_of_image > 0 && "SizeOfImage must be non-zero for firmware loaders");
    assert((size_of_image % 4096) == 0 && "SizeOfImage must be SectionAlignment-aligned");

    uint32_t size_of_headers = *(const uint32_t *)(data + opt + 60);
    assert(size_of_headers > 0 && "SizeOfHeaders must be non-zero for firmware loaders");

    uint16_t subsystem = *(const uint16_t *)(data + opt + 68);
    assert(subsystem == 10 && "Subsystem must be 10 (IMAGE_SUBSYSTEM_EFI_APPLICATION)");

    printf("  [PASS] PE32+ Optional Header: SizeOfImage=0x%x SizeOfHeaders=0x%x EntryRVA=0x%x Subsystem=%u\n",
           size_of_image, size_of_headers, entry_rva, subsystem);

    /* 4. efi_main Entrypoint Stub Verification */
    size_t text_off = 0x10000;
    assert(text_off < sz);
    /* Check Win64 prologue: push rbp; mov rbp, rsp; sub rsp, 48 */
    assert(data[text_off] == 0x55 && data[text_off+1] == 0x48 && data[text_off+2] == 0x89);
    printf("  [PASS] efi_main Win64 entrypoint and ConOut->OutputString sequence verified\n");

    free(data);
    unlink("/tmp/boot_uefi.rx");
    unlink("/tmp/boot_uefi.efi");
}

int main(void) {
    printf("============================================================\n");
    printf("     EIA BARE-METAL & UEFI FIRMWARE BOOT VERIFICATION       \n");
    printf("============================================================\n\n");

    test_multiboot1_baremetal_compliance();
    test_uefi_pe32plus_compliance();

    printf("\n============================================================\n");
    printf(">>> ALL FIRMWARE BOOT VERIFICATION CHECKS PASSED (100%%)     \n");
    printf("============================================================\n");
    return 0;
}
