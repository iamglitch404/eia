/*
 * tests/test_eia_abi_bridge.c - Full System V AMD64 <-> Win64 ABI Bridge Test Suite
 *
 * Verifies bidirectional calling convention translation, full 6-argument forwarding
 * (register args + stack slots), non-volatile register preservation across boundaries,
 * and compiler-emitted contract bridging via eia-run.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#if defined(__x86_64__)

/* Helper to execute command and return exit code */
static int run_cmd_exit(const char *cmd) {
    int rc = system(cmd);
    if (WIFEXITED(rc)) {
        return WEXITSTATUS(rc);
    }
    return -1;
}

static void test_sysv_to_win64_unit(void) {
    printf("[ABI TEST 1] In-Memory Thunk: SysV AMD64 -> Win64 (6 args + shadow space)...\n");

    size_t page_sz = 4096;
    uint8_t *arena = (uint8_t *)mmap(NULL, page_sz, PROT_READ | PROT_WRITE | PROT_EXEC,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert(arena != MAP_FAILED);

    /*
     * Win64 Callee:
     * rcx = arg1, rdx = arg2, r8 = arg3, r9 = arg4
     * [rsp + 40] = arg5 (return address is [rsp+0], shadow space is [rsp+8..39])
     * [rsp + 48] = arg6
     * Computes sum in rax and returns.
     */
    uint8_t win64_callee_code[] = {
        0x55,                                               // push rbp
        0x48, 0x89, 0xe5,                                   // mov rbp, rsp
        0x48, 0x89, 0xc8,                                   // mov rax, rcx
        0x48, 0x01, 0xd0,                                   // add rax, rdx
        0x4c, 0x01, 0xc0,                                   // add rax, r8
        0x4c, 0x01, 0xc8,                                   // add rax, r9
        0x48, 0x03, 0x45, 0x30,                             // add rax, [rbp + 48] (arg 5)
        0x48, 0x03, 0x45, 0x38,                             // add rax, [rbp + 56] (arg 6)
        0x5d,                                               // pop rbp
        0xc3                                                // ret
    };
    memcpy(arena, win64_callee_code, sizeof(win64_callee_code));
    uint64_t callee_addr = (uint64_t)arena;

    /*
     * SysV -> Win64 Bridge Thunk:
     * Accepts: rdi, rsi, rdx, rcx, r8, r9
     * Forwards to Win64:
     *   rcx = rdi, rdx = rsi, r8 = rdx, r9 = rcx
     *   [rsp + 32] = r8 (SysV arg5)
     *   [rsp + 40] = r9 (SysV arg6)
     */
    uint8_t thunk[64];
    size_t b_idx = 0;
    thunk[b_idx++] = 0x55;                                          // push rbp
    thunk[b_idx++] = 0x48; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xe5; // mov rbp, rsp
    thunk[b_idx++] = 0x48; thunk[b_idx++] = 0x83; thunk[b_idx++] = 0xec; thunk[b_idx++] = 0x30; // sub rsp, 48
    thunk[b_idx++] = 0x4c; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0x44; thunk[b_idx++] = 0x24; thunk[b_idx++] = 0x20; // mov [rsp + 32], r8
    thunk[b_idx++] = 0x4c; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0x4c; thunk[b_idx++] = 0x24; thunk[b_idx++] = 0x28; // mov [rsp + 40], r9
    thunk[b_idx++] = 0x49; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xc9; // mov r9, rcx
    thunk[b_idx++] = 0x49; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xd0; // mov r8, rdx
    thunk[b_idx++] = 0x48; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xf2; // mov rdx, rsi
    thunk[b_idx++] = 0x48; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xf9; // mov rcx, rdi
    thunk[b_idx++] = 0x48; thunk[b_idx++] = 0xb8; // mov rax, imm64
    memcpy(thunk + b_idx, &callee_addr, 8);
    b_idx += 8;
    thunk[b_idx++] = 0xff; thunk[b_idx++] = 0xd0; // call rax
    thunk[b_idx++] = 0x48; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xec; // mov rsp, rbp
    thunk[b_idx++] = 0x5d; // pop rbp
    thunk[b_idx++] = 0xc3; // ret

    uint8_t *thunk_exec = arena + 128;
    memcpy(thunk_exec, thunk, b_idx);

    typedef uint64_t (*SysVBridgeFn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    SysVBridgeFn call_fn = (SysVBridgeFn)thunk_exec;

    uint64_t res = call_fn(10, 10, 10, 5, 5, 2);
    assert(res == 42);
    printf("  [PASS] SysV -> Win64 6-arg forwarding returned %lu (expected 42)\n", (unsigned long)res);

    munmap(arena, page_sz);
}

static void test_win64_to_sysv_unit(void) {
    printf("[ABI TEST 2] In-Memory Thunk: Win64 -> SysV AMD64 (callee-saved registers + stack args)...\n");

    size_t page_sz = 4096;
    uint8_t *arena = (uint8_t *)mmap(NULL, page_sz, PROT_READ | PROT_WRITE | PROT_EXEC,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert(arena != MAP_FAILED);

    /*
     * SysV Callee:
     * Expects: rdi, rsi, rdx, rcx, r8, r9
     * Intentionally clobbers rdi and rsi to verify bridge preservation.
     * Computes sum in rax and returns.
     */
    uint8_t sysv_callee_code[] = {
        0x48, 0x89, 0xf8,                                   // mov rax, rdi
        0x48, 0x01, 0xf0,                                   // add rax, rsi
        0x48, 0x01, 0xd0,                                   // add rax, rdx
        0x48, 0x01, 0xc8,                                   // add rax, rcx
        0x4c, 0x01, 0xc0,                                   // add rax, r8
        0x4c, 0x01, 0xc8,                                   // add rax, r9
        0x48, 0x31, 0xff,                                   // xor rdi, rdi (clobber)
        0x48, 0x31, 0xf6,                                   // xor rsi, rsi (clobber)
        0xc3                                                // ret
    };
    memcpy(arena, sysv_callee_code, sizeof(sysv_callee_code));
    uint64_t callee_addr = (uint64_t)arena;

    /*
     * Win64 -> SysV Bridge Thunk:
     * Receives Win64 caller state:
     *   rcx = arg1, rdx = arg2, r8 = arg3, r9 = arg4
     *   [rbp + 48] = arg5, [rbp + 56] = arg6
     * Preserves rdi and rsi (Win64 non-volatile).
     */
    uint8_t thunk[64];
    size_t b_idx = 0;
    thunk[b_idx++] = 0x55;                                          // push rbp
    thunk[b_idx++] = 0x48; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xe5; // mov rbp, rsp
    thunk[b_idx++] = 0x57;                                          // push rdi (preserve)
    thunk[b_idx++] = 0x56;                                          // push rsi (preserve)
    thunk[b_idx++] = 0x4c; thunk[b_idx++] = 0x8b; thunk[b_idx++] = 0x55; thunk[b_idx++] = 0x30; // mov r10, [rbp + 48]
    thunk[b_idx++] = 0x4c; thunk[b_idx++] = 0x8b; thunk[b_idx++] = 0x5d; thunk[b_idx++] = 0x38; // mov r11, [rbp + 56]
    thunk[b_idx++] = 0x48; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xcf; // mov rdi, rcx
    thunk[b_idx++] = 0x48; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xd6; // mov rsi, rdx
    thunk[b_idx++] = 0x4c; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xc2; // mov rdx, r8
    thunk[b_idx++] = 0x4c; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xc9; // mov rcx, r9
    thunk[b_idx++] = 0x4d; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xd0; // mov r8, r10
    thunk[b_idx++] = 0x4d; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xd9; // mov r9, r11
    thunk[b_idx++] = 0x48; thunk[b_idx++] = 0xb8; // mov rax, imm64
    memcpy(thunk + b_idx, &callee_addr, 8);
    b_idx += 8;
    thunk[b_idx++] = 0xff; thunk[b_idx++] = 0xd0; // call rax
    thunk[b_idx++] = 0x5e;                                          // pop rsi
    thunk[b_idx++] = 0x5f;                                          // pop rdi
    thunk[b_idx++] = 0x48; thunk[b_idx++] = 0x89; thunk[b_idx++] = 0xec; // mov rsp, rbp
    thunk[b_idx++] = 0x5d;                                          // pop rbp
    thunk[b_idx++] = 0xc3;                                          // ret

    uint8_t *thunk_exec = arena + 128;
    memcpy(thunk_exec, thunk, b_idx);

    /*
     * Test harness that simulates Win64 caller passing 6 args:
     */
    uint64_t canary_rdi = 0xCAFEBABE11223344ULL;
    uint64_t canary_rsi = 0xDEADBEEF55667788ULL;
    uint64_t out_rdi = 0, out_rsi = 0, res = 0;

    __asm__ __volatile__(
        "movq %4, %%rdi\n\t"
        "movq %5, %%rsi\n\t"
        "movq $10, %%rcx\n\t"
        "movq $10, %%rdx\n\t"
        "movq $10, %%r8\n\t"
        "movq $5, %%r9\n\t"
        "subq $48, %%rsp\n\t"
        "movq $5, 32(%%rsp)\n\t"
        "movq $2, 40(%%rsp)\n\t"
        "callq *%3\n\t"
        "addq $48, %%rsp\n\t"
        "movq %%rax, %0\n\t"
        "movq %%rdi, %1\n\t"
        "movq %%rsi, %2\n\t"
        : "=r"(res), "=r"(out_rdi), "=r"(out_rsi)
        : "r"(thunk_exec), "r"(canary_rdi), "r"(canary_rsi)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );

    assert(res == 42);
    assert(out_rdi == canary_rdi && "Bridge failed to preserve Win64 non-volatile RDI");
    assert(out_rsi == canary_rsi && "Bridge failed to preserve Win64 non-volatile RSI");
    printf("  [PASS] Win64 -> SysV 6-arg bridge returned %lu; non-volatile RDI/RSI preserved\n", (unsigned long)res);

    munmap(arena, page_sz);
}

static void test_e2e_sysv_client_win64_provider(void) {
    printf("[ABI TEST 3] End-to-End: SysV Client calling Win64 Provider via eia-run...\n");

    const char client_src[] =
        "#[abi(\"sysv\")]\n"
        "extern fn bridge_add6(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64;\n\n"
        "fn main() -> u64 {\n"
        "    return bridge_add6(10, 10, 10, 5, 5, 2);\n"
        "}\n";

    const char provider_src[] =
        "#[abi(\"win64\")]\n"
        "fn bridge_add6(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {\n"
        "    return a + b + c + d + e + f;\n"
        "}\n\n"
        "fn main() -> i64 {\n"
        "    return 0;\n"
        "}\n";

    FILE *f1 = fopen("/tmp/abi_c1.rx", "w");
    assert(f1 && fwrite(client_src, 1, sizeof(client_src) - 1, f1) > 0);
    fclose(f1);

    FILE *f2 = fopen("/tmp/abi_p1.rx", "w");
    assert(f2 && fwrite(provider_src, 1, sizeof(provider_src) - 1, f2) > 0);
    fclose(f2);

    int rc1 = run_cmd_exit("./bin/spark0 /tmp/abi_c1.rx -o /tmp/abi_c1_bin >/dev/null 2>&1");
    int rc2 = run_cmd_exit("./bin/spark0 /tmp/abi_p1.rx -o /tmp/abi_p1_bin >/dev/null 2>&1");
    assert(rc1 == 0 && rc2 == 0);

    int exec_rc = run_cmd_exit("./bin/eia-run /tmp/abi_c1_bin /tmp/abi_p1_bin >/dev/null 2>&1");
    assert(exec_rc == 42);
    printf("  [PASS] SysV Client -> Win64 Provider dynamically linked and executed (exit 42)\n");

    unlink("/tmp/abi_c1.rx");
    unlink("/tmp/abi_p1.rx");
    unlink("/tmp/abi_c1_bin");
    unlink("/tmp/abi_p1_bin");
}

static void test_e2e_win64_client_sysv_provider(void) {
    printf("[ABI TEST 4] End-to-End: Win64 Client calling SysV Provider via eia-run...\n");

    const char client_src[] =
        "#[abi(\"win64\")]\n"
        "extern fn bridge_add6(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64;\n\n"
        "fn main() -> u64 {\n"
        "    return bridge_add6(10, 10, 10, 5, 5, 2);\n"
        "}\n";

    const char provider_src[] =
        "#[abi(\"sysv\")]\n"
        "fn bridge_add6(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {\n"
        "    return a + b + c + d + e + f;\n"
        "}\n\n"
        "fn main() -> i64 {\n"
        "    return 0;\n"
        "}\n";

    FILE *f1 = fopen("/tmp/abi_c2.rx", "w");
    assert(f1 && fwrite(client_src, 1, sizeof(client_src) - 1, f1) > 0);
    fclose(f1);

    FILE *f2 = fopen("/tmp/abi_p2.rx", "w");
    assert(f2 && fwrite(provider_src, 1, sizeof(provider_src) - 1, f2) > 0);
    fclose(f2);

    int rc1 = run_cmd_exit("./bin/spark0 /tmp/abi_c2.rx -o /tmp/abi_c2_bin >/dev/null 2>&1");
    int rc2 = run_cmd_exit("./bin/spark0 /tmp/abi_p2.rx -o /tmp/abi_p2_bin >/dev/null 2>&1");
    assert(rc1 == 0 && rc2 == 0);

    int exec_rc = run_cmd_exit("./bin/eia-run /tmp/abi_c2_bin /tmp/abi_p2_bin >/dev/null 2>&1");
    assert(exec_rc == 42);
    printf("  [PASS] Win64 Client -> SysV Provider dynamically linked and executed (exit 42)\n");

    unlink("/tmp/abi_c2.rx");
    unlink("/tmp/abi_p2.rx");
    unlink("/tmp/abi_c2_bin");
    unlink("/tmp/abi_p2_bin");
}

#endif /* __x86_64__ */

int main(void) {
    printf("============================================================\n");
    printf("   EIA SYSTEM V <-> WIN64 ABI CALLING CONVENTION SUITE      \n");
    printf("============================================================\n\n");

#if defined(__x86_64__)
    test_sysv_to_win64_unit();
    test_win64_to_sysv_unit();
    test_e2e_sysv_client_win64_provider();
    test_e2e_win64_client_sysv_provider();

    printf("\n============================================================\n");
    printf(">>> ALL ABI CALLING CONVENTION TESTS PASSED (100%%)          \n");
    printf("============================================================\n");
#else
    printf("ABI calling convention bridge test suite is architecture-specific (x86-64).\n");
    printf("Skipping execution on non-x86_64 host.\n");
#endif
    return 0;
}
