#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "spark0_codegen.h"

static void print_usage(void) {
    printf("Rubix Stage-0 Bootstrap Compiler (spark0)\n"
           "Usage: spark0 <source.rx> -o <output_binary> [flags]\n\n"
           "Flags:\n"
           "  -o <path>             Specify executable output path\n"
           "  --target=<isa>        Target architecture: x86_64 (default), arm64, riscv64, baremetal, uefi, universal\n"
           "  --upbp                Emit Universal Polyglot Binary Package (Multi-OS)\n"
           "  -h, --help            Show this help dialog\n");
}

static char *read_entire_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen input file");
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = (char *)malloc(sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t r = fread(buf, 1, sz, f);
    buf[r] = '\0';
    fclose(f);
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return 0;
    }

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        }
    }

    const char *input_path = NULL;
    const char *output_path = NULL;
    int is_upbp = 0;
    int is_signed = 0;

    int target_arch = 0; /* 0=x86_64, 1=arm64, 2=riscv64, 3=baremetal, 4=uefi */

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 < argc) {
                output_path = argv[++i];
            } else {
                fprintf(stderr, "Error: -o requires an argument\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--upbp") == 0) {
            is_upbp = 1;
        } else if (strcmp(argv[i], "--sign") == 0 || strcmp(argv[i], "--auth") == 0) {
            is_signed = 1;
        } else if (strncmp(argv[i], "--target=", 9) == 0 || strncmp(argv[i], "-target=", 8) == 0) {
            const char *t = strchr(argv[i], '=') + 1;
            if (strcmp(t, "x86_64") == 0) {
                target_arch = 0;
            } else if (strcmp(t, "arm64") == 0 || strcmp(t, "aarch64") == 0) {
                target_arch = 1;
            } else if (strcmp(t, "riscv64") == 0) {
                target_arch = 2;
            } else if (strcmp(t, "baremetal") == 0 || strcmp(t, "multiboot") == 0) {
                target_arch = 3;
            } else if (strcmp(t, "uefi") == 0 || strcmp(t, "efi") == 0) {
                target_arch = 4;
            } else if (strcmp(t, "universal") == 0 || strcmp(t, "multiarch") == 0) {
                target_arch = 5;
            } else if (strcmp(t, "pe") == 0 || strcmp(t, "windows") == 0 || strcmp(t, "win64") == 0) {
                target_arch = 6;
            } else if (strcmp(t, "macho") == 0 || strcmp(t, "macos") == 0 || strcmp(t, "darwin") == 0) {
                target_arch = 7;
            } else {
                fprintf(stderr, "Error: unsupported target architecture '%s'\n", t);
                return 1;
            }
        } else if (strcmp(argv[i], "--target") == 0 || strcmp(argv[i], "-target") == 0) {
            if (i + 1 < argc) {
                const char *t = argv[++i];
                if (strcmp(t, "x86_64") == 0) {
                    target_arch = 0;
                } else if (strcmp(t, "arm64") == 0 || strcmp(t, "aarch64") == 0) {
                    target_arch = 1;
                } else if (strcmp(t, "riscv64") == 0) {
                    target_arch = 2;
                } else if (strcmp(t, "baremetal") == 0 || strcmp(t, "multiboot") == 0) {
                    target_arch = 3;
                } else if (strcmp(t, "uefi") == 0 || strcmp(t, "efi") == 0) {
                    target_arch = 4;
                } else if (strcmp(t, "universal") == 0 || strcmp(t, "multiarch") == 0) {
                    target_arch = 5;
                } else if (strcmp(t, "pe") == 0 || strcmp(t, "windows") == 0 || strcmp(t, "win64") == 0) {
                    target_arch = 6;
                } else if (strcmp(t, "macho") == 0 || strcmp(t, "macos") == 0 || strcmp(t, "darwin") == 0) {
                    target_arch = 7;
                } else {
                    fprintf(stderr, "Error: unsupported target architecture '%s'\n", t);
                    return 1;
                }
            } else {
                fprintf(stderr, "Error: %s requires a target architecture argument\n", argv[i]);
                return 1;
            }
        } else if (argv[i][0] != '-') {
            if (!input_path) {
                input_path = argv[i];
            }
        }
    }

    if (!input_path || !output_path) {
        fprintf(stderr, "Error: missing required input file or output path (-o)\n");
        return 1;
    }

    char *src = read_entire_file(input_path);
    if (!src) {
        fprintf(stderr, "Error: could not read input file '%s'\n", input_path);
        return 1;
    }

    RuModule *module = spark0_parse(src, input_path);
    if (!module) {
        fprintf(stderr, "Error: failed to parse '%s'\n", input_path);
        free(src);
        return 1;
    }

    int rc = spark0_compile_to_elf_opt(module, output_path, is_upbp, target_arch, is_signed);
    if (rc != 0) {
        fprintf(stderr, "Error: compilation failed for '%s'\n", output_path);
        free(src);
        return 1;
    }

    printf("[spark0] Successfully compiled '%s' -> '%s'\n", input_path, output_path);
    free(src);
    return 0;
}
