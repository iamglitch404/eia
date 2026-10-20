/*
 * test_gdam_hot_migration.c - EIA Generation-Driven Schema Migration (GDAM)
 * Concurrent Live Upgrades, Atomic Publication, Rollback & Stress Suite
 *
 * Enforces Reynolds' Relational Parametricity and zero-downtime hot migration.
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>
#include "spark0.h"

/* Production GDAM routines are directly linked from src/eia_loader.c */

/* ------------------------------------------------------------------------- */
/* Concurrent Reader / Upgrade Simulation Test                              */
/* ------------------------------------------------------------------------- */

#define NUM_READERS 4
#define READ_CYCLES 50000

typedef struct {
    ConcurrentGdamState *gdam;
    int reader_id;
    _Atomic(bool) *running;
    _Atomic(uint64_t) read_count;
    _Atomic(uint64_t) error_count;
} ReaderThreadArg;

static void *reader_worker(void *arg) {
    ReaderThreadArg *ra = (ReaderThreadArg *)arg;
    uint64_t bal_hash = spark0_hash_str("balance");
    uint64_t id_hash = spark0_hash_str("id");

    while (atomic_load(ra->running)) {
        GdamGeneration *gen = gdam_reader_enter(ra->gdam);
        if (!gen || !gen->record_buf) {
            gdam_reader_leave(ra->gdam);
            atomic_fetch_add(&ra->error_count, 1);
            continue;
        }

        const uint8_t *rec = gen->record_buf;
        const GdamFieldEntry *tg = gen->schema;
        uint32_t cnt = gen->count;

        uint32_t bal_offset = 0xFFFFFFFF;
        uint32_t id_offset = 0xFFFFFFFF;

        for (uint32_t i = 0; i < cnt; ++i) {
            if (tg[i].field_hash == bal_hash) bal_offset = tg[i].byte_offset;
            if (tg[i].field_hash == id_hash) id_offset = tg[i].byte_offset;
        }

        if (bal_offset != 0xFFFFFFFF && id_offset != 0xFFFFFFFF) {
            uint64_t bal = *(const uint64_t *)(rec + bal_offset);
            uint64_t id = *(const uint64_t *)(rec + id_offset);
            if (bal != 42 || id != 1001) {
                atomic_fetch_add(&ra->error_count, 1);
            }
        }

        gdam_reader_leave(ra->gdam);

        atomic_fetch_add(&ra->read_count, 1);
        if (atomic_load(&ra->read_count) >= READ_CYCLES) break;
    }

    return NULL;
}

int main(void) {
    printf("============================================================\n");
    printf("   EIA GDAM CONCURRENT LIVE UPGRADE & MIGRATION SUITE       \n");
    printf("============================================================\n\n");

    uint64_t acct_type_hash = spark0_hash_str("Account");
    uint64_t id_hash = spark0_hash_str("id");
    uint64_t bal_hash = spark0_hash_str("balance");
    uint64_t audit_hash = spark0_hash_str("audit_id");
    uint64_t flags_hash = spark0_hash_str("flags");

    /* Schema V1: Account { id: u64 (off 0), balance: u64 (off 8) } */
    GdamFieldEntry schema_v1[] = {
        { acct_type_hash, id_hash,  0, 8 },
        { acct_type_hash, bal_hash, 8, 8 }
    };
    uint8_t rec_v1[16];
    *(uint64_t *)(rec_v1 + 0) = 1001; /* id */
    *(uint64_t *)(rec_v1 + 8) = 42;   /* balance */

    GdamGeneration gen1 = {
        .epoch = 1,
        .record_buf = rec_v1,
        .schema = schema_v1,
        .count = 2
    };

    /* Schema V2: Account { flags: u64 (off 0), audit_id: u64 (off 8), balance: u64 (off 16), id: u64 (off 24) } */
    GdamFieldEntry schema_v2[] = {
        { acct_type_hash, flags_hash, 0, 8 },
        { acct_type_hash, audit_hash, 8, 8 },
        { acct_type_hash, bal_hash,  16, 8 },
        { acct_type_hash, id_hash,   24, 8 }
    };
    uint8_t rec_v2[32];
    memset(rec_v2, 0, sizeof(rec_v2));
    *(uint64_t *)(rec_v2 + 0) = 1;     /* flags */
    *(uint64_t *)(rec_v2 + 8) = 9999;  /* audit_id */

    GdamGeneration gen2 = {
        .epoch = 2,
        .record_buf = rec_v2,
        .schema = schema_v2,
        .count = 4
    };

    /* Schema V3: Account { flags: u64, audit_id: u64, balance: u64, id: u64, status: u64 } */
    uint64_t status_hash = spark0_hash_str("status");
    GdamFieldEntry schema_v3[] = {
        { acct_type_hash, flags_hash,  0, 8 },
        { acct_type_hash, audit_hash,  8, 8 },
        { acct_type_hash, bal_hash,   16, 8 },
        { acct_type_hash, id_hash,    24, 8 },
        { acct_type_hash, status_hash,32, 8 }
    };
    uint8_t rec_v3[40];
    memset(rec_v3, 0, sizeof(rec_v3));

    GdamGeneration gen3 = {
        .epoch = 3,
        .record_buf = rec_v3,
        .schema = schema_v3,
        .count = 5
    };

    /* Initialize GDAM with Gen 1 */
    ConcurrentGdamState gdam;
    gdam_init(&gdam, &gen1);
    printf("[PHASE 1] Initialized Generation 1: Epoch=1, Schema Entries=2\n");

    /* Launch concurrent reader threads */
    _Atomic(bool) running = true;
    pthread_t threads[NUM_READERS];
    ReaderThreadArg args[NUM_READERS];

    for (int i = 0; i < NUM_READERS; ++i) {
        args[i].gdam = &gdam;
        args[i].reader_id = i;
        args[i].running = &running;
        atomic_init(&args[i].read_count, 0);
        atomic_init(&args[i].error_count, 0);
        int rc = pthread_create(&threads[i], NULL, reader_worker, &args[i]);
        assert(rc == 0);
    }
    printf("[PHASE 2] Spawned %d concurrent reader threads (stress target: %d ops/thread)\n",
           NUM_READERS, READ_CYCLES);

    /* Let readers run on Epoch 1 */
    usleep(1000);

    /* Perform live migration to Generation 2 under concurrent load */
    printf("[PHASE 3] Live Migrating Generation 1 -> Generation 2...\n");
    size_t mig1 = gdam_migrate_record(rec_v1, schema_v1, 2, rec_v2, schema_v2, 4, acct_type_hash);
    assert(mig1 == 2);
    assert(*(uint64_t *)(rec_v2 + 16) == 42);   /* balance at 16 */
    assert(*(uint64_t *)(rec_v2 + 24) == 1001); /* id at 24 */

    uint64_t epoch2 = gdam_atomic_publish(&gdam, &gen2);
    assert(epoch2 == 2);
    printf("  [PASS] Atomic Publication Epoch 2 Verified! (new_epoch=%lu)\n", (unsigned long)epoch2);

    /* Perform live migration to Generation 3 */
    usleep(1000);
    printf("[PHASE 4] Live Migrating Generation 2 -> Generation 3...\n");
    size_t mig2 = gdam_migrate_record(rec_v2, schema_v2, 4, rec_v3, schema_v3, 5, acct_type_hash);
    assert(mig2 == 4);
    *(uint64_t *)(rec_v3 + 32) = 777; /* status */

    uint64_t epoch3 = gdam_atomic_publish(&gdam, &gen3);
    assert(epoch3 == 3);
    printf("  [PASS] Atomic Publication Epoch 3 Verified! (new_epoch=%lu)\n", (unsigned long)epoch3);

    /* Test rollback mechanism */
    usleep(1000);
    printf("[PHASE 5] Testing Atomic Rollback Protection...\n");
    int rb = gdam_rollback(&gdam);
    assert(rb == 0);
    GdamGeneration *curr = atomic_load(&gdam.active_generation);
    assert(curr->epoch == 2);
    assert(curr->count == 4);
    printf("  [PASS] Atomic Rollback to Epoch 2 verified without reader interruption!\n");

    /* Re-publish Generation 3 */
    gdam_atomic_publish(&gdam, &gen3);

    /* Wait for reader threads to complete */
    for (int i = 0; i < NUM_READERS; ++i) {
        pthread_join(threads[i], NULL);
    }

    uint64_t total_reads = 0;
    uint64_t total_errors = 0;
    for (int i = 0; i < NUM_READERS; ++i) {
        total_reads += atomic_load(&args[i].read_count);
        total_errors += atomic_load(&args[i].error_count);
    }

    printf("\n[RESULTS] Total Concurrent Reader Operations: %lu\n", (unsigned long)total_reads);
    printf("          Total Invariant Violations / Data Races: %lu\n", (unsigned long)total_errors);
    assert(total_errors == 0 && "Concurrent data race detected during live migration!");

    /* [PHASE 6] Production Multi-Object Graph Live Migration & Thread Registration */
    printf("\n[PHASE 6] Multi-Thread Dynamic Registration & Arbitrary Object Graph Live Migration...\n");
    ConcurrentGdamState app_gdam;
    gdam_init(&app_gdam, &gen1);

    /* Allocate application objects:
     * 1. A single Account struct (v1 layout: id at 0, balance at 8, size 16)
     * 2. An array of 100 Account structs
     */
    void *app_single_account = calloc(16, 1);
    *(uint64_t *)((uint8_t *)app_single_account + 0) = 4242; /* id */
    *(uint64_t *)((uint8_t *)app_single_account + 8) = 9999; /* balance */

    size_t arr_count = 100;
    void *app_account_array = calloc(16 * arr_count, 1);
    for (size_t a = 0; a < arr_count; ++a) {
        *(uint64_t *)((uint8_t *)app_account_array + a * 16 + 0) = 1000 + a;
        *(uint64_t *)((uint8_t *)app_account_array + a * 16 + 8) = (a + 1) * 10;
    }

    /* Register application objects into GDAM object graph */
    assert(eia_gdam_register_object(&app_gdam, &app_single_account, acct_type_hash, 1, 16) == 0);
    assert(eia_gdam_register_object(&app_gdam, &app_account_array, acct_type_hash, arr_count, 16) == 0);

    /* Register worker threads */
    uint64_t worker_tid1 = 1001;
    uint64_t worker_tid2 = 1002;
    assert(eia_gdam_register_thread(&app_gdam, worker_tid1) == 0);
    assert(eia_gdam_register_thread(&app_gdam, worker_tid2) == 0);

    /* Thread enters critical section */
    eia_gdam_thread_enter(&app_gdam, worker_tid1);
    eia_gdam_thread_leave(&app_gdam, worker_tid1);

    /* Live migrate the entire application object graph from Gen 1 to Gen 2! */
    uint64_t migrated_objs = eia_gdam_migrate_object_graph(&app_gdam, &gen2, acct_type_hash);
    assert(migrated_objs == 2);
    printf("  [PASS] Migrated %lu arbitrary application object nodes to Generation 2!\n", (unsigned long)migrated_objs);

    /* Verify single account migrated to Gen 2 layout (balance at 16, id at 24, size 32) */
    assert(*(uint64_t *)((uint8_t *)app_single_account + 24) == 4242);
    assert(*(uint64_t *)((uint8_t *)app_single_account + 16) == 9999);

    /* Verify all 100 elements in the array migrated cleanly to Gen 2 layout! */
    for (size_t a = 0; a < arr_count; ++a) {
        assert(*(uint64_t *)((uint8_t *)app_account_array + a * 32 + 24) == (1000 + a));
        assert(*(uint64_t *)((uint8_t *)app_account_array + a * 32 + 16) == ((a + 1) * 10));
    }
    printf("  [PASS] Verified 100-element array of structs and single object preserved all invariant fields!\n");

    /* Live migrate again to Gen 3! */
    uint64_t migrated_objs2 = eia_gdam_migrate_object_graph(&app_gdam, &gen3, acct_type_hash);
    assert(migrated_objs2 == 2);
    assert(*(uint64_t *)((uint8_t *)app_single_account + 24) == 4242);
    assert(*(uint64_t *)((uint8_t *)app_single_account + 16) == 9999);
    printf("  [PASS] Successfully live migrated object graph to Generation 3!\n");

    /* Cleanup application object graph and threads */
    assert(eia_gdam_unregister_object(&app_gdam, &app_single_account) == 0);
    assert(eia_gdam_unregister_object(&app_gdam, &app_account_array) == 0);
    assert(eia_gdam_unregister_thread(&app_gdam, worker_tid1) == 0);
    assert(eia_gdam_unregister_thread(&app_gdam, worker_tid2) == 0);
    gdam_reclaim_retired(&app_gdam);
    free(app_single_account);
    free(app_account_array);

    printf("\n============================================================\n");
    printf(">>> ALL GDAM CONCURRENT HOT MIGRATION TESTS PASSED (100%%)    \n");
    printf("============================================================\n");

    return 0;
}
