#include <mbedtls/ecp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esp_random.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/platform.h"

#define assert_exit(cond, ret)                                                          \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            printf("  !. assert: failed [line: %d, error: -0x%04X]\n", __LINE__, -ret); \
            goto cleanup;                                                               \
        }                                                                               \
    } while (0)

static int entropy_source(void *data, uint8_t *output, size_t len, size_t *olen) {
    uint32_t seed;

    seed = esp_random();
    if (len > sizeof(seed)) {
        len = sizeof(seed);
    }

    memcpy(output, &seed, len);
    *olen = len;

    return 0;
}

static void dump_buf(char *info, uint8_t *buf, uint32_t len) {
    mbedtls_printf("%s", info);
    for (int i = 0; i < len; i++) {
        mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n    " : " ", buf[ i ],
                       i == len - 1 ? "\n" : "");
    }
}

void app_main(void) {
    int                      ret = 0;
    size_t                   olen;
    char                     buf[ 65 ];
    mbedtls_ecp_group        grp;
    mbedtls_mpi              cli_secret, srv_secret;
    mbedtls_mpi              cli_pri, srv_pri;
    mbedtls_ecp_point        cli_pub, srv_pub;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    char                    *pers = "simple_ecdh";

    mbedtls_mpi_init(&cli_pri);
    mbedtls_mpi_init(&srv_pri);
    mbedtls_mpi_init(&cli_secret);
    mbedtls_mpi_init(&srv_secret);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&cli_pub);
    mbedtls_ecp_point_init(&srv_pub);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_add_source(&entropy, entropy_source, NULL, MBEDTLS_ENTROPY_MAX_GATHER,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const uint8_t *)pers,
                          strlen(pers));
    printf("\n  . setup rng ... ok\n");

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    printf("\n  . selet ecp group SECP256R1 ... ok\n");

    ret = mbedtls_ecdh_gen_public(&grp, &cli_pri, &cli_pub, mbedtls_ctr_drbg_random, &ctr_drbg);
    assert_exit(ret == 0, ret);
    mbedtls_ecp_point_write_binary(&grp, &cli_pub, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                   (unsigned char *)buf, sizeof(buf));
    dump_buf("  1. ecdh client generate public parameter:", (unsigned char *)buf, olen);

    ret = mbedtls_ecdh_gen_public(&grp, &srv_pri, &srv_pub, mbedtls_ctr_drbg_random, &ctr_drbg);
    assert_exit(ret == 0, ret);
    mbedtls_ecp_point_write_binary(&grp, &srv_pub, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                   (unsigned char *)buf, sizeof(buf));
    dump_buf("  2. ecdh server generate public parameter:", (unsigned char *)buf, olen);

    ret = mbedtls_ecdh_compute_shared(&grp, &cli_secret, &srv_pub, &cli_pri,
                                      mbedtls_ctr_drbg_random, &ctr_drbg);

    assert_exit(ret == 0, ret);
    mbedtls_mpi_write_binary(&cli_secret, (unsigned char *)buf, mbedtls_mpi_size(&cli_secret));
    dump_buf("  3. ecdh client generate secret:", (unsigned char *)buf,
             mbedtls_mpi_size(&cli_secret));

    ret = mbedtls_ecdh_compute_shared(&grp, &srv_secret, &cli_pub, &srv_pri,
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    assert_exit(ret == 0, ret);
    mbedtls_mpi_write_binary(&srv_secret, (unsigned char *)buf, mbedtls_mpi_size(&srv_secret));
    dump_buf("  4. ecdh server generate secret:", (unsigned char *)buf,
             mbedtls_mpi_size(&srv_secret));

    ret = mbedtls_mpi_cmp_mpi(&cli_secret, &srv_secret);
    assert_exit(ret == 0, ret);
    printf("  5. ecdh checking secrets ... ok\n");

cleanup:
    mbedtls_mpi_free(&cli_pri);
    mbedtls_mpi_free(&srv_pri);
    mbedtls_mpi_free(&cli_secret);
    mbedtls_mpi_free(&srv_secret);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&cli_pub);
    mbedtls_ecp_point_free(&srv_pub);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
}
