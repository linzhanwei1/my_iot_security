#include <mbedtls/md.h>
#include <stdio.h>
#include <string.h>

#include "esp_random.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/platform.h"
#include "mbedtls/rsa.h"

#define mbedtls_printf printf

#define assert_exit(cond, ret)                                                 \
  do {                                                                         \
    if (!(cond)) {                                                             \
      printf("  !. assert: failed [line: %d, error: -0x%04X]\n", __LINE__,     \
             -ret);                                                            \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

static int entropy_source(void *data, uint8_t *output, size_t len,
                          size_t *olen) {
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
    mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n    " : " ", buf[i],
                   i == len - 1 ? "\n" : "");
  }
}

static void dump_rsa_key(mbedtls_rsa_context *ctx) {
  size_t olen;
  uint8_t buf[516];

  mbedtls_printf("\n  +++++++++++++++ rsa keypair +++++++++++++++\n\n");
  mbedtls_mpi_write_string(&ctx->N, 16, (char *)buf, sizeof(buf), &olen);
  mbedtls_printf("N: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->E, 16, (char *)buf, sizeof(buf), &olen);
  mbedtls_printf("E: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->D, 16, (char *)buf, sizeof(buf), &olen);
  mbedtls_printf("D: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->P, 16, (char *)buf, sizeof(buf), &olen);
  mbedtls_printf("P: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->Q, 16, (char *)buf, sizeof(buf), &olen);
  mbedtls_printf("Q: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->DP, 16, (char *)buf, sizeof(buf), &olen);
  mbedtls_printf("DQ: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->DQ, 16, (char *)buf, sizeof(buf), &olen);
  mbedtls_printf("DQ: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->QP, 16, (char *)buf, sizeof(buf), &olen);
  mbedtls_printf("QP: %s\n", buf);
  mbedtls_printf("\n ++++++++++++++ rsa keypair +++++++++++++++\n\n");
}

void app_main(void) {
  int ret = 0;
  uint8_t msg[100];
  uint8_t sig[2048 / 8];
  char *pers = "simple_rsa_sign";

  mbedtls_rsa_context ctx;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

  mbedtls_entropy_add_source(&entropy, entropy_source, NULL,
                             MBEDTLS_ENTROPY_MAX_GATHER,
                             MBEDTLS_ENTROPY_SOURCE_STRONG);
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const uint8_t *)pers, strlen(pers));
  assert_exit(ret == 0, ret);
  mbedtls_printf("\n  . setup rng ... ok\n\n");

  mbedtls_printf("  ! RSA Generating large primes may take minutes! \n");
  ret = mbedtls_rsa_gen_key(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, 2048,
                            65537);
  assert_exit(ret == 0, ret);
  mbedtls_printf("  1. rsa generate keypair ... ok\n");
  dump_rsa_key(&ctx);

  ret = mbedtls_rsa_pkcs1_sign(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg,
                               MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                               sizeof(msg), msg, sig);
  assert_exit(ret == 0, ret);
  dump_buf("  2. rsa generate signature:", sig, sizeof(sig));

  ret = mbedtls_rsa_pkcs1_verify(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg,
                                 MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256,
                                 sizeof(msg), msg, sig);
  assert_exit(ret == 0, ret);
  mbedtls_printf("  3. rsa verify signature ... ok\n\n");

cleanup:
  mbedtls_rsa_free(&ctx);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}
