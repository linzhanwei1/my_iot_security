#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/platform.h"
#include "mbedtls/rsa.h"

#include "esp_random.h"

#define assert_exit(cond, ret)                                                 \
  do {                                                                         \
    if (!(cond)) {                                                             \
      printf("  !. assert: failed [line: %d, error: -0x%04X]\n", __LINE__,     \
             -ret);                                                            \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

static void dump_buf(char *info, uint8_t *buf, uint32_t len) {
  mbedtls_printf("%s", info);
  for (int i = 0; i < len; i++) {
    printf("%s%02X%s", i % 16 == 0 ? "\n     " : " ", buf[i],
           i == len - 1 ? "\n" : "");
  }
}

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

static void dump_rsa_key(mbedtls_rsa_context *ctx) {
  size_t olen;
  char buf[516];

  printf("\n  +++++++++++++++ rsa keypair +++++++++++++++\n\n");

  mbedtls_mpi_write_string(&ctx->N, 16, buf, sizeof(buf), &olen);
  printf("N:  %s\n", buf);

  mbedtls_mpi_write_string(&ctx->E, 16, buf, sizeof(buf), &olen);
  printf("E:  %s\n", buf);

  mbedtls_mpi_write_string(&ctx->D, 16, buf, sizeof(buf), &olen);
  printf("E:  %s\n", buf);

  mbedtls_mpi_write_string(&ctx->P, 16, buf, sizeof(buf), &olen);
  printf("E:  %s\n", buf);

  mbedtls_mpi_write_string(&ctx->Q, 16, buf, sizeof(buf), &olen);
  printf("E:  %s\n", buf);

  mbedtls_mpi_write_string(&ctx->DP, 16, buf, sizeof(buf), &olen);
  printf("E:  %s\n", buf);

  mbedtls_mpi_write_string(&ctx->DQ, 16, buf, sizeof(buf), &olen);
  printf("E:  %s\n", buf);

  mbedtls_mpi_write_string(&ctx->DP, 16, buf, sizeof(buf), &olen);
  printf("E:  %s\n", buf);

  printf("\n  ++++++++++ rsa keypair ++++++++++\n\n");
}

void app_main(void) {
  int ret;
  size_t olen = 0;
  uint8_t out[2048 / 8];

  mbedtls_rsa_context ctx;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  const char *pers = "simple_rsa";
  const char *msg = "Hello, World!";

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

  mbedtls_entropy_add_source(&entropy, entropy_source, NULL,
                             MBEDTLS_ENTROPY_MAX_GATHER,
                             MBEDTLS_ENTROPY_SOURCE_STRONG);
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)pers, strlen(pers));

  assert_exit(ret == 0, ret);
  printf("\n  . setup rng ...ok\n");

  printf("\n  ! RSA Generating large primes may take minutes! \n");
  ret = mbedtls_rsa_gen_key(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, 2048,
                            65537);

  assert_exit(ret == 0, ret);
  printf("\n  1. RSA generate key ... ok\n");
  dump_rsa_key(&ctx);

  ret = mbedtls_rsa_pkcs1_encrypt(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg,
                                  MBEDTLS_RSA_PUBLIC, strlen(msg),
                                  (const unsigned char *)msg, out);
  assert_exit(ret == 0, ret);
  dump_buf("\n   2. RSA encryption ... ok", out, sizeof(out));

  ret = mbedtls_rsa_pkcs1_decrypt(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg,
                                  MBEDTLS_RSA_PRIVATE, &olen, out, out,
                                  sizeof(out));
  assert_exit(ret == 0, ret);

  out[olen] = 0;
  printf("\n   3. RSA decryption ... ok\n     %s\n", out);

  ret = memcmp(out, msg, olen);
  assert_exit(ret == 0, ret);
  printf("\n   4. RSA Compare results and plaintext ... ok\n");
cleanup:
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_rsa_free(&ctx);
}
