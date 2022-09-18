#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/md.h"
#include "mbedtls/platform.h"

static void dump_buf(char *info, uint8_t *buf, uint32_t len) {
  printf("%s", info);
  for (int i = 0; i < len; i++) {
    printf("%s%02X%s", i % 16 == 0 ? "\n\t" : " ", buf[i],
           i == len - 1 ? "\n" : "");
  }
  printf("\n");
}

void app_main(void) {
  uint8_t digest[32];
  char *msg = "abc";
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t *info;

  mbedtls_md_init(&ctx);
  info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  mbedtls_md_setup(&ctx, info, 0);
  printf("\n  md info setup, name: %s, digest size: %d\n",
         mbedtls_md_get_name(info), mbedtls_md_get_size(info));

  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char *)msg, strlen(msg));
  mbedtls_md_finish(&ctx, digest);

  dump_buf("\n  md sha-256 digest:", digest, sizeof(digest));

  mbedtls_md_free(&ctx);
}
