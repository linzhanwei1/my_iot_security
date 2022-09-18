#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include <stdio.h>

int app_main(void) {
  while (1) {
    printf("  0x%u\n", esp_random());
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
}
