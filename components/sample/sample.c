#include <stdio.h>
#include "sample.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

void func_sample(void)
{
 vTaskDelay(500 / portTICK_PERIOD_MS);
}
