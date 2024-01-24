#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "esp_http_server.h"

#include "lwip/err.h"
#include "lwip/sys.h"

#include "cJSON.h"
#include "time.h"

#define TOKEN_LENGTH 32

// Token structure
struct Token {
    char token[TOKEN_LENGTH + 1];  // +1 for null terminator
    int expireTime;
    uint32_t startTime;
};

void wifi_init_softap(void);
static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data);
static esp_err_t root_handler(httpd_req_t *req);
static esp_err_t network_handler(httpd_req_t *req);
static esp_err_t scan_handler(httpd_req_t *req);
void HandlerUserLogin(const char* request_body);
char* generateRandomString(int length);
struct Token generateToken(int expireTime);
void getMacAddress(uint8_t mac[6]);