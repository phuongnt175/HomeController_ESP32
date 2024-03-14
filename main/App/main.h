#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include "freertos/event_groups.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_https_server.h"
#include "nvs_flash.h"

#include "esp_http_server.h"

#include "lwip/err.h"
#include "lwip/sys.h"

#include "time.h"

#include "Mid/serverSession.h"

#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"

#define TOKEN_LENGTH 32

// Token structure
struct Token {
    char token[TOKEN_LENGTH+1];
    int expireTime;
    uint32_t startTime;
};
void wifi_init_softap(void);
static httpd_handle_t https_server_init(uint16_t port);
static httpd_handle_t https_sta_server_init(void);
static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data);
static esp_err_t network_handler(httpd_req_t *req);
static esp_err_t scan_handler(httpd_req_t *req);
static esp_err_t HandlerUserLogin(httpd_req_t *req);
static esp_err_t HandlerWifiList(httpd_req_t *req);
static esp_err_t HandlerWifiConfig(httpd_req_t *req);
char* generateRandomString(int length);
struct Token generateToken(int expireTime);
void getMacAddress(uint8_t mac[6]);
void convertToLowercase(char *str);
const char* wifi_auth_mode_to_str(wifi_auth_mode_t auth_mode);
void wifi_configure(const char *ssid, const char *pass, int networkMode);
void get_sta_ip();