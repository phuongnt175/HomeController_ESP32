#include "main.h"

#define ESP_WIFI_SSID      "esp32_test_ap"
#define ESP_WIFI_PASS      "ABC123456"
#define ESP_WIFI_CHANNEL   1
#define MAX_STA_CONN       4
#define SOFTAP_IP          "10.10.10.254"

static const char *TAG = "main";

uint8_t mac_addr[6];

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                    int32_t event_id, void* event_data)
{
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" join, AID=%d",
                 MAC2STR(event->mac), event->aid);
    } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" leave, AID=%d",
                 MAC2STR(event->mac), event->aid);
    }
}

static esp_err_t root_handler(httpd_req_t *req)
{
    const char *resp_str = "OK";
    httpd_resp_send(req, resp_str, strlen(resp_str));
    return ESP_OK;
}

static esp_err_t network_handler(httpd_req_t *req)
{
    const char *resp_str = "Wifi infomation...";
    httpd_resp_send(req, resp_str, strlen(resp_str));
    return ESP_OK;
}

static esp_err_t scan_handler(httpd_req_t *req)
{
    const char *resp_str = "Scan Wifi list...";
    httpd_resp_send(req, resp_str, strlen(resp_str));
    return ESP_OK;
}

static const httpd_uri_t root_uri = {
    .uri       = "/",
    .method    = HTTP_GET,
    .handler   = root_handler,
};

static const httpd_uri_t network_uri = {
    .uri       = "/api/device/network",
    .method    = HTTP_GET,
    .handler   = network_handler,
};

static const httpd_uri_t scan_uri = {
    .uri       = "/api/device/network/scan",
    .method    = HTTP_GET,
    .handler   = scan_handler,
};

void wifi_init_softap(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));
                                                    
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t wifi_config = {
        .ap = {
            .ssid = ESP_WIFI_SSID,
            .ssid_len = strlen(ESP_WIFI_SSID),
            .channel = ESP_WIFI_CHANNEL,
            .password = ESP_WIFI_PASS,
            .max_connection = MAX_STA_CONN,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                    .required = true,
            },
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    char* ip = SOFTAP_IP;
    char* gateway = "10.10.10.254";
    char* netmask = "255.255.255.0";
    esp_netif_ip_info_t info_t;
    memset(&info_t, 0, sizeof(esp_netif_ip_info_t));

    if (ap_netif)
    {
        ESP_ERROR_CHECK(esp_netif_dhcps_stop(ap_netif));
        info_t.ip.addr = esp_ip4addr_aton((const char *)ip);
        info_t.netmask.addr = esp_ip4addr_aton((const char *)netmask);
        info_t.gw.addr = esp_ip4addr_aton((const char *)gateway);
        esp_netif_set_ip_info(ap_netif, &info_t);
        ESP_ERROR_CHECK(esp_netif_dhcps_start(ap_netif));
    }

    ESP_LOGI(TAG, "wifi_init_softap finished. SSID:%s",
             ESP_WIFI_SSID);

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    httpd_handle_t server;
    if (httpd_start(&server, &config) == ESP_OK)
    {
        ESP_LOGI(TAG, "HTTP server started on port: '%d'", config.server_port);
    }
    else
    {
        ESP_LOGE(TAG, "Failed to start HTTP server");
    }

    httpd_register_uri_handler(server, &root_uri);
    httpd_register_uri_handler(server, &network_uri);
    httpd_register_uri_handler(server, &scan_uri);
}

void app_main(void)
{
    //Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "ESP_WIFI_MODE_AP");
    wifi_init_softap();
    
}

void HandlerUserLogin(const char* request_body) {
    getMacAddress(mac_addr);
    cJSON* body = NULL;
    cJSON* response = cJSON_CreateObject();
    struct Token token;

    char mac_str[18];  // Assumes a MAC address is 6 bytes, and each byte is represented by 2 characters, plus a null terminator
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
         mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

    body = cJSON_Parse(request_body);
    if (!body || !cJSON_IsObject(body)) {
        cJSON_AddStringToObject(response, "error", "Could not parse message");
        goto BadRequest;
    }

    const cJSON* username = cJSON_GetObjectItemCaseSensitive(body, "username");
    const cJSON* password = cJSON_GetObjectItemCaseSensitive(body, "password");

    if (!cJSON_IsString(username) || !cJSON_IsString(password)) {
        cJSON_AddStringToObject(response, "error", "Invalid format");
        goto BadRequest;
    }

    if (strcmp(username->valuestring, "admin") != 0 || strcmp(password->valuestring, "luci123") != 0) {
        cJSON_AddStringToObject(response, "error", "Invalid credentials");
        goto BadRequest;
    }

    // Generate token and expireTime (replace these lines with your actual logic)
    snprintf(token.token, sizeof(token.token), generateRandomString(TOKEN_LENGTH));
    token.expireTime = 3600;
    token.startTime = time(NULL);

    cJSON_AddStringToObject(response, "data", "OK");
    cJSON_AddStringToObject(response, "timezone", "Asia/Ho Chi Minh"); //timezone?
    cJSON_AddStringToObject(response, "mac", mac_str); //mac device

    cJSON* token_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(token_obj, "token", token.token);
    cJSON_AddNumberToObject(token_obj, "expireTime", token.expireTime);
    cJSON_AddNumberToObject(token_obj, "startTime", token.startTime);

    cJSON_AddItemToObject(response, "data", token_obj);

    char* response_str = cJSON_PrintUnformatted(response);
    // TODO: Send response_str as an HTTP response

    cJSON_Delete(response);
    cJSON_Delete(body);
    free(response_str);  // Free the memory allocated by cJSON_PrintUnformatted
    return;

BadRequest:
    // TODO: Handle bad request
    cJSON_Delete(response);
    cJSON_Delete(body);
}

// Function to generate a random string of a given length
char* generateRandomString(int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char* randomString = malloc((length + 1) * sizeof(char));  // +1 for null terminator
    if (randomString) {
        for (int i = 0; i < length; i++) {
            int index = rand() % (int)(sizeof(charset) - 1);
            randomString[i] = charset[index];
        }
        randomString[length] = '\0';  // Null-terminate the string
    }
    return randomString;
}

// Function to generate a token
struct Token generateToken(int expireTime) {
    struct Token token;

    // Generate a random string and copy it to the token
    char* randomString = generateRandomString(TOKEN_LENGTH);
    strcpy(token.token, randomString);
    free(randomString);  // Free the memory allocated by generateRandomString

    // Set other token properties
    token.expireTime = expireTime;
    token.startTime = (uint32_t)time(NULL);

    // Log information about the generated token
    printf("Onetime token %s generated (expires in %ds)\n", token.token, expireTime);

    return token;
}

void getMacAddress(uint8_t mac[6])
{
    esp_err_t ret = ESP_OK;
    ret = esp_efuse_mac_get_default(mac);
    if(ret != ESP_OK){
    }

    uint8_t index = 0;
    char macId[50];
    for(uint8_t i=0; i<6; i++){
        index += sprintf(&macId[index], "%02x", mac[i]);
    }
}

