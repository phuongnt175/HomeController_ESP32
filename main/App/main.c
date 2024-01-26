#include "main.h"

#define HTTPS_ENABLE 1

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

static esp_err_t HandlerUserLogin(httpd_req_t *req) {
    getMacAddress(mac_addr);
    cJSON* body = NULL;
    cJSON* response = cJSON_CreateObject();
    struct Token token;

    char mac_str[18]; 
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
         mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

    // Get the length of the request body
    size_t content_length = req->content_len;

    // Allocate a buffer to store the request body
    char* request_body = malloc(content_length + 1);
    if (!request_body) {
        // Handle memory allocation error
        httpd_resp_send(req, "Internal Server Error", strlen("Internal Server Error"));
        goto BadRequest;
    }

    if (req->method != HTTP_POST) {
        httpd_resp_send(req, "Internal Server Error", strlen("Method not supported"));
        goto BadRequest;
    }

    // Read the request body
    if (httpd_req_recv(req, request_body, content_length) <= 0) {
        // Handle error reading request body
        free(request_body);
        httpd_resp_send(req, "Internal Server Error", strlen("Internal Server Error"));
        goto BadRequest;
    }

    // Null-terminate the request body string
    request_body[content_length] = '\0';
    body = cJSON_Parse(request_body);

    const cJSON* username = cJSON_GetObjectItemCaseSensitive(body, "username");
    const cJSON* password = cJSON_GetObjectItemCaseSensitive(body, "password");

    if (!cJSON_IsString(username) || !cJSON_IsString(password)) {
        httpd_resp_send(req, "Internal Server Error", strlen("Internal Server Error"));
        ESP_LOGI(TAG, "check username and password string");
        goto BadRequest;
    }

    if (strcmp(username->valuestring, "admin") != 0 || strcmp(password->valuestring, "luci123") != 0) {
        httpd_resp_send(req, "Internal Server Error", strlen("Internal Server Error"));
        ESP_LOGI(TAG, "check string compare");
        goto BadRequest;
    }
    ESP_LOGI(TAG, "pass username and password userlogin check");

    // Generate token and expireTime
    snprintf(token.token, sizeof(token.token), generateRandomString(TOKEN_LENGTH));
    ESP_LOGI(TAG, "%s", token.token);
    token.expireTime = 3600;
    token.startTime = time(NULL);
    
    cJSON* token_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(token_obj, "timezone", "Asia/Ho Chi Minh"); //timezone?
    cJSON_AddStringToObject(token_obj, "mac", mac_str); //mac device
    cJSON_AddStringToObject(token_obj, "token", token.token);
    cJSON_AddNumberToObject(token_obj, "expireTime", token.expireTime);

    cJSON_AddItemToObject(response, "data", token_obj);

    char* response_str = cJSON_PrintUnformatted(response);
    httpd_resp_send(req, response_str, strlen(response_str));

    ESP_LOGI(TAG, "%s", response_str);

    // free(request_body);
    cJSON_Delete(response);
    cJSON_Delete(body);
    free(response_str);  // Free the memory allocated by cJSON_PrintUnformatted
    return ESP_OK;

    BadRequest:
    // TODO: Handle bad request
    char* response_bad_rq = cJSON_PrintUnformatted(response);
    httpd_resp_send(req, response_bad_rq, strlen(response_bad_rq));
    ESP_LOGI(TAG, "bad request");
    cJSON_Delete(response);
    cJSON_Delete(body);
    free(response_bad_rq);
    return ESP_OK;
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
    .uri       = "/user/login",
    .method    = HTTP_POST,
    .handler   = HandlerUserLogin,
    .user_ctx  = NULL
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

static httpd_handle_t https_server_init(void)
{
#ifdef HTTP_ENABLE
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 3001;

    httpd_handle_t server;
    if (httpd_start(&server, &config) == ESP_OK)
    {
        ESP_LOGI(TAG, "HTTP server started on port: '%d'", config.server_port);
    }
    else
    {
        ESP_LOGE(TAG, "Failed to start HTTP server");
    }
#endif
#ifdef HTTPS_ENABLE
    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    httpd_handle_t server = NULL;
    config.port_secure = 3001;

    extern const unsigned char servercert_pem_start[] asm("_binary_servercert_pem_start");
    extern const unsigned char servercert_pem_end[] asm("_binary_servercert_pem_end");
    config.servercert = servercert_pem_start;
    config.servercert_len = servercert_pem_end - servercert_pem_start;

    extern const unsigned char prvkey_pem_start[] asm("_binary_prvkey_pem_start");
    extern const unsigned char prvkey_pem_end[] asm("_binary_prvkey_pem_end");
    config.prvtkey_pem = prvkey_pem_start;
    config.prvtkey_len = prvkey_pem_end - prvkey_pem_start;

    esp_err_t ret = httpd_ssl_start(&server, &config);
    if(ESP_OK != ret)
    {
        ESP_LOGI(TAG, "Error starting server!");
        return NULL;
    }

#endif

    httpd_register_uri_handler(server, &root_uri);
    httpd_register_uri_handler(server, &network_uri);
    httpd_register_uri_handler(server, &scan_uri);
    return server;
}

void wifi_init_softap(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,
                                                ESP_EVENT_ANY_ID,
                                                &wifi_event_handler,
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
    https_server_init();
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