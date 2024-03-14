#include "main.h"

#define ESP_WIFI_CHANNEL   1
#define MAX_STA_CONN       4
#define SOFTAP_IP          "10.10.10.254"

#define WIFI_CONNECTED_BIT 0
#define WIFI_FAIL_BIT      1

static const char *TAG = "main";

static httpd_handle_t server = NULL; // Initialize to NULL
static httpd_handle_t sta_server = NULL;

uint8_t mac_addr[6];

static int s_retry_num = 0;
static EventGroupHandle_t s_wifi_event_group;

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

static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < 5) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG,"connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
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
    convertToLowercase(mac_str);
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

    printf("---->  %s\n", cJSON_Print(body));

    const cJSON* username = cJSON_GetObjectItemCaseSensitive(body, "username");
    const cJSON* password = cJSON_GetObjectItemCaseSensitive(body, "password");

    if (!cJSON_IsString(username) || !cJSON_IsString(password)) {
        httpd_resp_send(req, "Internal Server Error", strlen("Internal Server Error"));
        goto BadRequest;
    }

    if (strcmp(username->valuestring, "admin") != 0 || strcmp(password->valuestring, "luci123") != 0) {
        httpd_resp_send(req, "Internal Server Error", strlen("Internal Server Error"));
        goto BadRequest;
    }

    // Generate token and expireTime
    snprintf(token.token, sizeof(token.token), generateRandomString(TOKEN_LENGTH));
    ESP_LOGI(TAG, "%s", token.token);
    ESP_LOGI(TAG, "size of token is %d", sizeof(token.token));
    token.expireTime = 3600;
    token.startTime = time(NULL);
    
    cJSON* token_obj = cJSON_CreateObject();

    cJSON_AddNumberToObject(token_obj, "expireTime", token.expireTime);
    cJSON_AddStringToObject(token_obj, "mac", mac_str); //mac device
    cJSON_AddStringToObject(token_obj, "timezone", "Asia/Ho Chi Minh"); //timezone
    cJSON_AddStringToObject(token_obj, "token", token.token);

    cJSON_AddItemToObject(response, "data", token_obj);

    cJSON_AddNumberToObject(response, "statusCode", 200);
    cJSON_AddStringToObject(response, "statusMessage", "OK");
    cJSON_AddTrueToObject(response, "success");

    char* response_str = cJSON_PrintUnformatted(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));

    ESP_LOGI(TAG, "<---- %s", response_str);

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

static esp_err_t HandlerWifiList(httpd_req_t *req) {
    if (req->method != HTTP_GET) {
        httpd_resp_send(req, "Internal Server Error", strlen("Method not supported"));
        goto BadRequest;
    }

    uint16_t number = 20;
    wifi_ap_record_t ap_info[20];
    uint16_t ap_count = 0;
    memset(ap_info, 0, sizeof(ap_info));
    esp_wifi_scan_start(NULL, true);
    esp_err_t scan_result = esp_wifi_scan_start(NULL, true);
    if (scan_result != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi scan failed with error code %d", scan_result);
    }

    ESP_LOGI(TAG, "Max AP number ap_info can hold = %u", number);
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    ESP_LOGI(TAG, "Total APs scanned = %u, actual AP number ap_info holds = %u", ap_count, number);

    cJSON* data_array = cJSON_CreateArray();

    for (int i = 0; i < number; i++) {
        cJSON* ap_object = cJSON_CreateObject();
        cJSON_AddStringToObject(ap_object, "bssid", (const char*)ap_info[i].bssid);
        cJSON_AddStringToObject(ap_object, "encryption", wifi_auth_mode_to_str(ap_info[i].authmode));
        cJSON_AddStringToObject(ap_object, "name", (const char*)ap_info[i].ssid);
        cJSON_AddNumberToObject(ap_object, "password", 0);  // You may need to implement logic to determine password presence
        cJSON_AddNumberToObject(ap_object, "signal", ap_info[i].rssi);

        cJSON_AddItemToArray(data_array, ap_object);
    }

    cJSON* response = cJSON_CreateObject();
    cJSON_AddItemToObject(response, "data", data_array);
    cJSON_AddTrueToObject(response, "success");
    cJSON_AddNumberToObject(response, "statusCode", 200);
    cJSON_AddStringToObject(response, "statusMessage", "OK");

    char* response_str = cJSON_PrintUnformatted(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));

    ESP_LOGI(TAG, "<---- %s", response_str);

    free(response_str);
    cJSON_Delete(response);

    BadRequest:

    return ESP_OK;
}

static esp_err_t HandlerWifiConfig(httpd_req_t *req){
    getMacAddress(mac_addr);
    char mac_str[18]; 
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
         mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    convertToLowercase(mac_str);
    cJSON* body = NULL;
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

    printf("---->  %s\n", cJSON_Print(body));

    const cJSON* ssidItem = cJSON_GetObjectItemCaseSensitive(body, "ssid");
    const cJSON* passwordItem = cJSON_GetObjectItemCaseSensitive(body, "password");
    const cJSON* networkModeItem = cJSON_GetObjectItemCaseSensitive(body, "network_mode");
    
    if (!cJSON_IsString(ssidItem) || !cJSON_IsString(passwordItem)) {
        httpd_resp_send(req, "Internal Server Error", strlen("Internal Server Error"));
        goto BadRequest;
    }

    //network_mode: 0 is dhcp
    //netowkr_mode: 1 is static_info

    const char *ssid = ssidItem->valuestring;
    const char *password = passwordItem->valuestring;
    int networkMode = cJSON_IsTrue(networkModeItem) ? 1 : 0;

    cJSON* response = cJSON_CreateObject();
    cJSON* network_session_config = cJSON_CreateObject();

    cJSON_AddStringToObject(network_session_config, "authorized_code", mac_str);
    cJSON_AddStringToObject(network_session_config, "network_session_config", "SmartHomeInit");

    cJSON_AddItemToObject(response, "data", network_session_config);

    cJSON_AddNumberToObject(response, "statusCode", 200);
    cJSON_AddStringToObject(response, "statusMessage", "OK");
    cJSON_AddTrueToObject(response, "success");

    char* response_str = cJSON_PrintUnformatted(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));

    ESP_LOGI(TAG, "<---- %s", response_str);

    vTaskDelay(pdMS_TO_TICKS(1500));
    wifi_configure(ssid, password, networkMode);

    // free(request_body);
    cJSON_Delete(response);
    cJSON_Delete(body);
    free(response_str);  // Free the memory allocated by cJSON_PrintUnformatted
    return ESP_OK;

    BadRequest:
    cJSON_Delete(body);
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

static const httpd_uri_t userLogin_uri = {
    .uri       = "/user/login",
    .method    = HTTP_POST,
    .handler   = HandlerUserLogin,
    .user_ctx  = NULL
};

static const httpd_uri_t wifiList_uri = {
    .uri       = "/wifi/list",
    .method    = HTTP_GET,
    .handler   = HandlerWifiList,
    .user_ctx  = NULL
};

static const httpd_uri_t wifiConfig_uri = {
    .uri       = "/wifi/config",
    .method    = HTTP_POST,
    .handler   = HandlerWifiConfig,
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

static httpd_handle_t https_server_init(uint16_t port)
{
    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    config.port_secure = port;

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
    httpd_register_uri_handler(server, &userLogin_uri);
    httpd_register_uri_handler(server, &wifiList_uri);
    httpd_register_uri_handler(server, &wifiConfig_uri);
    httpd_register_uri_handler(server, &network_uri);
    httpd_register_uri_handler(server, &scan_uri);
    return server;
}

static httpd_handle_t https_sta_server_init(void)
{
    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    config.port_secure = 443;

    extern const unsigned char staservercert_pem_start[] asm("_binary_staservercert_pem_start");
    extern const unsigned char staservercert_pem_end[] asm("_binary_staservercert_pem_end");
    config.servercert = staservercert_pem_start;
    config.servercert_len = staservercert_pem_end - staservercert_pem_start;

    extern const unsigned char key_pem_start[] asm("_binary_key_pem_start");
    extern const unsigned char key_pem_end[] asm("_binary_key_pem_end");
    config.prvtkey_pem = key_pem_start;
    config.prvtkey_len = key_pem_end - key_pem_start;

    esp_err_t ret = httpd_ssl_start(&sta_server, &config);
    if(ESP_OK != ret)
    {
        ESP_LOGI(TAG, "Error starting server!");
        return NULL;
    }
    return sta_server;
}

void wifi_init_softap(void)
{
    getMacAddress(mac_addr);
    char mac_str[8]; 
    snprintf(mac_str, sizeof(mac_str), "HC%02X%02X",
         mac_addr[4], mac_addr[5]);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,
                                                ESP_EVENT_ANY_ID,
                                                &wifi_event_handler,
                                                NULL));
                                                    
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    char SSID[18];
    strcpy(SSID, "ESP_");
    strcat(SSID, mac_str);

    wifi_config_t wifi_config = {
        .ap = {
            .channel = ESP_WIFI_CHANNEL,
            .password = "ABC123456",
            .max_connection = MAX_STA_CONN,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                    .required = true,
            },
        },
    };

    // Copy the SSID into the ssid field of wifi_config_t
    strncpy((char*)wifi_config.ap.ssid, SSID, sizeof(wifi_config.ap.ssid) - 1);
    wifi_config.ap.ssid[sizeof(wifi_config.ap.ssid) - 1] = '\0';
    wifi_config.ap.ssid_len = strlen((char*)wifi_config.ap.ssid);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    char* ip = SOFTAP_IP;
    // char* gateway = "10.10.10.254";
    // char* netmask = "255.255.255.0";
    esp_netif_ip_info_t info_t;
    memset(&info_t, 0, sizeof(esp_netif_ip_info_t));

    if (ap_netif)
    {
        ESP_ERROR_CHECK(esp_netif_dhcps_stop(ap_netif));
        info_t.ip.addr = esp_ip4addr_aton((const char *)ip);
        // info_t.netmask.addr = esp_ip4addr_aton((const char *)netmask);
        // info_t.gw.addr = esp_ip4addr_aton((const char *)gateway);
        esp_netif_set_ip_info(ap_netif, &info_t);
        ESP_ERROR_CHECK(esp_netif_dhcps_start(ap_netif));
    }
    https_server_init(3001);
    ESP_LOGI(TAG, "wifi_init_softap finished. SSID:%s",
             SSID);
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

void convertToLowercase(char *str) {
    while (*str) {
        *str = tolower((unsigned char)*str);
        str++;
    }
}

const char* wifi_auth_mode_to_str(wifi_auth_mode_t auth_mode) {
    switch (auth_mode) {
        case WIFI_AUTH_OPEN:
            return "Open";
        case WIFI_AUTH_WEP:
            return "WEP";
        case WIFI_AUTH_WPA_PSK:
            return "WPA-PSK";
        case WIFI_AUTH_WPA2_PSK:
            return "WPA2-PSK";
        case WIFI_AUTH_WPA_WPA2_PSK:    
            return "WPA/WPA2-PSK";
        case WIFI_AUTH_WPA2_ENTERPRISE:
            return "WPA2-Enterprise";
        default:
            return "Unknown";
    }
}

void wifi_configure(const char *ssid, const char *pass, int networkMode){
    
    // ESP_ERROR_CHECK(esp_wifi_stop());
    // ESP_ERROR_CHECK(esp_wifi_deinit());
    esp_wifi_disconnect();
    esp_wifi_stop();
    esp_wifi_set_mode(WIFI_MODE_NULL);

    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());

    //ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));


    // Configure WiFi with SSID and password
    wifi_config_t wifi_config = {
        .sta = {
            /* Setting a password implies station will connect to all security modes including WEP/WPA.
             * However these modes are deprecated and not advisable to be used. Incase your Access point
             * doesn't support WPA2, these mode can be enabled by commenting below line */
            .threshold.authmode = WIFI_AUTH_WPA_WPA2_PSK,
            .pmf_cfg = {
                .capable = true,
                .required = false
            },
        },
    };
    strncpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
    wifi_config.sta.ssid[sizeof(wifi_config.sta.ssid) - 1] = '\0';

    strncpy((char *)wifi_config.sta.password, pass, sizeof(wifi_config.sta.password));
    wifi_config.sta.password[sizeof(wifi_config.sta.password) - 1] = '\0';


    ESP_LOGI(TAG, "SSID buffer size: %d", sizeof(wifi_config.sta.ssid));
    ESP_LOGI(TAG, "Password buffer size: %d", sizeof(wifi_config.sta.password));

    
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    
    ESP_LOGI(TAG, "wifi_init_sta finished.");

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            false,
            false,
            1000);

    ESP_LOGI(TAG, "ssid: %s", wifi_config.sta.ssid);
    ESP_LOGI(TAG, "password: %s", wifi_config.sta.password);

    httpd_ssl_stop(&server);
    https_sta_server_init();

    if (bits & WIFI_CONNECTED_BIT) {
    ESP_LOGI(TAG, "connected to Wifi");
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGI(TAG, "Failed to connect to WiFi");
    } else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
    }

    if (networkMode == 1) {
        //DHCP mode
    }else if (networkMode == 0) {
        //Static mode
    }
    
    get_sta_ip();
    ESP_LOGI(TAG, "Start Wifi as STA mode");
}

void get_sta_ip() {
    esp_netif_ip_info_t ip_info;

    // Get the IP information for the STA interface
    esp_netif_get_ip_info(esp_netif_get_handle_from_ifkey("WIFI_STA_DEF"), &ip_info);

    // Convert IP address to string
    char ip_str[16];
    esp_ip4addr_ntoa(&ip_info.ip, ip_str, sizeof(ip_str));

    ESP_LOGI("get_sta_ip", "STA IP Address: %s", ip_str);
}