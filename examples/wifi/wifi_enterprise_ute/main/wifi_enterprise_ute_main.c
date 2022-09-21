/*
 * SPDX-FileCopyrightText: 2022 Janfred
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* WiFi Connection Example using WPA2 Enterprise using EAP-NOOB
 */

#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_wpa2.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_netif.h"

static EventGroupHandle_t wifi_event_group;
static esp_netif_t *sta_netif = NULL;

const int CONNECTED_BIT = BIT0;

static const char *TAG = "example";

static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
    }
}

static void initialize_wifi(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    sta_netif = esp_netif_create_default_wifi_sta();
    assert(sta_netif);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL) );
    ESP_ERROR_CHECK( esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = "eduroam"
        }
    };

    ESP_LOGI(TAG, "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK( esp_wifi_sta_wpa2_ent_set_identity((uint8_t *)"initial@eap-ute.arpa", strlen("initial@eap-ute.arpa")) );
    ESP_ERROR_CHECK( esp_wifi_sta_wpa2_ent_eap_ute_set_initial_association() );
    ESP_ERROR_CHECK( esp_wifi_sta_wpa2_ent_enable() );
    ESP_ERROR_CHECK( esp_wifi_start() );
}

static void wpa2_enterprise_example_task(void *pvParameters)
{
    esp_netif_ip_info_t ip;
    memset(&ip, 0, sizeof(esp_netif_ip_info_t));
    vTaskDelay(2000 / portTICK_PERIOD_MS);

    while (1) {
        vTaskDelay(2000 / portTICK_PERIOD_MS);

        if ( esp_wifi_sta_wpa2_ent_eap_ute_oob_pending() ) {
            esp_eap_ute_oob_msg_t *oobmsg = esp_wifi_sta_wpa2_ent_eap_ute_generate_oob_msg();
            char *auth_str = malloc(65);
            char *nonce_str = malloc(65);
            char *oobid_str = malloc(33);
            char *peeridstr = malloc(33);
            uint8_t *peerid = esp_wifi_sta_wpa2_ent_eap_ute_get_peerid();

            for (int i = 0; i < 32; i++) {
                snprintf(auth_str + i * 2, 3, "%02x", oobmsg->auth[i]);
                snprintf(nonce_str + i * 2, 3, "%02x", oobmsg->nonce[i]);
            }
            for (int i = 0; i < 16; i++) {
                snprintf(oobid_str + i * 2, 3, "%02x", oobmsg->oob_id[i]);
                snprintf(peeridstr + i * 2, 3, "%02x", peerid[i]);
            }



            ESP_LOGI(TAG, "OOBMsg");
            ESP_LOGI(TAG, "Auth:  %s", auth_str);
            ESP_LOGI(TAG, "Nonce: %s", nonce_str);
            ESP_LOGI(TAG, "OOBId: %s", oobid_str);
            ESP_LOGI(TAG, "PeerId: %s", peeridstr);

            free(auth_str);
            free(nonce_str);
            free(oobid_str);
            free(peeridstr);
            free(peerid);
        }

        if (esp_netif_get_ip_info(sta_netif, &ip) == 0) {
            ESP_LOGI(TAG, "~~~~~~~~~~~");
            ESP_LOGI(TAG, "IP:"IPSTR, IP2STR(&ip.ip));
            ESP_LOGI(TAG, "MASK:"IPSTR, IP2STR(&ip.netmask));
            ESP_LOGI(TAG, "GW:"IPSTR, IP2STR(&ip.gw));
            ESP_LOGI(TAG, "~~~~~~~~~~~");
        }
    }
}

int app_main(void)
{
    esp_log_level_set("*", ESP_LOG_VERBOSE);
    ESP_ERROR_CHECK( nvs_flash_init() );
    initialize_wifi();
    xTaskCreate(&wpa2_enterprise_example_task, "wpa2_enterprise_example_task", 4096, NULL, 5, NULL);
    return 0;
}
