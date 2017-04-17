/*
 * Here's what we are going to do.
 * Deep sleep. Wake up every 1 minute or so.
 * Enable Wifi and bluetooth. Let it search for x seconds for access points
 * Freez results and store them
 * Collect and store:
 *  * wifi: BSSID (mac), channel, SSID (str), RSSI [dBm]
 *  * bluetooth: macAddress (6 bytes), name of beacon, RSSI [dBm]
 *
 */
//----------------------------------
// MLS request
//----------------------------------
//{
//    "considerIp": false,
//    "bluetoothBeacons": [
//        {
//            "macAddress": "ff:23:45:67:89:ab",
//            "age": 2000,
//            "name": "beacon",
//            "signalStrength": -110
//        }
//    ],
//    "cellTowers": [{
//        "radioType": "wcdma",
//        "mobileCountryCode": 208,
//        "mobileNetworkCode": 1,
//        "locationAreaCode": 2,
//        "cellId": 1234567,
//        "age": 1,
//        "psc": 3,
//        "signalStrength": -60,
//        "timingAdvance": 1
//    }],
//    "wifiAccessPoints": [{
//        "macAddress": "01:23:45:67:89:ab",
//        "age": 3,
//        "channel": 11,
//        "frequency": 2412,
//        "signalStrength": -51,
//        "signalToNoiseRatio": 13
//    }, {
//        "macAddress": "01:23:45:67:89:cd"
//    }],
//    "fallbacks": {
//        "lacf": true,
//        "ipf": true
//    }
//}

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "driver/adc.h"
#include "esp_log.h"
#include <string.h>

#include "lwip/inet.h"
#include "lwip/ip4_addr.h"
#include "lwip/dns.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "rom/queue.h"
#include "dnsSneaker.h"

#include "main.h"

static const char* TAG = "main.c";

EventGroupHandle_t g_wifi_event_group;
#define CONNECTED_BIT 		 (1<<0)
#define DNS_DONE_BIT 		 (1<<1)

#define MAX_CACHE_RESULTS    75			// Store N scan results in RTC mem
#define MAX_WIFIS_PER_RESULT 6			// Only the N strongest wifis are stored per scan result
#define MAX_WIFIS_PER_SCAN   32			// Scan up to N wifis

struct wifiId_t{
	uint8_t bssid[6];                     /**< MAC address of AP */
	uint8_t primary;                      /**< channel of AP */
	int8_t  rssi;                         /**< signal strength of AP */
};

struct scanResult_t {
	struct wifiId_t wifiIds[MAX_WIFIS_PER_RESULT];
	uint32_t timestamp;
};

RTC_DATA_ATTR struct scanResult_t g_scanResults[MAX_CACHE_RESULTS];
RTC_DATA_ATTR uint16_t g_scanResultWritePointer;	//Points to next free entry
RTC_DATA_ATTR struct timeval g_startTime;

static void printWifiId( struct wifiId_t *id ){
	for( uint8_t i=0; i<MAX_WIFIS_PER_RESULT; i++ ){
		if( id->primary == 0xFF ){
			break;
		}
		ESP_LOGI( TAG, "    %2x:%2x:%2x:%2x:%2x:%2x | %2d | %3d", id->bssid[0],id->bssid[1],id->bssid[2],id->bssid[3],id->bssid[4],id->bssid[5], id->primary, id->rssi );
		id++;
	}
}

static void printRtcMem(){
	struct scanResult_t *temp = g_scanResults;
	for( uint16_t i=0; i<MAX_CACHE_RESULTS; i++ ){
		if( temp->timestamp == 0xFFFFFFFF ){
			break;
		}
		ESP_LOGI( TAG, "%6d [", temp->timestamp );
		printWifiId( temp->wifiIds );
		ESP_LOGI( TAG, "]");
		temp++;
	}
}

static uint16_t countRtcMem(){
	struct scanResult_t *temp = g_scanResults;
	uint16_t nItems = 0;
	for( uint16_t i=0; i<MAX_CACHE_RESULTS; i++ ){
		if( temp++->timestamp == 0xFFFFFFFF ){
			break;
		}
		nItems++;
	}
	return nItems;
}

static void addWifis( wifi_ap_record_t *wifis, uint8_t nFound ){
	struct scanResult_t *srTemp;
	struct wifiId_t *wifiTemp;
	struct timeval currentTime;
	gettimeofday(&currentTime, NULL);
	ESP_LOGI( TAG, "Found %d access points:", nFound);
	if( nFound <= 0 ){
		return;
	}
	srTemp = &g_scanResults[g_scanResultWritePointer];
	srTemp->timestamp = currentTime.tv_sec - g_startTime.tv_sec;
	wifiTemp = srTemp->wifiIds;
	for( uint8_t i=0; i<nFound; i++ ){
		ESP_LOGI( TAG, "%32s | %7d | %4d | %d", ((char *)wifis->ssid), wifis->primary, wifis->rssi, wifis->authmode );
		if( i<MAX_WIFIS_PER_RESULT ){				//Add the first 6 found wifis to RTC mem
			wifiTemp->primary = wifis->primary;
			wifiTemp->rssi = wifis->rssi;
			memcpy( wifiTemp->bssid, wifis->bssid, 6 );
			wifiTemp++;
		}
		wifis++;
	}
	// Increment and wrap around circular buffer
	if( ++g_scanResultWritePointer >= MAX_CACHE_RESULTS ){
		g_scanResultWritePointer = 0;
	}
}

static wifi_ap_record_t *findWifiCandidate( wifi_ap_record_t *wifis, uint8_t nFound ){
	if( countRtcMem() < 1 ){
		return NULL;
	}
	for( uint8_t i=0; i<nFound; i++ ){
		if( wifis->authmode==WIFI_AUTH_OPEN ){
			return wifis;
		}
		wifis++;
	}
	return NULL;
}

static void initStuff(){
	g_wifi_event_group = xEventGroupCreate();
	// Init LED port
	gpio_pad_select_gpio( LED_GPIO );
	ESP_ERROR_CHECK( gpio_set_direction( LED_GPIO, GPIO_MODE_OUTPUT ) );
	gpio_set_level( LED_GPIO, 0 );
	// Init BUCK port
	gpio_pad_select_gpio( BUCK_GPIO );
	ESP_ERROR_CHECK( gpio_set_direction( BUCK_GPIO, GPIO_MODE_OUTPUT ) );
	gpio_set_level( BUCK_GPIO, 0 );
	// Init RTC Memory (only on initial power up)
	if ( esp_deep_sleep_get_wakeup_cause() == ESP_DEEP_SLEEP_WAKEUP_UNDEFINED ){
		memset( g_scanResults, 0xFF, sizeof(g_scanResults) );
		g_scanResultWritePointer = 0;
	    gettimeofday(&g_startTime, NULL);
	}
}

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch(event->event_id) {
       case SYSTEM_EVENT_STA_GOT_IP:
           xEventGroupSetBits( g_wifi_event_group, CONNECTED_BIT );
           break;
       default:
           break;
   }
   return ESP_OK;
}

static void doWifiScan( void *pvParameters ){
	uint8_t dnsBuffer[256];
    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));		//Startup WIFI as a client
    ESP_ERROR_CHECK( esp_wifi_set_ps(WIFI_PS_MODEM) );
    ESP_ERROR_CHECK( esp_wifi_start() );
    wifi_scan_config_t scanConfig = {						//Define a scan filter
		.ssid = 0,
		.bssid = 0,
		.channel = 0,
		.show_hidden = true,
		.scan_type = WIFI_SCAN_TYPE_ACTIVE
    };
	gpio_set_level( LED_GPIO, 1 );
    ESP_ERROR_CHECK( esp_wifi_scan_start( &scanConfig, 1 ) );
	gpio_set_level( LED_GPIO, 0 );

	//-----------------------------------------------
	// Do a wifi scan (~1.5 s)
	//-----------------------------------------------
    wifi_ap_record_t myResultItems[MAX_WIFIS_PER_SCAN];
    uint16_t nWifiStations = MAX_WIFIS_PER_SCAN;
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&nWifiStations, myResultItems));
    //-----------------------------------------------
    // Store scan result in RTC mem
    //-----------------------------------------------
    addWifis( myResultItems, nWifiStations );
//    printRtcMem();
    ESP_LOGI(TAG,"Cached items: %d", countRtcMem());
    //-----------------------------------------------
	// Check if there is a wifi candidate to phone home
	//-----------------------------------------------
    wifi_ap_record_t *wifiCandidate = findWifiCandidate( myResultItems, nWifiStations );
    if( wifiCandidate != NULL ){
        wifi_config_t cfg;
        memcpy( cfg.sta.ssid, wifiCandidate->ssid, 32 );
        memcpy( cfg.sta.bssid, wifiCandidate->bssid, 6 );
        cfg.sta.bssid_set = true;
    	ESP_LOGI( TAG, "Phoning home on %s ...", cfg.sta.ssid );
        ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_STA, &cfg) );
        ESP_ERROR_CHECK( esp_wifi_connect() );
        // Wait for active IP connection
		if( xEventGroupWaitBits(g_wifi_event_group, CONNECTED_BIT, true, true, 10000/portTICK_PERIOD_MS) & CONNECTED_BIT ){
			ESP_LOGI( TAG, "Connected !!!");
			uint8_t testStr[] = "Wow, this is a very long request String!. Let's see if it passes!!!";
//			dnsEncode( wifiCandidate->ssid, strlen((char*)wifiCandidate->ssid), dnsBuffer );
			dnsEncode( testStr, sizeof(testStr), dnsBuffer );
			dnsSend( dnsBuffer );
		} else {
			ESP_LOGI( TAG, "Connection timeout");
		}
		esp_wifi_disconnect();
    }

    // We are done, sleep and reset
    ESP_LOGI( TAG, "ZzzZZZzZZzzZZ");
    esp_deep_sleep_enable_timer_wakeup( 10000*1000 );
	esp_deep_sleep_start();
}

void app_main(void)
{
	ESP_LOGI( TAG, "WifiScanner started" );
	ESP_ERROR_CHECK( nvs_flash_init() );
	initStuff();
	xTaskCreate(&doWifiScan,   "doWifiScan",   4096*2, NULL, 5, NULL);
}

