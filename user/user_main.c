/*
 * ESPRSSIF MIT License
 *
 * Copyright (c) 2015 <ESPRESSIF SYSTEMS (SHANGHAI) PTE LTD>
 *
 * Permission is hereby granted for use on ESPRESSIF SYSTEMS ESP8266 only, in which case,
 * it is free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "esp_common.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"
#include "espressif/espconn.h"
#include "cjson.h"
#include "../include/gpio.h"

#define server_ip "192.168.101.142"
#define server_port 9669

#define GPIO_SWITCH GPIO_Pin_2
#define GPIO_SWITCH_ON 0
#define GPIO_SWITCH_OFF 1

/******************************************************************************
 * FunctionName : user_rf_cal_sector_set
 * Description  : SDK just reversed 4 sectors, used for rf init data and paramters.
 *                We add this function to force users to set rf cal sector, since
 *                we don't know which sector is free in user's application.
 *                sector map for last several sectors : ABCCC
 *                A : rf cal
 *                B : rf init data
 *                C : sdk parameters
 * Parameters   : none
 * Returns      : rf cal sector
*******************************************************************************/
uint32 user_rf_cal_sector_set(void)
{
    flash_size_map size_map = system_get_flash_size_map();
    uint32 rf_cal_sec = 0;

    switch (size_map) {
        case FLASH_SIZE_4M_MAP_256_256:
            rf_cal_sec = 128 - 5;
            break;

        case FLASH_SIZE_8M_MAP_512_512:
            rf_cal_sec = 256 - 5;
            break;

        case FLASH_SIZE_16M_MAP_512_512:
        case FLASH_SIZE_16M_MAP_1024_1024:
            rf_cal_sec = 512 - 5;
            break;

        case FLASH_SIZE_32M_MAP_512_512:
        case FLASH_SIZE_32M_MAP_1024_1024:
            rf_cal_sec = 1024 - 5;
            break;
        case FLASH_SIZE_64M_MAP_1024_1024:
            rf_cal_sec = 2048 - 5;
            break;
        case FLASH_SIZE_128M_MAP_1024_1024:
            rf_cal_sec = 4096 - 5;
            break;
        default:
            rf_cal_sec = 0;
            break;
    }

    return rf_cal_sec;
}

void scan_done(void *arg, STATUS status)
{
	uint8 ssid[33];
	char temp[128];
	if (status == OK) {
		struct bss_info *bss_link = (struct bss_info *)arg;
		while (bss_link != NULL) {
			memset(ssid, 0, 33);
			if (strlen(bss_link->ssid) <= 32)
				memcpy(ssid, bss_link->ssid, strlen(bss_link->ssid));
			else
				memcpy(ssid, bss_link->ssid, 32);
			printf("(%d,\"%s\",%d,\""MACSTR"\",%d)\r\n",
			bss_link->authmode, ssid, bss_link->rssi,
			MAC2STR(bss_link->bssid),bss_link->channel);
			bss_link = bss_link->next.stqe_next;
		}

		struct station_config *config = zalloc(sizeof(struct station_config));

		wifi_station_get_config(config);
		printf("auto connect %d\n", wifi_station_get_auto_connect());
		printf("config: %s %s %d\n", config->ssid, config->password, config->bssid_set);
		wifi_station_get_config_default(config);
		printf("config: %s %s %d\n", config->ssid, config->password, config->bssid_set);

		sprintf(config->ssid, "yangliu");
		sprintf(config->password, "yangliujiezou");

	    wifi_station_scan(NULL, scan_done);

	    wifi_station_set_config(config);

	    free(config);

	    wifi_station_connect();
	} else {
		printf("scan fail !!!\r\n");
	}
}

void wifi_handle_event_cb(System_Event_t *evt)
{
	printf("event %x\n", evt->event_id);
	switch (evt->event_id) {
		case EVENT_STAMODE_CONNECTED:
			printf("connect to ssid %s, channel %d\n",
			evt->event_info.connected.ssid,
			evt->event_info.connected.channel);
		break;
		case EVENT_STAMODE_DISCONNECTED:
			printf("disconnect from ssid %s, reason %d\n",
			evt->event_info.disconnected.ssid,
			evt->event_info.disconnected.reason);
		break;
		case EVENT_STAMODE_AUTHMODE_CHANGE:
			printf("mode: %d -> %d\n",
			evt->event_info.auth_change.old_mode,
			evt->event_info.auth_change.new_mode);
		break;
		case EVENT_STAMODE_GOT_IP:
			printf("ip:" IPSTR ",mask:" IPSTR ",gw:" IPSTR,
			IP2STR(&evt->event_info.got_ip.ip),
			IP2STR(&evt->event_info.got_ip.mask),
			IP2STR(&evt->event_info.got_ip.gw));
			printf("\n");
		break;
		case EVENT_SOFTAPMODE_STACONNECTED:
			printf("station: " MACSTR "join, AID = %d\n",
			MAC2STR(evt->event_info.sta_connected.mac),
			evt->event_info.sta_connected.aid);
		break;
		case EVENT_SOFTAPMODE_STADISCONNECTED:
			printf("station: " MACSTR "leave, AID = %d\n",
			MAC2STR(evt->event_info.sta_disconnected.mac),
			evt->event_info.sta_disconnected.aid);
		break;
		default:
		break;
	}
}

void smartconfig_done(sc_status status, void *pdata)
{
    switch(status) {
        case SC_STATUS_WAIT:
            printf("SC_STATUS_WAIT\n");
            break;
        case SC_STATUS_FIND_CHANNEL:
            printf("SC_STATUS_FIND_CHANNEL\n");
            break;
        case SC_STATUS_GETTING_SSID_PSWD:
            printf("SC_STATUS_GETTING_SSID_PSWD\n");
            sc_type *type = pdata;
            if (*type == SC_TYPE_ESPTOUCH) {
                printf("SC_TYPE:SC_TYPE_ESPTOUCH\n");
            } else {
                printf("SC_TYPE:SC_TYPE_AIRKISS\n");
            }
            break;
        case SC_STATUS_LINK:
            printf("SC_STATUS_LINK\n");
            struct station_config *sta_conf = pdata;

	        wifi_station_set_config(sta_conf);
	        wifi_station_disconnect();
	        wifi_station_connect();
            break;
        case SC_STATUS_LINK_OVER:
            printf("SC_STATUS_LINK_OVER\n");
            if (pdata != NULL) {
				//SC_TYPE_ESPTOUCH
                uint8 phone_ip[4] = {0};

                memcpy(phone_ip, (uint8*)pdata, 4);
                printf("Phone ip: %d.%d.%d.%d\n",phone_ip[0],phone_ip[1],phone_ip[2],phone_ip[3]);
            } else {
            	//SC_TYPE_AIRKISS - support airkiss v2.0
				//airkiss_start_discover();
			}
            smartconfig_stop();
            break;
    }
}

char * get_switch_status(void)
{
	if (GPIO_GET_OUTPUT(GPIO_SWITCH) == GPIO_SWITCH_ON) {
		return "ON";
	}
	else
	{
		return "OFF";
	}
}

char * requestHeader =
		"POST /smartdevice_cloud_service/connect HTTP/1.1\r\n"
		"Host: www.ai-keys.com:8080\r\n"
		"User-Agent: curl/7.47.0\r\n"
		"Accept: */*\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"\r\n"
		"%s";

char * reportState_template =
		"{"
			"'name_space':'Alexa',"
			"'name':'ReportState',"
			"'deviceId':'%s',"
			"'properties':["
				"{'name_space':'Alexa.PowerController','name':'powerState','value':'%s'},"
				"{'name_space':'Alexa.EndpointHealth','name':'connectivity','value':{'value':'OK'}}"
			"]"
		"}";

char *powerController_template =
		"{"
			"'name_space':'Alexa',"
			"'name':'Response',"
			"'deviceId':'%s',"
			"'properties':["
				"{'name_space':'Alexa.PowerController','name':'powerState','value':'%s'},"
				"{'name_space':'Alexa.EndpointHealth','name':'connectivity','value':{'value':'OK'}}"
			"]"
		"}";

char buf[1024];
char device_id_str[13];
uint16_t buf_len;
LOCAL void tcp_task(void *pvParameters)
{
	struct sockaddr_in server_addr;
	int ret;
	int fd;
	char * json;
	cJSON *cjson;
	cJSON *cjsonTmp;
	char * tmp;

	wifi_get_macaddr(0, buf);
	sprintf(device_id_str, "%02X%02X%02X%02X%02X%02X", buf[0], buf[1],
			buf[2], buf[3], buf[4], buf[5]);
	printf("mac: %s\n", device_id_str);

	struct station_config *config = zalloc(sizeof(struct station_config));

	wifi_station_get_config(config);
	printf("auto connect %d\n", wifi_station_get_auto_connect());
	printf("config: %s %s %d\n", config->ssid, config->password, config->bssid_set);
	wifi_station_get_config_default(config);
	printf("config: %s %s %d\n", config->ssid, config->password, config->bssid_set);

	if (!strlen(config->ssid))
		smartconfig_start(smartconfig_done);

	free(config);

	/*//wifi_station_scan(NULL, scan_done);
	//vTaskDelay(500);
	/*GPIO_OUTPUT_SET(2, 0);
	vTaskDelay(100);
	GPIO_OUTPUT_SET(2, 1);
	vTaskDelay(100);*/
	//smartconfig_start(smartconfig_done);

	while(1)
	{
		if (wifi_station_get_connect_status() != STATION_GOT_IP)
		{
			vTaskDelay(100);
			continue;
		}

		struct hostent * h = gethostbyname("www.ai-keys.com");
		if(!h)
		{
			printf("error: gethostbyname\n");
			vTaskDelay(100);
			continue;
		}

		printf("%d\n", h->h_addrtype);
		for(ret = 0; h->h_aliases[ret]; ret++)
		{
			printf("%s\n", h->h_aliases[ret]);
		}
		for(ret = 0; h->h_addr_list[ret]; ret++)
		{
			printf("ip %s\n", inet_ntoa(*(unsigned int*)h->h_addr_list[ret]));
		}

		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd == -1)
		{
			close(fd);
			printf("error: socket\n");
			vTaskDelay(200);
			continue;
		}

		ret = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &ret, sizeof(ret)) != 0)
		{
			printf("error: SO_KEEPALIVE\n");
		}

		ret = 60000;
		if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &ret, sizeof(ret)))
		{
			printf("error: TCP_KEEPALIVE\n");
		}
		ret = 60;
		if(setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &ret, sizeof(ret)))
		{
			printf("error: TCP_KEEPIDLE\n");
		}
		ret = 10;
		if(setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &ret, sizeof(ret)))
		{
			printf("error: TCP_KEEPINTVL\n");
		}
		ret = 3;
		if(setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &ret, sizeof(ret)))
		{
			printf("error: TCP_KEEPCNT\n");
		}

		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = *(in_addr_t*)h->h_addr_list[0]; //inet_addr("192.168.3.55");
		server_addr.sin_port = htons(8080);

		ret = connect(fd, (const struct sockaddr *)&server_addr, sizeof(struct sockaddr));
		if (ret) {
			printf("connect fail retry %d\n", ret);
			close(fd);
			vTaskDelay(200);
			continue;
		}

		char * reportState = malloc(300);
		uint16_t reportStateLen = sprintf(reportState, reportState_template, device_id_str, get_switch_status());

		buf_len = sprintf(buf, requestHeader, strlen(reportState), reportState);

		free(reportState);

		printf("ss: %s\n", buf);

		send(fd, buf, buf_len, 0);

		while(1)
		{
			buf_len = recv(fd, buf, 1024, 0);
			if (buf_len > 0)
			{
				buf[buf_len] = 0;
				printf("recv: %s", buf);
				if ((json = strchr(buf, '{')) != NULL) {
					if ((cjson = cJSON_Parse(json)) != NULL) {
						cjsonTmp = cJSON_GetObjectItem(cjson, "name");
						if (cjsonTmp) {
							printf("name: %s\n", cjsonTmp->valuestring);
							if (strcmp(cjsonTmp->valuestring, "TurnOn") == 0) {
								GPIO_OUTPUT_SET(2, 0);
								buf_len = sprintf(buf, powerController_template, device_id_str, get_switch_status());
								printf("%d %s\n", buf_len, buf);
							}
							else if (strcmp(cjsonTmp->valuestring, "TurnOff") == 0){
								GPIO_OUTPUT_SET(2, 1);
								buf_len = sprintf(buf, powerController_template, device_id_str, get_switch_status());
								printf("%d %s\n", buf_len, buf);
							}
							else if (strcmp(cjsonTmp->valuestring, "ReportState") == 0){
								reportStateLen = sprintf(buf, reportState_template, device_id_str, get_switch_status());
								printf("%d %s\n", buf_len, buf);
							}
						}

						cJSON_Delete(cjson);
					}
				}
			}
			else
			{
				printf("recv fail %d\n", buf_len);
				close(fd);
				break;
			}
		}
	}

    vTaskDelete(NULL);
}

/******************************************************************************
 * FunctionName : user_init
 * Description  : entry of user application, init user function here
 * Parameters   : none
 * Returns      : none
*******************************************************************************/
void ICACHE_FLASH_ATTR
user_init(void)
{
	uart_init_new();
    printf("SDK version:%s 0x%X\n", system_get_sdk_version(), system_get_chip_id());

    PIN_FUNC_SELECT(PERIPHS_IO_MUX_GPIO2_U, FUNC_GPIO2);
    //GPIO_OUTPUT_SET(2, 0);
    GPIO_OUTPUT(GPIO_SWITCH, 0);

    wifi_set_opmode(STATION_MODE);
    wifi_set_event_handler_cb(wifi_handle_event_cb);

    smartconfig_set_type(SC_TYPE_ESPTOUCH);

    xTaskCreate(tcp_task, "tcp_task", 1024, NULL, 4, NULL);
}

