/*
* If not stated otherwise in this file or this component's Licenses.txt file the
* following copyright and licenses apply:
*
* Copyright 2018 RDK Management
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <wifi_common_hal.h>
#include <stdbool.h>
#include "rdk_debug.h"

#define LOG_NMGR "LOG.RDK.WIFIHAL"
#define MAX_SSID_LEN        32           /* Maximum SSID name */
extern BOOL bNoAutoScan;

ULONG ssid_number_of_entries = 0;

/*! Supported values are NONE - 0, WPA - 1, WEP - 2*/
typedef enum _SsidSecurity
{
    NET_WIFI_SECURITY_NONE = 0,
    NET_WIFI_SECURITY_WEP_64,
    NET_WIFI_SECURITY_WEP_128,
    NET_WIFI_SECURITY_WPA_PSK_TKIP,
    NET_WIFI_SECURITY_WPA_PSK_AES,
    NET_WIFI_SECURITY_WPA2_PSK_TKIP,
    NET_WIFI_SECURITY_WPA2_PSK_AES,
    NET_WIFI_SECURITY_WPA_ENTERPRISE_TKIP,
    NET_WIFI_SECURITY_WPA_ENTERPRISE_AES,
    NET_WIFI_SECURITY_WPA2_ENTERPRISE_TKIP,
    NET_WIFI_SECURITY_WPA2_ENTERPRISE_AES,
    NET_WIFI_SECURITY_NOT_SUPPORTED = 15,
} SsidSecurity;

/*static struct _wifi_securityModes
{
    SsidSecurity 	securityMode;
    const char          *modeString;
} wifi_securityModes[] =
{
    { NET_WIFI_SECURITY_NONE,          		    "No Security"                   },
    { NET_WIFI_SECURITY_WEP_64, 	            "WEP (Open & Shared)"        	},
    { NET_WIFI_SECURITY_WEP_128,                "WEP (Open & Shared)"           },
    { NET_WIFI_SECURITY_WPA_PSK_TKIP, 		 	"WPA-Personal, TKIP encryp."   	},    
    { NET_WIFI_SECURITY_WPA_PSK_AES, 		  	"WPA-Personal, AES encryp."    	},
    { NET_WIFI_SECURITY_WPA2_PSK_TKIP, 			"WPA2-Personal, TKIP encryp."  	},
    { NET_WIFI_SECURITY_WPA2_PSK_AES,  			"WPA2-Personal, AES encryp."   	},
    { NET_WIFI_SECURITY_WPA_ENTERPRISE_TKIP,	"WPA-ENTERPRISE, TKIP"		},
    { NET_WIFI_SECURITY_WPA_ENTERPRISE_AES,		"WPA-ENTERPRISE, AES"		},
    { NET_WIFI_SECURITY_WPA2_ENTERPRISE_TKIP,		"WPA2-ENTERPRISE, TKIP"		},
    { NET_WIFI_SECURITY_WPA2_ENTERPRISE_AES,		"WPA2-ENTERPRISE, AES"		},
    { NET_WIFI_SECURITY_NOT_SUPPORTED, 		  	"Security format not supported" },
};*/

static struct _wifi_securityModes
{
    const char          *modeString;
    const char          *encryptionString;
    const char          *apSecurityEncryptionString;
} wifi_securityModes[] =
{
    { "WPA-WPA2","TKIP","[WPA-PSK-TKIP][WPA2-PSK-TKIP]"},
    { "WPA-WPA2","AES","[WPA-PSK-CCMP][WPA2-PSK-CCMP]"},
    { "WPA-WPA2","TKIP,AES","[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP]"},
    { "WPA-WPA2-Enterprise","TKIP","[WPA-EAP-TKIP][WPA2-EAP-TKIP]"},
    { "WPA-WPA2-Enterprise","AES","[WPA-EAP-CCMP][WPA2-EAP-CCMP]"},
    { "WPA-WPA2-Enterprise","TKIP,AES","[WPA-EAP-CCMP+TKIP][WPA2-EAP-CCMP+TKIP]"},
    { "WPA-Enterprise","TKIP,AES","[WPA-EAP-CCMP+TKIP]"},
    { "WPA2-Enterprise","TKIP,AES","[WPA2-EAP-CCMP+TKIP]"},
    { "WPA-Enterprise","TKIP","[WPA-EAP-TKIP]"},
    { "WPA-Enterprise","AES","[WPA-EAP-CCMP]"},
    { "WPA2-Enterprise","TKIP","[WPA2-EAP-TKIP]"},
    { "WPA2-Enterprise","AES","[WPA2-EAP-CCMP]"},
    { "WPA","TKIP","[WPA-PSK-TKIP]"},
    { "WPA2","TKIP","[WPA2-PSK-TKIP]"},
    { "WPA","AES","[WPA-PSK-CCMP]"},
    { "WPA2","AES","[WPA2-PSK-CCMP]"},
    { "WPA","TKIP,AES","[WPA-PSK-CCMP+TKIP]"},
    { "WPA2","TKIP,AES","[WPA2-PSK-CCMP+TKIP]"},
    { "WEP","","WEP"},
    { "None","","None"},
};
/*{
    { NET_WIFI_SECURITY_NONE,          		    "No Security"                   },
    { NET_WIFI_SECURITY_WEP_64, 	            "WEP (Open & Shared)"        	},
    { NET_WIFI_SECURITY_WEP_128,                "WEP (Open & Shared)"           },
    { NET_WIFI_SECURITY_WPA_PSK_TKIP, 		 	"WPA-Personal, TKIP encryp."   	},    
    { NET_WIFI_SECURITY_WPA_PSK_AES, 		  	"WPA-Personal, AES encryp."    	},
    { NET_WIFI_SECURITY_WPA2_PSK_TKIP, 			"WPA2-Personal, TKIP encryp."  	},
    { NET_WIFI_SECURITY_WPA2_PSK_AES,  			"WPA2-Personal, AES encryp."   	},
    { NET_WIFI_SECURITY_WPA_ENTERPRISE_TKIP,	"WPA-ENTERPRISE, TKIP"		},
    { NET_WIFI_SECURITY_WPA_ENTERPRISE_AES,		"WPA-ENTERPRISE, AES"		},
    { NET_WIFI_SECURITY_WPA2_ENTERPRISE_TKIP,		"WPA2-ENTERPRISE, TKIP"		},
    { NET_WIFI_SECURITY_WPA2_ENTERPRISE_AES,		"WPA2-ENTERPRISE, AES"		},
    { NET_WIFI_SECURITY_NOT_SUPPORTED, 		  	"Security format not supported" },
};*/
 
INT is_null_pointer(char* str) {    //Check if passed string is a null pointer and empty string or not
    if ((str !=NULL) && (str[0]=='\0')) {
        return 0;
    }
    return 1;
}

#include <wpa_ctrl.h>
#define BUF_SIZE               256

#define CA_ROOT_CERT_PATH      "/opt/lnf/ca-chain.cert.pem"
#define CA_CLIENT_CERT_PATH    "/opt/lnf/xi5device.cert.pem"
#define CA_PRIVATE_KEY_PATH    "/opt/lnf/xi5device.key.pem"
#define WPA_SUP_CONFIG         "/opt/wifi/wpa_supplicant.conf"

#define WPA_SUP_PIDFILE         "/var/run/wpa_supplicant/wlan0.pid"
#define WPA_SUP_CTRL            "/var/run/wpa_supplicant/wlan0"

#define WPA_SUP_TIMEOUT         4000   /* 4 msec */
#define WPA_SUP_PING_INTERVAL   60 /* 1 min */

typedef enum {
    WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE,
    WIFI_HAL_WPA_SUP_SCAN_STATE_CMD_SENT,
    WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED,
    WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED,
} WIFI_HAL_WPA_SUP_SCAN_STATE;

char* getValue(char *buf, char *keyword);
int wpaCtrlSendCmd(char *cmd);

bool init_done=false;   /* Flag to check if WiFi init was already done or not */
extern bool stop_monitor;  /* Flag to stop the monitor thread */
extern bool kill_wpa_supplicant; /* Flag to kill wpa_supplicant */
uint32_t g_wpa_sup_pid=0, ap_count=0;
struct wpa_ctrl *g_wpa_ctrl= NULL;
struct wpa_ctrl *g_wpa_monitor = NULL; 
WIFI_HAL_WPA_SUP_SCAN_STATE cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE;
pthread_mutex_t wpa_sup_lock;
char cmd_buf[1024], return_buf[8192];
char event_buf[4096];
wifi_neighbor_ap_t ap_list[512];
extern char currSsid[MAX_SSID_LEN+1];

void monitor_thread_task(void *param);
void monitor_wpa_health();
static int wifi_getWpaSupplicantStatus();
static int wifi_openWpaSupConnection();

INT wifi_getHalVersion(CHAR *output_string)
{
    int ret = 0;
    if(output_string)
    {
        ret = sprintf(output_string,"%d.%d.%d",WIFI_HAL_MAJOR_VERSION,WIFI_HAL_MINOR_VERSION,WIFI_HAL_MAINTENANCE_VERSION);
    }
    return ret;
}
char* readFile(char *filename)
{
    FILE    *fp = NULL;
    char    *buf = NULL;
    long    fBytes = 0;
    long    freadBytes = 0; 

    fp=fopen(filename,"r");
    if(fp==NULL)
    {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"readFile(): File Open Error \n" );
        return NULL;
    }
    fseek(fp,0L,SEEK_END);
    fBytes=ftell(fp);
    fseek(fp,0L,SEEK_SET);
    if(fBytes > 0)
    {
        buf=(char *)calloc(fBytes+1,sizeof(char));
        if(buf == NULL)
        {
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"readFile(): Memory Allocation Error \n" );
            fclose(fp);
            return NULL; 
        }
        freadBytes = fread(buf,sizeof(char),fBytes,fp);
        if(freadBytes != fBytes) // Do we need to proceed on partial read.. ? Blocking for now.
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR," readFile(): Error occured during fread(), freadBytes= %d  \n" ,freadBytes); 
            fclose(fp);
            free(buf);
            return NULL;
        }
    }
    else
    {
       RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"readFile(): File is empty \n" );
    }
    fclose(fp);
    return buf;
}

static int sysfs_get(char *path, unsigned int *out)
{
    FILE *f;
    unsigned int tmp;
    char buf[BUF_SIZE];

    f = fopen(path, "r");
    if(! f)
        return(-1);
    if(fgets(buf, BUF_SIZE, f) != buf)
    {
        fclose(f);
        return(-1);
    }
    fclose(f);
    if(sscanf(buf, "0x%x", &tmp) != 1 && sscanf(buf, "%u", &tmp) != 1)
        return(-1);
    *out = tmp;
    return(0);
}



// Initializes the wifi subsystem (all radios)
INT wifi_init() {
    int retry = 0;
    int pid;
    stop_monitor=false;
    kill_wpa_supplicant=false;
    pthread_attr_t thread_attr;
    pthread_t monitor_thread;
    pthread_t wpa_health_mon_thread;
    int ret;

    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wifi_init() entered \n");
    if(init_done == true) {
       RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Wifi init has already been done\n");
       return RETURN_OK;
    }
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: TELEMETRY_WIFI_WPA_SUPPLICANT:ENABLED \n ");    
    if (g_wpa_sup_pid != 0)	{
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wifi_init called again \n");
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: %s(): wpa_supplicant already started", __FUNCTION__);		
    }
    
    /* Creating wpa_supplicant.conf if it does not already exist */
    if(access("/opt/wifi/wpa_supplicant.conf", F_OK ) != -1){
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Configuration file present\n");
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Continuing to check contents of file\n");

        bool ctrlInterfacePresent = false;
        bool updateConfigPresent = false;
        char* line = NULL;
        size_t len = 0;
        size_t read;
        FILE* f = fopen("/opt/wifi/wpa_supplicant.conf", "r");
        if(f == NULL){
           RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Error opening file\n");
           return RETURN_ERR;
        }
        while((read = getline(&line, &len, f)) != -1) {
		//RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Retrieved line of length %zu :\n", read);
          if((strstr(line, "ctrl_interface=/var/run/wpa_supplicant") != NULL)){
             ctrlInterfacePresent = true;
          }
          if((strstr(line, "update_config=1") != NULL)){
             updateConfigPresent = true;
          }
	}
        free(line);
        fclose(f);
        /* Write fresh contents if corrupted */
        if((ctrlInterfacePresent == false) || (updateConfigPresent == false)){
          RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: The conf file looks corrupted. Deleting and creating new one\n");
          system("rm /opt/wifi/wpa_supplicant.conf");
          FILE* fp = fopen("/opt/wifi/wpa_supplicant.conf", "w");
          if(fp == NULL){
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Error in opening configuration file\n");
            return RETURN_ERR;
          }
          fprintf(fp, "ctrl_interface=/var/run/wpa_supplicant\n");
          fprintf(fp, "update_config=1\n");
          fclose(fp);
        }
    }
    else{
        FILE* fp;
        fp = fopen("/opt/wifi/wpa_supplicant.conf", "w");
        if(fp == NULL){
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Error in opening configuration file\n");
            return RETURN_ERR;
        }
        fprintf(fp, "ctrl_interface=/var/run/wpa_supplicant\n");
        //fprintf(fp, "mem_only_psk=1\n");                       /* Will not store PSK to configuration file and only holds it in memory if set to 1*/
        fprintf(fp, "update_config=1\n");
        fclose(fp);
    }

    /* Kill the existing wpa_supplicant process */
    if(sysfs_get(WPA_SUP_PIDFILE, &pid) == 0)
        kill(pid, SIGKILL);   
 
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Starting wpa_supplicant \n");
    system("/usr/sbin/wpa_supplicant -B -Dnl80211 -c/opt/wifi/wpa_supplicant.conf -iwlan0 -P/var/run/wpa_supplicant/wlan0.pid -d -t -f /opt/logs/wpa_supplicant.log");
    
    /* Starting wpa_supplicant may take some time, try 10 times before giving up */
    retry = 0;    
    while (retry++ < 10) {
        g_wpa_ctrl = wpa_ctrl_open(WPA_SUP_CTRL);
        if (g_wpa_ctrl != NULL) break;
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"ctrl_open returned NULL \n");
        sleep(1);
    }

    if (g_wpa_ctrl == NULL) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_ctrl_open failed for control interface \n");
        return RETURN_ERR;
    }
    g_wpa_monitor = wpa_ctrl_open(WPA_SUP_CTRL);
    if ( g_wpa_monitor == NULL ) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_ctrl_open failed for monitor interface \n");
        return RETURN_ERR;
    }

    if ( wpa_ctrl_attach(g_wpa_monitor) != 0) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_ctrl_attach failed \n");
        return RETURN_ERR;
    }
    if (pthread_mutex_init(&wpa_sup_lock, NULL) != 0)
    {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: mutex init failed\n");
        return RETURN_ERR;
    }
    currSsid[0] = '\0';
    /* Create thread to monitor events from wpa supplicant */
    pthread_attr_init(&thread_attr);
    pthread_attr_setstacksize(&thread_attr, 256*1024);
    
    ret = pthread_create(&monitor_thread, &thread_attr, monitor_thread_task, NULL);
    
    
    if (ret != 0) {        
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Monitor thread creation failed \n");
        return RETURN_ERR;
    }
    // Stat wpa_supplicant health monitor thread
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Starting wpa_supplicant health monitor thread \n");
    ret = pthread_create(&wpa_health_mon_thread, NULL, monitor_wpa_health, NULL);
    if (ret != 0) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: WPA health monitor thread creation failed  \n");
        return RETURN_ERR;
    }

    init_done=true;

    return RETURN_OK;
    
}

// Uninitializes wifi
INT wifi_uninit() {

    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Stopping monitor thread\n");
    int pid; 
    stop_monitor=true;

    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Disconnecting from the network\n");

    wpaCtrlSendCmd("DISCONNECT");

    wpaCtrlSendCmd("DISABLE_NETWORK 0");
    
    while(kill_wpa_supplicant != true)
         sleep(1);    

    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Killing wpa_supplicant process\n");
    /* Kill the existing wpa_supplicant process */
    if(sysfs_get(WPA_SUP_PIDFILE, &pid) == 0)
       kill(pid, SIGKILL);
    
    init_done=false;
    return RETURN_OK;
}

//clears internal variables to implement a factory reset of the Wi-Fi subsystem
INT wifi_factoryReset() {

    return RETURN_OK;
}

//Restore all radio parameters without touch access point parameters
INT wifi_factoryResetRadios() {
    return RETURN_OK;
}

//Restore selected radio parameters without touch access point parameters
INT wifi_factoryResetRadio(int radioIndex) {

    return RETURN_OK;
}

// resets the wifi subsystem, deletes all APs
INT wifi_reset() {
    return RETURN_OK;
}


// turns off transmit power for the entire Wifi subsystem, for all radios
INT wifi_down() {

    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Bring the wlan interface down\n");
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Hardcoding the interface to wlan0 for now\n");
    system("ifdown wlan0");
    return RETURN_OK;
}

INT parse_scan_results(char *buf, size_t len)
{
    uint32_t count = 0;
    char tmp_str[100];
    char flags[256];
    char *delim_ptr, *ptr, *encrypt_ptr,*security_ptr;
    int i; 
    if ((len == 0) || (buf == NULL)) return -1;
    
    /* example output:
        * bssid / frequency / signal level / flags / ssid
        * b8:62:1f:e5:dd:5b       5200    -55     [WPA2-EAP-CCMP][ESS]    BCLMT-Wifi
        */
  
    /* skip heading */
    ptr = strstr(buf,"/ ssid");
    if (ptr == NULL) return -1;
    ptr += strlen("/ ssid") + 1;
  

    /* Parse scan results */
    while ((delim_ptr=strchr(ptr, '\t')) != NULL) {
    
        /* Parse bssid */
        memcpy(ap_list[count].ap_BSSID, ptr, (delim_ptr-ptr));    
        ap_list[count].ap_BSSID[delim_ptr-ptr] = '\0';
/*        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"bssid=%s \n",ap_list[count].ap_BSSID); */

        /* Parse frequency */
        ptr = delim_ptr + 1;
        delim_ptr=strchr(ptr, '\t');
        memcpy(ap_list[count].ap_OperatingFrequencyBand, ptr, (delim_ptr-ptr));
        ap_list[count].ap_OperatingFrequencyBand[delim_ptr-ptr] = '\0';
/*        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"freq=%s \n",ap_list[count].ap_OperatingFrequencyBand); */

        /* parse signal level */    
        ptr = delim_ptr + 1;
        delim_ptr=strchr(ptr, '\t');
        memcpy(tmp_str, ptr, (delim_ptr-ptr));
        tmp_str[delim_ptr-ptr] = '\0';
        ap_list[count].ap_SignalStrength = atoi(tmp_str);
/*        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"signal strength=%d \n",ap_list[count].ap_SignalStrength); */
    
        /* parse flags */    
        ptr = delim_ptr + 1;
        delim_ptr=strchr(ptr, '\t');
        memcpy(flags, ptr, (delim_ptr-ptr));
        flags[delim_ptr-ptr] = '\0';
        memset(ap_list[count].ap_SecurityModeEnabled, 0, sizeof(ap_list[count].ap_SecurityModeEnabled));
        memset(ap_list[count].ap_EncryptionMode, 0, sizeof(ap_list[count].ap_EncryptionMode));
        encrypt_ptr=ap_list[count].ap_EncryptionMode;
        security_ptr=ap_list[count].ap_SecurityModeEnabled;
        int len = sizeof(wifi_securityModes)/sizeof(wifi_securityModes[0]);
        for(i = 0; i < len; i++)
        {
            if(NULL != strcasestr(flags,wifi_securityModes[i].apSecurityEncryptionString)) {
                strcpy(security_ptr, wifi_securityModes[i].modeString);
                strcpy(encrypt_ptr, wifi_securityModes[i].encryptionString);
                break;
            }
        }
        if (encrypt_ptr > ap_list[count].ap_EncryptionMode) {
            *(encrypt_ptr-1)='\0';
        }       
        if (security_ptr > ap_list[count].ap_SecurityModeEnabled) {
            *(security_ptr-1)='\0';
        }
        RDK_LOG(RDK_LOG_INFO, LOG_NMGR,"flags=%s ap_list[count].ap_SecuritymodeEnabled = %s ap_list[count].ap_EncryptionMode=%s \n", flags,ap_list[count].ap_SecurityModeEnabled,ap_list[count].ap_EncryptionMode);
    
        /* parse SSID */  
        ptr = delim_ptr + 1;
        delim_ptr=strchr(ptr, '\n');
        memcpy(ap_list[count].ap_SSID, ptr, (delim_ptr-ptr));
        ap_list[count].ap_SSID[delim_ptr-ptr] = '\0';
/*        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID=%s \n",ap_list[count].ap_SSID); */
    
        ptr = delim_ptr + 1;    
        count++;   

    }

    return count;

 }    

INT wifi_getNeighboringWiFiDiagnosticResult(INT radioIndex, wifi_neighbor_ap_t **neighbor_ap_array, UINT *output_array_size) 
{    
    size_t return_len=sizeof(return_buf)-1;
    int retry = 0;
    
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Starting a single scan..\n");

    pthread_mutex_lock(&wpa_sup_lock);
    if (cur_scan_state != WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Scan is in progress \n");
        goto exit_err;
        
    }
    bNoAutoScan=TRUE; 
    wpaCtrlSendCmd("SCAN");
    if (strstr(return_buf, "FAIL-BUSY") != NULL) {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Scan command returned %s .. waiting \n", return_buf);            
//        pthread_mutex_unlock(&wpa_sup_lock);
        wpaCtrlSendCmd("BSS_FLUSH 0");
        sleep(1); 
//        pthread_mutex_lock(&wpa_sup_lock);
        wpaCtrlSendCmd("SCAN");
        if (strstr(return_buf, "FAIL-BUSY") != NULL) {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Scan command returned %s FAILED \n", return_buf);
            goto exit_err;
        }
    }
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Scan command returned %s \n", return_buf);

    cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED;
    pthread_mutex_unlock(&wpa_sup_lock);
    while ((cur_scan_state !=  WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED) &&(retry++ < 1000)) {       
        usleep(WPA_SUP_TIMEOUT);
    }
    pthread_mutex_lock(&wpa_sup_lock);    
    if (cur_scan_state != WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED) { 
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Scan timed out retry times = %d \n",retry);
        //*output_array_size=0;
       // goto exit_err;
    } //else {
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Trying to read Scan results \n"); // Lets read scan_results even if it is timed out FIX:- Xi-6 Scan timeout
    wpaCtrlSendCmd("SCAN_RESULTS");
    ap_count = parse_scan_results(return_buf, return_len);
    if (ap_count > 0) {
        int i;            
        *output_array_size = ap_count;
        *neighbor_ap_array = (wifi_neighbor_ap_t *)malloc(ap_count*sizeof(wifi_neighbor_ap_t));
            
        if(*neighbor_ap_array == NULL) {
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Malloc Memory allocation failure\n");            
            goto exit_err;
        }
        for (i=0; i<*output_array_size; i++)
            (*neighbor_ap_array)[i] = ap_list[i];
    }        
   // }
   cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE;
   bNoAutoScan=FALSE;
   pthread_mutex_unlock(&wpa_sup_lock);
   return RETURN_OK;

 exit_err:   
   cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE;
   bNoAutoScan=FALSE;
   pthread_mutex_unlock(&wpa_sup_lock);
   return RETURN_ERR; 
}

/**************WiFi Diagnostics********************/

INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string) {

    if(!output_string) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Error in getting supported bands.. Null string\n");
        return RETURN_ERR;
    }
    snprintf(output_string, 64, "5GHz");
    return RETURN_OK;
}

INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string) {
    if(!output_string) {
        return RETURN_ERR;
    }
    snprintf(output_string, 64, "5GHz");
    return RETURN_OK;
}

INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string) {

    if (!output_string) {
        return RETURN_ERR;
    }
    snprintf(output_string, 64, (radioIndex==0)?"b,g,n":"n,ac");
    return RETURN_OK;
}

INT wifi_getRadioStandard(INT radioIndex, CHAR *output_string, BOOL *gOnly, BOOL *nOnly, BOOL *acOnly) {

    if(!output_string) {
        return RETURN_ERR;
    }
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Test mode\n");
    return RETURN_OK;
}

INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string) {

    if(!output_string) {
        return RETURN_ERR;
    }
    snprintf(output_string, 64, "%s", (radioIndex==0)?"1-11":"36,40");
    return RETURN_OK;
}

INT wifi_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string) {

    if(!output_string) {
        return RETURN_OK;
    }
    return RETURN_OK;
}

INT wifi_getSSIDName(INT apIndex, CHAR *output_string) {
    
    char *ptr, *bssid, *ssid;

    pthread_mutex_lock(&wpa_sup_lock);
    wpaCtrlSendCmd("STATUS");
    bssid = getValue(return_buf, "bssid");
    if (bssid == NULL) 
        goto exit_err;
    ptr = bssid + strlen(bssid) + 1;
    ssid = getValue(ptr, "ssid");
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"ssid=%s \n", ssid);
    if (ssid == NULL) 
        goto exit_err;
    else
        if (output_string != NULL) strcpy(output_string, ssid);

    pthread_mutex_unlock(&wpa_sup_lock);
    return RETURN_OK;

exit_err:
    pthread_mutex_unlock(&wpa_sup_lock);
    return RETURN_ERR;
}

INT wifi_setSSIDName(INT apIndex, CHAR *ssid_string) {

    return RETURN_OK;
}

INT wifi_getBaseBSSID(INT ssidIndex, CHAR *output_string) {

    char *bssid = NULL;
    int maxBssidLen = 18;

    pthread_mutex_lock(&wpa_sup_lock);
    wpaCtrlSendCmd("STATUS");
    bssid = getValue(return_buf, "bssid");
    if (bssid == NULL)
        goto exit_err;
    else
        if (output_string != NULL) strncpy(output_string, bssid,maxBssidLen);

    pthread_mutex_unlock(&wpa_sup_lock);
    return RETURN_OK;


exit_err:
    pthread_mutex_unlock(&wpa_sup_lock);
    return RETURN_ERR;
}

INT wifi_getSSIDMACAddress(INT ssidIndex, CHAR *output_string) {
    
    char *ptr, *bssid;
    
    pthread_mutex_lock(&wpa_sup_lock);
    wpaCtrlSendCmd("STATUS");
    bssid = getValue(return_buf, "bssid");
    if (bssid == NULL) 
        goto exit_err;
    else
        if (output_string != NULL) strcpy(output_string, bssid);
            
    pthread_mutex_unlock(&wpa_sup_lock);
    return RETURN_OK;
            
        
exit_err:
    pthread_mutex_unlock(&wpa_sup_lock);
    return RETURN_ERR;
}

static INT wifi_getRadioSignalParameter (const CHAR* parameter, CHAR *output_string) {

    if (!parameter || !output_string) {
        return RETURN_ERR;
    }

    char *parameter_value = NULL;
    int ret = RETURN_ERR;

    pthread_mutex_lock (&wpa_sup_lock);
    wpaCtrlSendCmd ("SIGNAL_POLL");
    if (NULL != (parameter_value = getValue(return_buf, parameter)))
    {
        strcpy (output_string, parameter_value);
        ret = RETURN_OK;
    }
    pthread_mutex_unlock (&wpa_sup_lock);

    RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR, "[%s] return code = [%d], parameter = [%s], parameter_value = [%s]\n",
            __FUNCTION__, ret, parameter, parameter_value ? parameter_value : "NULL");
    return ret;
}

static int wifi_getRadioChannelFromFrequency(int frequency)
{
    if (frequency == 2484)
        return 14;
    else if (frequency < 2484)
        return (frequency - 2407) / 5;
    else if (frequency >= 4910 && frequency <= 4980)
        return (frequency - 4000) / 5;
    else if (frequency <= 45000)
        return (frequency - 5000) / 5;
    else if (frequency >= 58320 && frequency <= 64800)
        return (frequency - 56160) / 2160;
    else
        return 0;
}
// Ping to wpa_supplicant and get connection Status, Ret = 0-> success, -1-> Response failure ,-2-> Command failure
static int wifi_getWpaSupplicantStatus()
{
    int retStatus = -1;
    char temp_buff[50];
    int pingStatus = -1;

    memset(temp_buff,0,sizeof(temp_buff));
    pthread_mutex_lock(&wpa_sup_lock);
    retStatus = wpaCtrlSendCmd("PING");
    strncpy(temp_buff,return_buf,sizeof(temp_buff)-1);
    pthread_mutex_unlock(&wpa_sup_lock);

    if(temp_buff[0] != '\0' && retStatus == 0 )
    {
        if(strncmp(temp_buff,"PONG",4) == 0)
        {
            pingStatus = 0;
        }
        else
        {
            pingStatus = -1; // Response failure
        }
    }
    else
    {
        pingStatus = -2; // Command Failure
    }
    return pingStatus;
}

// Open wpa_supplicant Control and Monitor Connection, Ret = 0-> Success , -1 -> failure
static int wifi_openWpaSupConnection()
{
    int retStatus = -1;

    // Open Control connection
    pthread_mutex_lock(&wpa_sup_lock);
    wpa_ctrl_close(g_wpa_ctrl);
    g_wpa_ctrl = wpa_ctrl_open(WPA_SUP_CTRL);
    if(NULL != g_wpa_ctrl) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_supplicant control connection opened successfuly. \n");
    } else{
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failure in opening wpa_supplicant control connection.\n");
        pthread_mutex_unlock(&wpa_sup_lock);
        return retStatus;
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    
    // Open Monitor Connection
    pthread_mutex_lock(&wpa_sup_lock);
    wpa_ctrl_close(g_wpa_monitor);
    g_wpa_monitor = wpa_ctrl_open(WPA_SUP_CTRL);
    if(NULL != g_wpa_monitor) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_supplicant monitor connection opened successfuly. \n");
        if ( wpa_ctrl_attach(g_wpa_monitor) != 0) {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: wpa_ctrl_attach failed \n");
        } else {
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Monitor connection Attached Successfully. \n");
            retStatus = 0;
        }
    } else{
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failure in opening wpa_supplicant monitor connection.\n");
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    return retStatus;
}
void monitor_wpa_health()
{
    int retStatus = -1;
    int printInterval = 0;
    int pingCount = 0;
    int openStatus = -1;

    while(true)
    {
        retStatus = wifi_getWpaSupplicantStatus();
        if(retStatus == 0)
        {
            if(printInterval >= 4)
            {
                RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_supplicant heartbeat success. \n");
                printInterval = 0;
            }
            else
                printInterval++;
        }
        else
        { 
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: wpa_supplicant heartbeat failed, Reason: %s \n",retStatus==-1?"No response.":"Command failure.");
            pingCount = 0;
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Trying for 5 continues pings...\n");
            while(pingCount < 5)
            {
                retStatus = wifi_getWpaSupplicantStatus();
                if(!retStatus) {
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_supplicant heartbeat success. , Breaking Ping attempts\n");
                    break; // Got one Success lets break
                }
                else
                    RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: wpa_supplicant heartbeat failed, Reason: %s, Attempt = %d\n",retStatus==-1?"No response.":"Command failure.",pingCount+1);
                pingCount++;
                sleep(3);
            }
            if(pingCount >= 5) {
                 RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Heartbeat failed for all attempts, Trying to reopen Connection.\n");
                 wifi_openWpaSupConnection();
            }
        }
        sleep(WPA_SUP_PING_INTERVAL);
    }
}

INT wifi_getRadioChannel(INT radioIndex,ULONG *output_ulong) {

    if(!output_ulong) {
        return RETURN_ERR;
    }

    CHAR frequency_string[8] = "";
    int frequency = 0;
    int channel = 0;
    int ret = RETURN_ERR;
    if (RETURN_OK == wifi_getRadioSignalParameter ("FREQUENCY", frequency_string) &&
            1 == sscanf (frequency_string, "%d", &frequency) &&
            0 != frequency &&
            0 != (channel = wifi_getRadioChannelFromFrequency (frequency)))
    {
        *output_ulong = channel;
        ret = RETURN_OK;
    }

    RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR, "[%s] return code = [%d], Channel Spec: %lu\n", __FUNCTION__, ret, *output_ulong);
    return ret;
}

INT wifi_getRadioChannelsInUse(INT radioIndex, CHAR *output_string) {
    if (!output_string)
        return RETURN_ERR;
    snprintf(output_string, 256, (radioIndex==0)?"1,6,11":"36,40");
    return RETURN_OK;
}

INT wifi_getSSIDNumberOfEntries(ULONG *output) {

    if(!output) {
        return RETURN_ERR;
    }

    *output = 1;
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: SSID entries:1\n");
    return RETURN_OK;

}

INT wifi_getRadioTrafficStats(INT radioIndex, wifi_radioTrafficStats_t *output_struct) {

    FILE *fp = NULL;
    char resultBuff[BUF_SIZE];
    char cmd[50];
    char interfaceName[10];
    long long int rx_bytes = 0,rx_packets = 0,rx_err = 0,rx_drop = 0;
    long long int tx_bytes = 0,tx_packets = 0,tx_err = 0,tx_drop = 0;
    int numParams = 0;
    int noise = 0;
    char* ptr = NULL;

    if(!output_struct) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"output struct is null");
        return 0;
    }

    // memset arrays
    memset(resultBuff,0,sizeof(resultBuff));
    memset(cmd,0,sizeof(cmd));
    memset(interfaceName,0,sizeof(interfaceName));

    wifi_getRadioIfName(0,interfaceName);
    snprintf(cmd,sizeof(cmd),"cat /proc/net/dev | grep %s",interfaceName);
    fp = popen(cmd,"r");
    if(fp != NULL)
    {
        if(fgets(resultBuff,BUF_SIZE-1,fp)!=NULL)
        {
            numParams = sscanf( resultBuff," %[^:]: %lld %lld %lld %lld %*u %*u %*u %*u %lld %lld %lld %lld %*u %*u %*u %*u",interfaceName, &rx_bytes, &rx_packets,&rx_err,&rx_drop,&tx_bytes,&tx_packets,&tx_err,&tx_drop );
            if(numParams != 9)
            {
                RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Error in parsing Radio Stats params \n");
            }
            output_struct->radio_PacketsSent = tx_packets;
            output_struct->radio_PacketsReceived = rx_packets;
            output_struct->radio_BytesSent = tx_bytes;
            output_struct->radio_BytesReceived = rx_bytes;
            output_struct->radio_ErrorsReceived = rx_err;
            output_struct->radio_ErrorsSent = tx_err;
            output_struct->radio_DiscardPacketsSent = tx_drop;
            output_struct->radio_DiscardPacketsReceived = rx_drop;
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"[tx_packets = %lld] [rx_packets =  %lld] [tx_bytes = %lld] [rx_bytes = %lld] [rx_err = %lld] [tx_err = %lld] [tx_drop = %lld] [rx_drop = %lld] \n",tx_packets,rx_packets,tx_bytes,rx_bytes,rx_err,tx_err,tx_drop,rx_drop);
        }
        else
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Error in reading /proc/net/dev file \n");
        }
        pclose(fp);
    }
    else
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Error in popen() : Opening /proc/net/dev failed \n");
    }
    pthread_mutex_lock(&wpa_sup_lock);
    wpaCtrlSendCmd("SIGNAL_POLL");
    ptr = getValue(return_buf, "NOISE");
    if(NULL != ptr)
    {
        noise = atoi(ptr);
        output_struct->radio_NoiseFloor = noise;
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"\n noise = %d ",noise);
    }
    else
    {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Noise is not available in siganl poll \n");
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    return RETURN_OK;
}

INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool) {
    *output_bool = (g_wpa_monitor != NULL);
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"The radio is %s\n", g_wpa_monitor ? "enabled" : "not enabled");
    return RETURN_OK;
}

INT wifi_getRadioStatus(INT radioIndex, CHAR *output_string) {
    if ( g_wpa_monitor != NULL ){
        strcpy(output_string, "UP");
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"The radio is enabled\n");
        return RETURN_OK;
    }
    
    strcpy(output_string, "DOWN");
    return RETURN_ERR;
}

INT wifi_getRegulatoryDomain(INT radioIndex, CHAR* output_string){
     
    if(!output_string){
       RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Output_string is null\n");
       return RETURN_ERR;
    }
    strcpy(output_string, "US");
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Regulatory domain:US\n");
    return RETURN_OK; 
}

INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string) {
    
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: MaxBitRate information will be implemented\n");
    return RETURN_ERR;
}

INT wifi_getRadioMCS(INT radioIndex, INT *output_INT){
    
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: MCS could not be determined\n");
    return RETURN_ERR;
}

INT wifi_getSSIDTrafficStats(INT ssidIndex, wifi_ssidTrafficStats_t *output_struct) {

char filename[]="/tmp/wlparam.txt";
char *bufPtr=NULL;
char *ptrToken;   

    if(!output_struct) {
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"output struct is null");
      return 0;
    }
    system("wl counter > /tmp/wlparam.txt");
    bufPtr=readFile(filename);
    if(bufPtr)
    {
        ptrToken = strtok (bufPtr," \t\n");
        while (ptrToken != NULL)
        {
            if (strcmp(ptrToken, "txdatamcast") == 0)
            {
                ptrToken = strtok (NULL, " \t\n");
                output_struct->ssid_MulticastPacketsSent=strtoull(ptrToken, NULL, 10);
                RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"\n txdatamcast = %llu ",strtoull(ptrToken, NULL, 10));
            }
            else if (strcmp(ptrToken, "txdatabcast") == 0)
            {
                ptrToken = strtok (NULL, " \t\n");
                output_struct->ssid_BroadcastPacketsSent=strtoull(ptrToken, NULL, 10);
                RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"\n txdatabcast = %llu ",strtoull(ptrToken, NULL, 10));
            }
            else if (strcmp(ptrToken, "txnoack") == 0)
            {
                ptrToken = strtok (NULL, " \t\n");
                output_struct->ssid_ACKFailureCount=strtoull(ptrToken, NULL, 10);
                RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"\n txnoack  = %llu ",strtoull(ptrToken, NULL, 10));
            }
            else
            {
                ptrToken = strtok (NULL, " \t\n");
            }   
        }   
        free(bufPtr);
    }

    //TODO: Get the following stats in. Commenting it out to unblock basic testing
    /*NETAPP_WIFI_STATS tTestInfo;
    memset(&tTestInfo, 0, sizeof(tTestInfo));
    NetAppWiFiTestGetStats(hNetApp, &tTestInfo);
    output_struct->ssid_MulticastPacketsSent = tTestInfo.txdatamcast;
    output_struct->ssid_BroadcastPacketsSent = tTestInfo.txdatabcast;
    output_struct->ssid_ACKFailureCount = tTestInfo.txnoack;*/
    return RETURN_OK;
}

INT wifi_getRadioExtChannel(INT radioIndex, CHAR *output_string) {

    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Extension channel is Auto\n");
    strcpy(output_string, "Auto");
    return RETURN_OK;
}

/***************Stubbed out functions**********************/
INT wifi_getRadioNumberOfEntries(ULONG *output) {
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"The radio number of entries is always 1\n");
    *output = 1;
    return RETURN_OK;
}

INT wifi_setRadioEnable(INT radioIndex, BOOL enable) {
    return RETURN_OK;
}

INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string) {
    strcpy(output_string, "wlan0");
    return RETURN_OK;
}

INT wifi_setRadioChannelMode(INT radioIndex, CHAR *channelMode, BOOL gOnlyFlag, BOOL nOnlyFlag, BOOL acOnlyFlag) {
    return RETURN_OK;
}

INT wifi_setRadioChannel(INT radioIndex, ULONG channel) {
    return RETURN_OK;
}

INT wifi_getRadioAutoChannelSupported(INT radioIndex, BOOL *output_bool) {
    return RETURN_OK;
}

INT wifi_getRadioAutoChannelEnable(INT radioIndex, BOOL *output_bool) {
    return RETURN_OK;
}

INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable) {
    return RETURN_OK;
}

INT wifi_getRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG *output_ulong) {
    return RETURN_OK;
}

INT wifi_setRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG seconds) {
    return RETURN_OK;
}

INT wifi_setRadioOperatingChannelBandwidth(INT radioIndex, CHAR *bandwidth) {
    return RETURN_OK;
}

INT wifi_setRadioExtChannel(INT radioIndex, CHAR *string) {
    return RETURN_OK;
}

INT wifi_getRadioGuardInterval(INT radioIndex, CHAR *output_string) {
    return RETURN_OK;
}

INT wifi_setRadioGuardInterval(INT radioIndex, CHAR *string) {
    return RETURN_OK;
}

INT wifi_setRadioMCS(INT radioIndex, INT MCS) {
    return RETURN_OK;
}

INT wifi_getRadioTransmitPowerSupported(INT radioIndex, CHAR *output_list) {
    return RETURN_OK;
}

INT wifi_getRadioTransmitPower(INT radioIndex, INT *output_INT) {
    return RETURN_OK;
}

INT wifi_setRadioTransmitPower(INT radioIndex, ULONG TransmitPower) {
    return RETURN_OK;
}

INT wifi_getRadioIEEE80211hSupported(INT radioIndex, BOOL *Supported) {
    return RETURN_OK;
}

INT wifi_getRadioIEEE80211hEnabled(INT radioIndex, BOOL *enable) {
    return RETURN_OK;
}

INT wifi_setRadioIEEE80211hEnabled(INT radioIndex, BOOL enable) {
    return RETURN_OK;
}

INT wifi_getRadioCarrierSenseThresholdRange(INT radioIndex, INT *output) {
    return RETURN_OK;
}

INT wifi_getRadioCarrierSenseThresholdInUse(INT radioIndex, INT *output) {
    return RETURN_OK;
}
INT wifi_setRadioCarrierSenseThresholdInUse(INT radioIndex, INT threshold) {
    return RETURN_OK;
}

INT wifi_getRadioChannelSwitchingCount(INT radioIndex, INT *output) {
    return RETURN_OK;
}

INT wifi_getRadioBeaconPeriod(INT radioIndex, UINT *output) {
    return RETURN_OK;
}

INT wifi_setRadioBeaconPeriod(INT radioIndex, UINT BeaconPeriod) {
    return RETURN_OK;
}

INT wifi_getRadioBasicDataTransmitRates(INT radioIndex, CHAR *output) {
    return RETURN_OK;
}

INT wifi_setRadioBasicDataTransmitRates(INT radioIndex, CHAR *TransmitRates) {
    return RETURN_OK;
}

INT wifi_setRadioTrafficStatsMeasure(INT radioIndex, wifi_radioTrafficStatsMeasure_t *input_struct) {
    return RETURN_OK;
}

INT wifi_getRadioStatsReceivedSignalLevel(INT radioIndex, INT signalIndex, INT *SignalLevel) {
    return RETURN_OK;
}

INT wifi_applyRadioSettings(INT radioIndex) {
    return RETURN_OK;
}

INT wifi_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex) {
    return RETURN_OK;
}

INT wifi_getSSIDEnable(INT ssidIndex, BOOL *output_bool) {
    return RETURN_OK;
}

INT wifi_setSSIDEnable(INT ssidIndex, BOOL enable) {
    return RETURN_OK;
}

INT wifi_getSSIDStatus(INT ssidIndex, CHAR *output_string) {
    return RETURN_OK;
}

INT wifi_applySSIDSettings(INT ssidIndex) {
    return RETURN_OK;
}


