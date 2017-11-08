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
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "rdk_debug.h"

#include <wifi_client_hal.h>
#include <unistd.h>

//This call back will be invoked when client automatically connect to AP.

wifi_connectEndpoint_callback callback_connect;

//This call back will be invoked when client lost the connection to AP.
wifi_disconnectEndpoint_callback callback_disconnect;

#include <wpa_ctrl.h>
#define LOG_NMGR "LOG.RDK.WIFIHAL"
#define WPA_SUP_TIMEOUT     500000       /* 500 msec */
#define MAX_SSID_LEN        32           /* Maximum SSID name */
#define MAX_PASSWORD_LEN    64           /* Maximum password length */
#define ENET_LEN            17           /* Length of bytes for displaying an Ethernet address, e.g., 00:00:00:00:00:00.*/
#define CSPEC_LEN           20           /* Channel Spec string length */
#define RETURN_BUF_LENGTH   8192

typedef enum {
    WIFI_HAL_WPA_SUP_STATE_IDLE,
    WIFI_HAL_WPA_SUP_STATE_CMD_SENT,
    WIFI_HAL_WPA_SUP_CONNECTING,
} WIFI_HAL_WPA_SUP_STATE;

typedef enum {
    WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE,
    WIFI_HAL_WPA_SUP_SCAN_STATE_CMD_SENT,
    WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED,
    WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED,
} WIFI_HAL_WPA_SUP_SCAN_STATE;


/* The control and monitoring interface is defined and initialized during the init phase */
extern struct wpa_ctrl *g_wpa_ctrl;
extern struct wpa_ctrl *g_wpa_monitor;

/* This mutex is used around wpa_supplicant calls. This is defined and initialized during the init phase */
extern pthread_mutex_t wpa_sup_lock;

/* Use the same buffer from wifi_common_hal.c */
extern char cmd_buf[1024];                     /* Buffer to pass the commands into */
extern char return_buf[RETURN_BUF_LENGTH];                  /* Buffer that stores the return results */
BOOL bNoAutoScan=FALSE;
char bUpdatedSSIDInfo=1;

/* Initialize the state of the supplicant */
WIFI_HAL_WPA_SUP_STATE cur_sup_state = WIFI_HAL_WPA_SUP_STATE_IDLE;
WIFI_HAL_WPA_SUP_SCAN_STATE cur_scan_state_from_supp = WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE;
extern WIFI_HAL_WPA_SUP_SCAN_STATE cur_scan_state;

char event_buf[4096];                   /* Buffer to store the event results */
char currSsid[MAX_SSID_LEN+1];
bool stop_monitor;
bool kill_wpa_supplicant=false;
static int save_ssid_to_conf=0;                  /* Variable to check whether to save to conf file - Default value is 1 (Will save to conf file) */ 
size_t event_buf_len;

/****** Helper functions ******/
char* getValue(char *buf, char *keyword) {
    char *ptr = NULL;
 
    if(buf == NULL)
        return NULL;
    /* Goto the place where keyword is located in the string */
    ptr = strstr(buf, keyword);
    if (ptr == NULL) return NULL;
 
    strtok(ptr, "=");
    return (strtok(NULL, "\n"));
 
}

char trimSpace(char *srcStr)
{
  char *tmpPtr1;
  char *tmpPtr2;
  for(tmpPtr2=tmpPtr1=srcStr;*tmpPtr1;tmpPtr1++)
  {
        if(!isspace(*tmpPtr1))
           *tmpPtr2++ = *tmpPtr1;
}
  *tmpPtr2 = '\0';
  return 1;
}
 
int wpaCtrlSendCmd(char *cmd) {
    size_t return_len=sizeof(return_buf)-1;
    int ret;
   
    memset(return_buf, 0, return_len);
    if(NULL == g_wpa_ctrl) {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Control interface is NULL. \n");
        return -1;
    }

    ret = wpa_ctrl_request(g_wpa_ctrl, cmd, strlen(cmd), return_buf, &return_len, NULL);

    if (ret == -2) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: cmd=%s timed out \n", cmd);
        return -2;
    } else if (ret < 0) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: cmd=%s failed \n", cmd);
        return -1;
    }
    return 0;        
}

int print_current_ssid_from_scan(char *scanResults)
{
    char *ptrToken,*ptr;
    char ssid[MAX_SSID_LEN+1];
    char bssid[32];
    char rssi[8];
    char ret=0;
    if (scanResults == NULL)
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: scanresults buffer empty");
        return 0;
    }
    ptr = strstr(scanResults,"/ ssid");
    if (ptr == NULL)
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: scanresults not in proper format");
        return 0;
    }
    if (currSsid[0] == '\0')
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: no currSsid");
        return 0;
    }
    ptr += strlen("/ ssid") + 1;
    ptrToken = strtok (ptr,"\n");
    while ((ptrToken != NULL))
    {
        ssid[0] = '\0';
        bssid[0] = '\0';
        rssi[0] = '\0';
        sscanf(ptrToken,"%31s %*s %7s %*s %32s",bssid,rssi,ssid);
        if((ssid[0] != '\0') && (strcmp(ssid,currSsid) == 0))
        {
                RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: bssid = %s rssi = %s ssid = %s \n",bssid,rssi,ssid);
            ret=1;
        }
        else
        {
            RDK_LOG( RDK_LOG_TRACE1, LOG_NMGR,"WIFI_HAL: No SSID match bssid = %s rssi = %s ssid = %s \n",bssid,rssi,ssid);
        }
        ptrToken = strtok (NULL, "\n");
    }
    if(!ret)
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: scan results didnt have ssid %s",currSsid);
    return ret;
}
/******************************/

/*********Callback thread to send messages to Network Service Manager *********/
void monitor_thread_task(void *param)
{
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Inside monitor thread task \n");
    char *start;
    char *ptr = NULL;
    char *curr_ssid=NULL;                                       /* Store the name of the SSID here to send back to Network Service Manager */
    char *curr_bssid=NULL;                                      /* Store the name of the BSSID here to send back to Network Service Manager */
    char ssid[MAX_SSID_LEN+1];
    char tmp_return_buf[8192];
    char *tmpPtr;
    
    wifiStatusCode_t connError;

    while ((stop_monitor != true) && (g_wpa_monitor != NULL)) {
        if (wpa_ctrl_pending(g_wpa_monitor) > 0) {            
            
            memset(event_buf, 0, sizeof(event_buf));
            event_buf_len = sizeof(event_buf) - 1;
            
            if (0 == wpa_ctrl_recv(g_wpa_monitor, event_buf, &event_buf_len)) {
                // RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa supplicant async monitor messsage recv:%s \n", event_buf);
                start = strchr(event_buf, '>');
                if (start == NULL) continue;
                if ((strstr(start, WPA_EVENT_SCAN_STARTED) != NULL)&&(!bNoAutoScan)) {
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Scanning started \n");
                    
                    /* Flush the BSS everytime so that there is no stale information */
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Flushing the BSS now\n");
                    pthread_mutex_lock(&wpa_sup_lock);
                    wpaCtrlSendCmd("GET_NETWORK 0 ssid");
                    if(return_buf[0] != '\0')
                    {
                        
                        sscanf(return_buf,"\"%[^\"]\"",currSsid);
                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Current ssid %s \n",currSsid);
                    }
                    else
                    {
                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Current SSID empty \n");
                    }

                    wpaCtrlSendCmd("BSS_FLUSH 0"); 

                    if (cur_scan_state == WIFI_HAL_WPA_SUP_SCAN_STATE_CMD_SENT)
                        cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED;
                    pthread_mutex_unlock(&wpa_sup_lock);
                } 
                
                else if (strstr(start, WPA_EVENT_SCAN_RESULTS) != NULL) {
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Scanning results received \n");
                    if(!bNoAutoScan)
                    {
                        pthread_mutex_lock(&wpa_sup_lock);
                        return_buf[0]='\0';
                        wpaCtrlSendCmd("SCAN_RESULTS");
                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Buffer Length = %d \n",strlen(return_buf));
                        if (return_buf[0] != '\0')
                        {
                            print_current_ssid_from_scan(return_buf);
                        }
                        else
                        {
                            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Malloc Failed in Scanning results \n");
                        }
                        pthread_mutex_unlock(&wpa_sup_lock);

                    }
                    else
                    {

                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Application is running wifi scan so skipping \n");
                    }
                    if (cur_scan_state == WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED) {
                        pthread_mutex_lock(&wpa_sup_lock);
                        cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED;
                        pthread_mutex_unlock(&wpa_sup_lock);
                    }
                }
             
                else if((strstr(start, WPS_EVENT_AP_AVAILABLE_PBC) != NULL)){
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: WPS Connection in progress\n");
                    connError = WIFI_HAL_CONNECTING;
                    /* Trigger callback to Network Service Manager */
                    if (callback_connect) (*callback_connect)(1, ssid, &connError);
                } 
 
                else if(strstr(start, WPS_EVENT_TIMEOUT) != NULL) {
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: WPS Connection timeout\n");
                    connError = WIFI_HAL_ERROR_NOT_FOUND;
                    if (callback_disconnect) (*callback_disconnect)(1, "", &connError);
                }

                else if(strstr(start, WPS_EVENT_SUCCESS) != NULL) {
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: WPS is successful...Associating now\n");
                }
                
                else if(strstr(start, WPA_EVENT_CONNECTED) != NULL) {
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Authentication completed successfully and data connection enabled\n");
                    
                    pthread_mutex_lock(&wpa_sup_lock);
                    /* Save the configuration */
                    if(save_ssid_to_conf){
                        wpaCtrlSendCmd("SAVE_CONFIG");
                        bUpdatedSSIDInfo=1;
                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"[%s:%d] WIFI_HAL: Configuration Saved \n",__FUNCTION__,__LINE__);
                    }
                    wpaCtrlSendCmd("STATUS");
                    memset(tmp_return_buf,0,sizeof(tmp_return_buf));
                    strncpy(tmp_return_buf,return_buf,sizeof(tmp_return_buf));
                    curr_bssid = getValue(return_buf, "bssid");
                    if(curr_bssid)
                    {
                        /* Returning the BSSID that the client is connected to */
                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"bssid=%s \n", curr_bssid);
                        ptr = curr_bssid + strlen(curr_bssid) + 1;
                    }
                    else
                    {
                        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"BSSID is NULL \n");
                        if(tmp_return_buf[0] != '\0')
                            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Status output = %s \n",tmp_return_buf); // Added for getting reason for BSSID get failure
                        else
                            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Status output is NULL \n");
                    }
                    curr_ssid = getValue(ptr, "ssid");
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"ssid=%s \n", curr_ssid);
                    
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Successfully connected to AP:%s\n", curr_ssid);
                    if(curr_ssid)
                        strcpy(ssid, curr_ssid);
                    pthread_mutex_unlock(&wpa_sup_lock);
                    
                    connError = WIFI_HAL_SUCCESS;
                    
                    //pthread_mutex_lock(&wpa_sup_lock);
                    /* Save the BSSID in the configuration file */
//                    sprintf(cmd_buf, "SET_NETWORK 0 bssid %s",curr_bssid);
//                    wpaCtrlSendCmd(cmd_buf);
                    
                    /* Do not store the PSK in the config file */
                    //wpaCtrlSendCmd("SET_NETWORK 0 mem_only_psk 1");
                    
                    //pthread_mutex_unlock(&wpa_sup_lock);
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"The SSID is:%s\n", ssid);
                    /* Trigger callback to Network Service Manager */
                    if (callback_connect) (*callback_connect)(1, ssid, &connError);
                }
                
                else if(strstr(start, WPA_EVENT_DISCONNECTED) != NULL) {
                    
                    pthread_mutex_lock(&wpa_sup_lock);
                    wpaCtrlSendCmd("GET_NETWORK 0 ssid");
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Disconnected from the network:%s\n", return_buf);
                    pthread_mutex_unlock(&wpa_sup_lock);
                    connError = WIFI_HAL_SUCCESS;
                    if (callback_disconnect) (*callback_disconnect)(1, return_buf, &connError);
                }
                
                else if(strstr(start, WPA_EVENT_TEMP_DISABLED) != NULL){
                    const static char WRONG_KEY[] = "WRONG_KEY";
                    const static char AUTH_FAILED[] = "AUTH_FAILED";
                    const static char CONN_FAILED[] = "CONN_FAILED";
                    const char* reason_string = strstr (start, "reason=");
                    if (NULL == reason_string)
                        connError = WIFI_HAL_ERROR_CONNECTION_FAILED; // TODO: default to WIFI_HAL_ERROR_CONNECTION_FAILED for "no reason" ?
                    else if (0 == strncmp (reason_string+7, WRONG_KEY, strlen(WRONG_KEY)))
                        connError = WIFI_HAL_ERROR_INVALID_CREDENTIALS;
                    else if (0 == strncmp (reason_string+7, AUTH_FAILED, strlen(AUTH_FAILED)))
                        connError = WIFI_HAL_ERROR_AUTH_FAILED;
                    else if (0 == strncmp (reason_string+7, CONN_FAILED, strlen(CONN_FAILED)))
                        connError = WIFI_HAL_ERROR_CONNECTION_FAILED;
                    else
                        connError = WIFI_HAL_ERROR_CONNECTION_FAILED; // TODO: default to WIFI_HAL_ERROR_CONNECTION_FAILED for "no valid reason" ?

                    const char* additional_info = strstr (start, "auth_failures=");
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Network authentication failure (connError=%d, %s)\n", connError, additional_info);

                    pthread_mutex_lock(&wpa_sup_lock);
                    /* Get the SSID that is currently in the conf file */
                    wpaCtrlSendCmd("GET_NETWORK 0 ssid");

                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Disconnected from the network:%s\n", return_buf);
                    pthread_mutex_unlock(&wpa_sup_lock);

                    (*callback_connect)(1, return_buf, &connError);
                }
                
                else if((strstr(start, WPA_EVENT_NETWORK_NOT_FOUND) != NULL)&&(!bNoAutoScan)) {
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Received a network not found event\n");
                    connError = WIFI_HAL_ERROR_NOT_FOUND;
                    
                    if(curr_bssid)
                    {
                    /* Get the BSSID of the last connected network */
//                    wpaCtrlSendCmd("GET_NETWORK 0 bssid");
                    
 /*                   if(strstr(return_buf,"FAIL") != NULL){
                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Connecting to incorrect SSID or previous info has been cleared\n");
                        connError = WIFI_HAL_ERROR_NOT_FOUND;
                        pthread_mutex_unlock(&wpa_sup_lock);
                        if (callback_disconnect) (*callback_disconnect)(1, return_buf, &connError);
                    }
                    else{*/
                        /* Pass in the BSSID to the supplicant and check if the AP exists */
                        pthread_mutex_lock(&wpa_sup_lock);
                        sprintf(cmd_buf, "BSS %s", curr_bssid);
                        wpaCtrlSendCmd(cmd_buf);
                        
                        /* Check whether AP is in range or not */
                        if(strcmp(return_buf,"") == 0) {
                            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: The AP is down or not within range\n");
                            wpaCtrlSendCmd("GET_NETWORK 0 ssid");
                            pthread_mutex_unlock(&wpa_sup_lock);
                            if (callback_disconnect) (*callback_disconnect)(1, return_buf, &connError);
                        }
                        else{ /* Check whether the SSID has changed */
                            
                            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: The SSID of the AP has changed\n");
                            connError = WIFI_HAL_ERROR_SSID_CHANGED;
                            /* Get the ssid info from the config file */
                            wpaCtrlSendCmd("GET_NETWORK 0 ssid");
                            pthread_mutex_unlock(&wpa_sup_lock);
                            if (callback_disconnect) (*callback_disconnect)(1, return_buf, &connError);
                        }
                    } /* else part for checking if BSS has bssid */
                    else
                    {
                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Connecting to incorrect SSID or previous info has been cleared\n");
                        if (callback_disconnect) (*callback_disconnect)(1, return_buf, &connError);
                    }
                } /* WPA_EVENT_NETWORK_NOT_FOUND */ 
                
                else {
                    continue;
                }                
            }
        } 
        else {
            usleep(WPA_SUP_TIMEOUT);
        }
    } /* End while loop */
    kill_wpa_supplicant=true;        
} /* End monitor_thread function */


void wifi_getStats(INT radioIndex, wifi_sta_stats_t *stats)
{
    char *ptr;
    char *bssid, *ssid;
    int phyrate, noise, rssi;
    int retStatus = -1;

    if(NULL == stats)
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Input Stats is NULL \n");
        return;
    }
        
    /* Find the currently connected BSSID and run signal_poll command to get the stats */
    pthread_mutex_lock(&wpa_sup_lock);
    retStatus = wpaCtrlSendCmd("STATUS");
    if(retStatus == 0)
    {
        bssid = getValue(return_buf, "bssid");
        if (bssid == NULL) 
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: BSSID is NULL in Status output\n");
            goto exit;
        }
        else
            strcpy(stats->sta_BSSID, bssid);
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"bssid=%s \n", bssid);
        ptr = bssid + strlen(bssid) + 1;
        ssid = getValue(ptr, "ssid");
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"ssid=%s \n", ssid);
        if (ssid == NULL) 
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: SSID is NULL in Status output\n");
            goto exit;
        }
        else
            strcpy(stats->sta_SSID, ssid);
    }
    else
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: wpaCtrlSendCmd(STATUS) failed - Ret = %d \n",retStatus);
    }

    retStatus = wpaCtrlSendCmd("SIGNAL_POLL");
    if(retStatus == 0)
    {
        ptr = getValue(return_buf, "RSSI");
    
        if (ptr == NULL)
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: RSSI not in signal poll \n");
            goto exit;
        }
        else {
            rssi = atoi(ptr);
            stats->sta_RSSI = rssi; 
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"rssi=%d \n", rssi);
        }
        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "LINKSPEED");
        if (ptr == NULL)
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: LINKSPEED not in signal poll \n");
            goto exit;
        }
        else {
            phyrate = atoi(ptr);
            stats->sta_PhyRate = phyrate; 
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"phyrate=%d \n", phyrate);
        }    
    
        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "NOISE");
        if (ptr == NULL)
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: NOISE not in signal poll \n");
            goto exit;
        }
        else {
            noise = atoi(ptr);
            stats->sta_Noise = noise; 
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"noise=%d \n", noise);
        }
    }
    else
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: wpaCtrlSendCmd(SIGNAL_POLL) failed ret = %d\n",retStatus);
    }
exit:
    pthread_mutex_unlock(&wpa_sup_lock);
    return;
}


/**************************************************************************************************/
/*WIFI WPS Related Functions                                                                      */
/**************************************************************************************************/

INT wifi_getCliWpsEnable(INT ssidIndex, BOOL *output_bool){
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  return RETURN_OK;
}

INT wifi_setCliWpsEnable(INT ssidIndex, BOOL enableValue){
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  return RETURN_OK;
}

INT wifi_getCliWpsDevicePIN(INT ssidIndex, ULONG *output_ulong){ //Where does the PIN come from?
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  return RETURN_OK;
}

INT wifi_setCliWpsDevicePIN(INT ssidIndex, ULONG pin){
#if 0  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID:%d\n", ssidIndex);
  uint32_t wps_pin = 0;
  if(NetAppWiFiGenerateWPSPin(hNetApp, &wps_pin) == NETAPP_SUCCESS){      //Trying to generate the pin and checking if the result is a success
    pin = wps_pin;
    return RETURN_OK;
  }
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Error setting the device pin\n");
  return RETURN_ERR; 
#endif
return RETURN_OK;
}

INT wifi_getCliWpsConfigMethodsSupported(INT ssidIndex, CHAR *methods){
  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  //Return all the methods: Push and Pin
 
  if (!is_null_pointer(methods)){
    strcpy(methods, "Push and Pin");
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Supported Methods: Push and Pin\n");
    return RETURN_OK;
  }
  return RETURN_ERR;
}

INT wifi_getCliWpsConfigMethodsEnabled(INT ssidIndex, CHAR *output_string){
  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  //I think returning push and pin for this would be acceptable
  if (!is_null_pointer(output_string)){
    strcpy(output_string, "Push and Pull");
    return RETURN_OK;
  }
  return RETURN_ERR;
}

INT wifi_setCliWpsConfigMethodsEnabled(INT ssidIndex, CHAR *methodString){
 
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  if (!is_null_pointer(methodString)){
    strcpy(methodString, "Push and Pin");
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Supported Methods: Push and Pin\n");
    return RETURN_OK;
  }
  return RETURN_ERR;
}

INT wifi_getCliWpsConfigurationState(INT ssidIndex, CHAR *output_string){
 
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  return RETURN_OK;
}

INT wifi_setCliWpsEnrolleePin(INT ssidIndex, CHAR *EnrolleePin){

 #if 0
  INT* pinValue = 0;
  *pinValue = atoi(EnrolleePin);
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  if(NetAppWiFiConnectByPin(hNetApp, NETAPP_IFACE_WIRELESS, NULL, *pinValue, true) == NETAPP_SUCCESS){   //Connecting to the device using a pin and checking the result
    return RETURN_OK;
  }
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Error connecting to device with enrollee pin... Check again\n");
  return RETURN_ERR;
#endif 
return RETURN_OK; 
}

INT wifi_setCliWpsButtonPush(INT ssidIndex){
 
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  
  size_t return_len=sizeof(return_buf)-1;                                                                /* Return length of the buffer */
  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: WPS Push Button Call\n");
  
  pthread_mutex_lock(&wpa_sup_lock);
  
  if (cur_sup_state != WIFI_HAL_WPA_SUP_STATE_IDLE) {
        pthread_mutex_unlock(&wpa_sup_lock);
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Connection is in progress, returning error \n");
        return RETURN_ERR;
  }

  save_ssid_to_conf=1;
  wpaCtrlSendCmd("REMOVE_NETWORK 0");
  wpaCtrlSendCmd("SAVE_CONFIG");
  bUpdatedSSIDInfo=1;
 
  wpaCtrlSendCmd("WPS_PBC");
  pthread_mutex_unlock(&wpa_sup_lock);

  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Will be timing out if AP not found after 120 seconds\n");

  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Deleting conf file and making a new one\n");

  if(remove("/opt/wifi/wpa_supplicant.conf") == 0){
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Removed File\n");
  }

  FILE* fp;
  fp = fopen("/opt/wifi/wpa_supplicant.conf", "w");
  if(fp == NULL){
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Error in opening configuration file\n");
    return RETURN_ERR;
  }
  fprintf(fp, "ctrl_interface=/var/run/wpa_supplicant\n");
  fprintf(fp, "update_config=1\n");
  fclose(fp);

  wifiStatusCode_t connError;
  connError = WIFI_HAL_CONNECTING;
  (*callback_connect)(1, "", &connError);
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Connection in progress..\n");
   
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI HAL: WPS Push sent successfully\n");
  return RETURN_OK;
}

INT wifi_connectEndpoint(INT ssidIndex, CHAR *AP_SSID, wifiSecurityMode_t AP_security_mode, CHAR *AP_security_WEPKey, CHAR *AP_security_PreSharedKey, CHAR *AP_security_KeyPassphrase,int saveSSID,CHAR * eapIdentity,CHAR * carootcert,CHAR * clientcert,CHAR * privatekey){
  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Save SSID value:%d\n", saveSSID);
  
  if(saveSSID){
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Saving to the conf file\n");
      save_ssid_to_conf = 1;
  }
  else{
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Will not save anything to conf file\n");
      save_ssid_to_conf = 0;
  } 
  
  pthread_mutex_lock(&wpa_sup_lock);                                 /* Locking in the mutex before connect */
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Requesting connection to AP\n");
  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL:Security mode:%d\n", AP_security_mode);
   
  wpaCtrlSendCmd("REMOVE_NETWORK 0");
  
  wpaCtrlSendCmd("ADD_NETWORK");

  wpaCtrlSendCmd("SET_NETWORK 0 auth_alg OPEN");
  
  /* Set SSID */
  sprintf(cmd_buf, "SET_NETWORK 0 ssid \"%s\"", AP_SSID);
  wpaCtrlSendCmd(cmd_buf);
  
  if((AP_security_mode == WIFI_SECURITY_WPA_PSK_AES) || (AP_security_mode == WIFI_SECURITY_WPA2_PSK_AES) || (AP_security_mode == WIFI_SECURITY_WPA_PSK_TKIP) || (AP_security_mode == WIFI_SECURITY_WPA2_PSK_TKIP)){
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Security mode is PSK\n");
      /* Key Management */
      sprintf(cmd_buf, "SET_NETWORK 0 key_mgmt WPA-PSK");
      wpaCtrlSendCmd(cmd_buf);
      /* Set the PSK */
      sprintf(cmd_buf, "SET_NETWORK 0 psk \"%s\"", AP_security_PreSharedKey);
      wpaCtrlSendCmd(cmd_buf);
      if(strstr(return_buf, "FAIL") != NULL){
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Password may not be falling within spec\n");
        wifiStatusCode_t connError;
        connError = WIFI_HAL_ERROR_INVALID_CREDENTIALS;
        (*callback_connect)(1, AP_SSID, &connError);
  	pthread_mutex_unlock(&wpa_sup_lock);
        return RETURN_OK;
      }
  }
  else if((AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_TKIP) || (AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_AES) || (AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_TKIP) || (AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_AES)){
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Security mode is WPA Enterprise\n");
      sprintf(cmd_buf, "SET_NETWORK 0 key_mgmt WPA-EAP");
      wpaCtrlSendCmd(cmd_buf);
  }
  else{
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: None\n");
      sprintf(cmd_buf, "SET_NETWORK 0 key_mgmt NONE");
      wpaCtrlSendCmd(cmd_buf);
//      sprintf(cmd_buf, "SET_NETWORK 0 wep_key0 \"%s\"", AP_security_KeyPassphrase);
//      wpaCtrlSendCmd(cmd_buf);
  }
  
  /* Allow us to connect to hidden SSIDs */
  wpaCtrlSendCmd("SET_NETWORK 0 scan_ssid 1");
      
  if((AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_TKIP) || (AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_AES) || (AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_TKIP) ||
      (AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_AES)|| (AP_security_mode == WIFI_SECURITY_WPA_PSK_AES) || (AP_security_mode == WIFI_SECURITY_WPA2_PSK_AES)){
          
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Setting TKIP values\n");
    
      wpaCtrlSendCmd("SET_NETWORK 0 pairwise CCMP TKIP");
          
      wpaCtrlSendCmd("SET_NETWORK 0 group CCMP TKIP");
          
      wpaCtrlSendCmd("SET_NETWORK 0 proto WPA RSN");
  }
  
  if((AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_TKIP) || (AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_AES) || (AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_TKIP) || (AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_AES)){
    
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL:EAP Identity %s\n", eapIdentity);
      sprintf(cmd_buf, "SET_NETWORK 0 identity \"%s\"", eapIdentity);
      
      wpaCtrlSendCmd(cmd_buf);

      wpaCtrlSendCmd("SET_NETWORK 0 eap TLS");
  }
  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: The carootcert:%s\n", carootcert);
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: The clientcert:%s\n", clientcert);
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: The privatekey:%s\n", privatekey);
  RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: The PSK key:%s\n", AP_security_PreSharedKey);
  RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: The KeyP key:%s\n", AP_security_KeyPassphrase);
  
  /* EAP with certificates */
  if (access(carootcert, F_OK) != -1){
      
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: CA Root certificate exists\n");
      sprintf(cmd_buf, "SET_NETWORK 0 ca_cert \"%s\"", carootcert);
      wpaCtrlSendCmd(cmd_buf);
  }

  if (access(clientcert, F_OK) != -1){
      
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Client Certificate exists\n");
      sprintf(cmd_buf, "SET_NETWORK 0 client_cert \"%s\"", clientcert);
      wpaCtrlSendCmd(cmd_buf);
  }

  if (access(privatekey, F_OK) != -1){
      
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Private Key exists\n");
      sprintf(cmd_buf, "SET_NETWORK 0 private_key \"%s\"", privatekey);
      wpaCtrlSendCmd(cmd_buf);
      
      sprintf(cmd_buf, "SET_NETWORK 0 private_key_passwd \"%s\"", AP_security_KeyPassphrase);
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Command is:%s\n", cmd_buf);
      wpaCtrlSendCmd(cmd_buf);
  }
  
  wpaCtrlSendCmd("SET_NETWORK 0 mode 0");
  
  wpaCtrlSendCmd("SELECT_NETWORK 0");
  
  wpaCtrlSendCmd("ENABLE_NETWORK 0");
  
  wpaCtrlSendCmd("REASSOCIATE");
  
  if(saveSSID){
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Connecting to the specified access point\n");
    wifiStatusCode_t connError;
    connError = WIFI_HAL_CONNECTING;
    if (callback_connect) (*callback_connect)(1, AP_SSID, &connError);    
  }    

  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Leaving WiFi Connect Endpoint function\n");
  pthread_mutex_unlock(&wpa_sup_lock);
  return RETURN_OK;
}

INT wifi_lastConnected_Endpoint(wifi_pairedSSIDInfo_t *pairedSSIDInfo){
    char buf[512];
    static char ssid[32]={0};
    static char bssid[20]={0};
    static char security[64]={0};
    static char passphrase[64]={0};
    char *tokenKey;
    char *tokenValue;
    FILE *f = NULL;

    if(!bUpdatedSSIDInfo)
    {
        strcpy(pairedSSIDInfo->ap_ssid, ssid);
        strcpy(pairedSSIDInfo->ap_bssid, bssid);
        strcpy(pairedSSIDInfo->ap_security, security);
        strcpy(pairedSSIDInfo->ap_passphrase,passphrase);
        return RETURN_OK;
    }
    f = fopen("/opt/wifi/wpa_supplicant.conf", "r");
    if(NULL == f)
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to open wpa_supplicant.conf\n");
        return RETURN_ERR;
    }
    while( fgets(buf, 512, f) != NULL) {
        tokenKey=strtok(buf,"\"=");
        tokenValue=strtok(NULL,"\"=");
        trimSpace(tokenKey);
        if((tokenValue != NULL) && (strcasecmp(tokenKey,"ssid") == 0))
        {
            strcpy(pairedSSIDInfo->ap_ssid,tokenValue);
            strcpy(ssid,tokenValue);
            bUpdatedSSIDInfo=0;
        }
        else if((tokenValue != NULL) && (strcasecmp(tokenKey,"psk") == 0))
        {
            strcpy(pairedSSIDInfo->ap_passphrase,tokenValue);
            strcpy(passphrase,tokenValue);
        }
        else if((tokenValue != NULL) && (strcasecmp(tokenKey,"bssid") == 0))
        {
            strcpy(pairedSSIDInfo->ap_bssid,tokenValue);
            strcpy(bssid,tokenValue);
        }
        else if((tokenValue != NULL) && (strcasecmp(tokenKey,"key_mgmt") == 0))
        {
            strcpy(pairedSSIDInfo->ap_security,tokenValue);
            strcpy(security,tokenValue);
        }
    }
    fclose(f);
    return RETURN_OK;
}

INT wifi_disconnectEndpoint(INT ssidIndex, CHAR *AP_SSID){

 RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
 
 RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Received request to disconnect from AP\n");
 
 wpaCtrlSendCmd("DISCONNECT");
 
 return RETURN_OK;
}

//Callback registration function.

void wifi_connectEndpoint_callback_register(wifi_connectEndpoint_callback callback_proc){

  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Registering connect callback...\n");
  callback_connect=callback_proc;

}

//Callback registration function.
void wifi_disconnectEndpoint_callback_register(wifi_disconnectEndpoint_callback callback_proc){

   RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Registering disconnect callback...\n");
   callback_disconnect=callback_proc;
}

