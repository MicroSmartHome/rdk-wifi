/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
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
#include "wifi_client_hal.h"
INT ssidIndex = 12;
CHAR* AP_SSID = "BRCMHAL";
wifi_connectEndpoint_callback callback_connect;
wifi_disconnectEndpoint_callback callback_disconnect;
wifiStatusCode_t connError;
INT wifi_setCliWpsButtonPush(INT ssidIndex){
 
  printf("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  connError=WIFI_HAL_SUCCESS;
//  connError=WIFI_HAL_ERROR_CON_ACTIVATION;
  (*callback_connect)(1,"thomson",&connError);
   return RETURN_OK;
}

void wifi_connectEndpoint_callback_register(wifi_connectEndpoint_callback callback_proc){
 
  printf("Connecting to Access Point...\n");
  //callback_proc(ssidIndex, AP_SSID);
  callback_connect=callback_proc;
}
//Callback registration function.
void wifi_disconnectEndpoint_callback_register(wifi_disconnectEndpoint_callback callback_proc){
   
   printf("Disconnect in progress...\n");
   callback_disconnect=callback_proc;
}

INT wifi_disconnectEndpoint(INT ssidIndex, CHAR *AP_SSID){
 printf("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
 printf("disconnecting from %s", AP_SSID);
  connError=WIFI_HAL_SUCCESS;
//  connError=WIFI_HAL_ERROR_CON_ACTIVATION;
  (*callback_disconnect)(1,"thomson",&connError);
  return RETURN_OK;
}

INT wifi_connectEndpoint(INT ssidIndex, CHAR *AP_SSID, wifiSecurityMode_t AP_security_mode, CHAR *AP_security_WEPKey, CHAR *AP_security_PreSharedKey, CHAR *AP_security_KeyPassphrase,int storeSSID)
{
  	connError=WIFI_HAL_SUCCESS;
	//  connError=WIFI_HAL_ERROR_CON_ACTIVATION;
  	(*callback_connect)(1,"RDK-123",&connError);
	 return RETURN_OK;
}
INT wifi_getCliWpsEnable(INT ssidIndex, BOOL *output_bool){
  printf("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  return RETURN_OK;
}
INT wifi_setCliWpsEnable(INT ssidIndex, BOOL enableValue){
  printf("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  return RETURN_OK;
}
INT wifi_getCliWpsDevicePIN(INT ssidIndex, ULONG *output_ulong){ //Where does the PIN come from?
  printf("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  return RETURN_OK;
}
INT wifi_setCliWpsDevicePIN(INT ssidIndex, ULONG pin){
  
    return RETURN_OK;
}
INT wifi_getCliWpsConfigMethodsSupported(INT ssidIndex, CHAR *methods){
  
  printf("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  //Return all the methods: Push and Pin
  if ((methods !=NULL) && (methods[0]=='\0')){
    strcpy(methods, "Push and Pin");
    printf("Supported Methods: Push and Pin\n");
    return RETURN_OK;
  }
  return RETURN_ERR;
}
INT wifi_getCliWpsConfigMethodsEnabled(INT ssidIndex, CHAR *output_string){
  
  printf("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  //I think returning push and pin for this would be acceptable
  if ((output_string !=NULL) && (output_string[0]=='\0')){
    strcpy(output_string, "Push and Pull");
    return RETURN_OK;
  }
  return RETURN_ERR;
}
INT wifi_getCliWpsConfigurationState(INT ssidIndex, CHAR *output_string){
 
  printf("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  return RETURN_OK;
}
INT wifi_setCliWpsEnrolleePin(INT ssidIndex, CHAR *EnrolleePin){
 
  if ((EnrolleePin !=NULL) && (EnrolleePin[0]=='\0')){
  printf("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
    return RETURN_OK;
  }
  printf("Error connecting to device with enrollee pin... Check again\n");
  return RETURN_ERR;
}
