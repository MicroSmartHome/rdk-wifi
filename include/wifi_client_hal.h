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

/**********************************************************************

    module: wifi_client_hal.h

        For CCSP Component:  Wifi_Provisioning_and_management

    ---------------------------------------------------------------


    description:

        This header file gives the function call prototypes and
        structure definitions used for the RDK-Broadband
        Wifi client hardware abstraction layer

        NOTE:
        THIS VERSION IS AN EARLY DRAFT INTENDED TO GET COMMENTS FROM COMCAST.
        TESTING HAS NOT YET BEEN COMPLETED.

    ---------------------------------------------------------------

    environment:

        This HAL layer is intended to support Wifi drivers
        through an open API.

    ---------------------------------------------------------------

    author:

        zhicheng_qiu@cable.comcast.com


**********************************************************************/


#ifndef __WIFI_CLINET_HAL_H__
#define __WIFI_CLINET_HAL_H__

#include <wifi_common_hal.h>

//----------------------------------------------------------------------------------------------------
//Device.WiFi.EndPoint //EndPoint list is mananged by RDKB wifi agent
//Device.WiFi.EndPoint.{i}.Enable
//Device.WiFi.EndPoint.{i}.Status
//Device.WiFi.EndPoint.{i}.Alias
//Device.WiFi.EndPoint.{i}.ProfileReference
//Device.WiFi.EndPoint.{i}.SSIDReference
//Device.WiFi.EndPoint.{i}.ProfileNumberOfEntries
//----------------------------------------------------------------------------------------------------
//Device.WiFi.EndPoint.{i}.Stats.LastDataDownlinkRate
//Device.WiFi.EndPoint.{i}.Stats.LastDataUplinkRate
//Device.WiFi.EndPoint.{i}.Stats.SignalStrength
//Device.WiFi.EndPoint.{i}.Stats.Retransmissions
//----------------------------------------------------------------------------------------------------
//Device.WiFi.EndPoint.{i}.Security
//Device.WiFi.EndPoint.{i}.Security.ModesSupported
//----------------------------------------------------------------------------------------------------
//Device.WiFi.EndPoint.{i}.Profile
//Device.WiFi.EndPoint.{i}.Profile.{i}.Enable
//Device.WiFi.EndPoint.{i}.Profile.{i}.Status
//Device.WiFi.EndPoint.{i}.Profile.{i}.Alias
//Device.WiFi.EndPoint.{i}.Profile.{i}.SSID
//Device.WiFi.EndPoint.{i}.Profile.{i}.Location
//Device.WiFi.EndPoint.{i}.Profile.{i}.Priority
//----------------------------------------------------------------------------------------------------
//Device.WiFi.EndPoint.{i}.Profile.{i}.Security.ModeEnabled
//Device.WiFi.EndPoint.{i}.Profile.{i}.Security.WEPKey
//Device.WiFi.EndPoint.{i}.Profile.{i}.Security.PreSharedKey
//Device.WiFi.EndPoint.{i}.Profile.{i}.Security.KeyPassphrase
//----------------------------------------------------------------------------------------------------
//Device.WiFi.EndPoint.{i}.WPS
//Device.WiFi.EndPoint.{i}.WPS.Enable
//Device.WiFi.EndPoint.{i}.WPS.ConfigMethodsSupported
//Device.WiFi.EndPoint.{i}.WPS.ConfigMethodsEnabled

//-----------------------------------------------------------------------------------------------------
//AP connection APIs
//1. WPS method
//Get WPS enable status
INT wifi_getCliWpsEnable(INT ssidIndex, BOOL *output_bool);	//RDKB
//Set WPS enable
INT wifi_setCliWpsEnable(INT ssidIndex, BOOL enableValue);	//RDKB
//Read WPS Device pin (it is also printed on the device label)
INT wifi_getCliWpsDevicePIN(INT ssidIndex, ULONG *output_ulong);	//RDKB
//Set WPS Device pin
INT wifi_setCliWpsDevicePIN(INT ssidIndex, ULONG pin);	//RDKB

//Get supported WPS method list. eg "USBFlashDriver,PushButton,PIN"
INT wifi_getCliWpsConfigMethodsSupported(INT ssidIndex, CHAR *methods);		//OEM
//Get the configed enabled WPS method. eg: "PushButton"
INT wifi_getCliWpsConfigMethodsEnabled(INT ssidIndex, CHAR *output_string);	//RDKB
//Set active WPS method.
INT wifi_setCliWpsConfigMethodsEnabled(INT ssidIndex, CHAR *methodString);	//RDKB
//Get the WPS config status. eg: "Not configured", "configured"
INT wifi_getCliWpsConfigurationState(INT ssidIndex, CHAR *output_string);	//RDKB	//OEM
//User get the EnrolleePin (device pin from AP device) give to hostapd for paring
INT wifi_setCliWpsEnrolleePin(INT ssidIndex, CHAR *EnrolleePin);	//RDKB
//Start the Push button pairing
INT wifi_setCliWpsButtonPush(INT ssidIndex);	//RDKB
//Stop the WPS process
INT wifi_cancelCliWPS(INT ssidIndex);	//RDKB

//2. Directly pairing method
//Connect to specified AP
INT wifi_connectEndpoint(INT ssidIndex, CHAR *AP_SSID, wifiSecurityMode_t AP_security_mode, CHAR *AP_security_WEPKey, CHAR *AP_security_PreSharedKey, CHAR *AP_security_KeyPassphrase,int saveSSID);	//Tr181

//Disconnect to specified AP
INT wifi_disconnectEndpoint(INT ssidIndex, CHAR *AP_SSID);

//This call back will be invoked when client lost the connection to AP.
typedef INT (*wifi_disconnectEndpoint_callback)(INT ssidIndex, CHAR *AP_SSID, wifiStatusCode_t *error);
//Callback registration function.
void wifi_disconnectEndpoint_callback_register(wifi_disconnectEndpoint_callback callback_proc);

//This call back will be invoked when client automatically connect to AP.
typedef INT (*wifi_connectEndpoint_callback)(INT ssidIndex, CHAR *AP_SSID, wifiStatusCode_t *error);
//Callback registration function.
void wifi_connectEndpoint_callback_register(wifi_connectEndpoint_callback callback_proc);

//This call will give the last saved AP's ssid.
// If previously connected SSSID present, the return as 'RETURN_OK' else 'RETURN_ERR'.
INT wifi_lastConnected_Endpoint(CHAR *ap_ssid,CHAR *ap_passphrase);

#else
#error "! __WIFI_CLINET_HAL_H__"
#endif

