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
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include "wifi_client_hal.h"
#define printf //

#ifndef RADIO_PREFIX
#define RADIO_PREFIX	"wifi"
#endif

typedef struct _wifi_radioValues
{
    CHAR OperatingChannelBandwidth[64];
    CHAR ExtChannel[64];
    CHAR GuardInterval[64];
    INT RadioMCS;
    ULONG TransmitPower;
    CHAR BasicDataTransmitRates[64];

} wifi_radioValues_t;

wifi_radioValues_t dummy_radioValues[] = { {"20MHz","BelowControlChannel","400nsec",-1,75,"1,2"},{"40MHz","AboveControlChannel","800nsec",1,100,"1.5,150"}};


wifi_radioTrafficStats_t dummy_radioTrafficStats = {1268,189263735,30,2625252,5,76,23,76,12,24,3,2,-40,80,50,25,34,20,65,93,2015080554};
wifi_neighbor_ap_t dummy_neighbor_ap[] =
{
    {"COMCAST1", "00:00:00:00:00:a1","AdHoc",1,-50,"WPA","TKIP,AES","2.4GHz","802.11a,802.11b,802.11g,802.11n","802.11g,802.11n","40MHz",10,-10,"1,2,3","1,2",10,{1,2,3}},
    {"COMCAST2", "00:00:00:00:00:a2","Infrastructure",6,-60,"None","TKIP,AES","5GHz","802.11a,802.11b,802.11g,802.11n","802.11g,802.11n","40MHz",10,-10,"1,2,3,4","3,4",10,{1,2,3}},
    {"COMCAST3", "00:00:00:00:00:a3","AdHoc",11,-70,"WPA2","TKIP,AES","2.4GHz","802.11a,802.11b,802.11g,802.11n","802.11g,802.11n","40MHz",10,-10,"1,2,3,4,5","2,3",10,{1,2,3}}
};

UINT wifi_getScanResults(INT radioIndex);


INT wifi_getRadioTrafficStats(INT radioIndex, wifi_radioTrafficStats_t *output_struct)
{
    if(!output_struct)
    {
        printf("output struct is null");
        return 0;
    }
    output_struct->radio_BytesSent=dummy_radioTrafficStats.radio_BytesSent;
    output_struct->radio_BytesReceived=dummy_radioTrafficStats.radio_BytesReceived;
    output_struct->radio_PacketsSent=dummy_radioTrafficStats.radio_PacketsSent;
    output_struct->radio_PacketsReceived=dummy_radioTrafficStats.radio_PacketsReceived;
    output_struct->radio_ErrorsSent=dummy_radioTrafficStats.radio_ErrorsSent;
    output_struct->radio_ErrorsReceived=dummy_radioTrafficStats.radio_ErrorsReceived;
    output_struct->radio_DiscardPacketsSent=dummy_radioTrafficStats.radio_DiscardPacketsSent;
    output_struct->radio_DiscardPacketsReceived=dummy_radioTrafficStats.radio_DiscardPacketsReceived;
    output_struct->radio_PLCPErrorCount=dummy_radioTrafficStats.radio_PLCPErrorCount;
    output_struct->radio_FCSErrorCount=dummy_radioTrafficStats.radio_FCSErrorCount;
    output_struct->radio_InvalidMACCount=dummy_radioTrafficStats.radio_InvalidMACCount;
    output_struct->radio_PacketsOtherReceived=dummy_radioTrafficStats.radio_PacketsOtherReceived;
    output_struct->radio_NoiseFloor=dummy_radioTrafficStats.radio_NoiseFloor;
    output_struct->radio_ChannelUtilization=dummy_radioTrafficStats.radio_ChannelUtilization;
    output_struct->radio_ActivityFactor=dummy_radioTrafficStats.radio_ActivityFactor;
    output_struct->radio_CarrierSenseThreshold_Exceeded=dummy_radioTrafficStats.radio_CarrierSenseThreshold_Exceeded;
    output_struct->radio_RetransmissionMetirc=dummy_radioTrafficStats.radio_RetransmissionMetirc;
    output_struct->radio_MaximumNoiseFloorOnChannel=dummy_radioTrafficStats.radio_MaximumNoiseFloorOnChannel;
    output_struct->radio_MinimumNoiseFloorOnChannel=dummy_radioTrafficStats.radio_MinimumNoiseFloorOnChannel;
    output_struct->radio_MedianNoiseFloorOnChannel=dummy_radioTrafficStats.radio_MedianNoiseFloorOnChannel;
    output_struct->radio_StatisticsStartTime=dummy_radioTrafficStats.radio_StatisticsStartTime;

}

INT wifi_getNeighboringWiFiDiagnosticResult(INT radioIndex, wifi_neighbor_ap_t **neighbor_ap_array, UINT *output_array_size)
{
    int size;
    *output_array_size=wifi_getScanResults(radioIndex);
    printf("size of the AP list %d",*output_array_size);
    size=*output_array_size;
    *neighbor_ap_array = (wifi_neighbor_ap_t *)malloc(size*sizeof(wifi_neighbor_ap_t));
    if(*neighbor_ap_array == NULL)
    {
        printf("Malloc Memory allocation failure\n");
        return 0;
    }
    printf("malloc allocated = %d ", malloc_usable_size(*neighbor_ap_array));
    for(size=0; size < *output_array_size; size++)
    {
        strcpy((*neighbor_ap_array)[size].ap_SSID , dummy_neighbor_ap[size].ap_SSID);
        strcpy((*neighbor_ap_array)[size].ap_BSSID , dummy_neighbor_ap[size].ap_BSSID);
        strcpy((*neighbor_ap_array)[size].ap_Mode , dummy_neighbor_ap[size].ap_Mode);
        (*neighbor_ap_array)[size].ap_Channel = dummy_neighbor_ap[size].ap_Channel;
        (*neighbor_ap_array)[size].ap_SignalStrength = dummy_neighbor_ap[size].ap_SignalStrength;
        strcpy((*neighbor_ap_array)[size].ap_SecurityModeEnabled , dummy_neighbor_ap[size].ap_SecurityModeEnabled);
        strcpy((*neighbor_ap_array)[size].ap_EncryptionMode , dummy_neighbor_ap[size].ap_EncryptionMode);
        strcpy((*neighbor_ap_array)[size].ap_OperatingFrequencyBand , dummy_neighbor_ap[size].ap_OperatingFrequencyBand);
        strcpy((*neighbor_ap_array)[size].ap_SupportedStandards , dummy_neighbor_ap[size].ap_SupportedStandards);
        strcpy((*neighbor_ap_array)[size].ap_OperatingStandards , dummy_neighbor_ap[size].ap_OperatingStandards);
        strcpy((*neighbor_ap_array)[size].ap_OperatingChannelBandwidth , dummy_neighbor_ap[size].ap_OperatingChannelBandwidth);
        (*neighbor_ap_array)[size].ap_BeaconPeriod = dummy_neighbor_ap[size].ap_BeaconPeriod;
        (*neighbor_ap_array)[size].ap_Noise = dummy_neighbor_ap[size].ap_Noise;
        strcpy((*neighbor_ap_array)[size].ap_BasicDataTransferRates , dummy_neighbor_ap[size].ap_BasicDataTransferRates);
        strcpy((*neighbor_ap_array)[size].ap_SupportedDataTransferRates , dummy_neighbor_ap[size].ap_SupportedDataTransferRates);
        (*neighbor_ap_array)[size].ap_DTIMPeriod = dummy_neighbor_ap[size].ap_DTIMPeriod;
        memcpy((*neighbor_ap_array)[size].ap_ChannelUtilization , dummy_neighbor_ap[size].ap_ChannelUtilization,sizeof((*neighbor_ap_array)[size].ap_ChannelUtilization));
        //strcpy((*neighbor_ap_array)[size].ap_SSID, dummy_neighbor_ap[size].ap_SSID);
    }
    return 1;

}

UINT countryCode=841;
BOOL bRadioEnable=FALSE;
UINT runChannelNumber=11;
BOOL bAutoChannelEnable=FALSE;
BOOL bDCSEnable=FALSE;
CHAR DCSChannelPool[256]= {"1,2,3,4,5,6,7,8,9"};
INT intervalSeconds=1800;
INT dwellMilliSeconds=40;
BOOL bDfsEnable=FALSE;
BOOL bIEEE80211hEnabled=FALSE;
INT carrierSenseThresholdInUse=-99;
UINT beaconPeriod=100;
//---------------------------------------------------------------------------------------------------
//Wifi system api
//Get the wifi hal version in string, eg "2.0.0".  WIFI_HAL_MAJOR_VERSION.WIFI_HAL_MINOR_VERSION.WIFI_HAL_MAINTENANCE_VERSION
//---------------------------------------------------------------------------------------------------
INT wifi_getHalVersion(CHAR *output_string)
{
    snprintf(output_string, 64, "%d.%d.%d", WIFI_HAL_MAJOR_VERSION, WIFI_HAL_MINOR_VERSION, WIFI_HAL_MAINTENANCE_VERSION);
    return RETURN_OK;
}

/* wifi_factoryReset() function */
/**
* Description: 
*  Resets Implementation specifics may dictate some functionality since
*  different hardware implementations may have different requirements.
*  Parameters : None
* 
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT wifi_factoryReset()
{
    //TODO: clears internal variables to implement a factory reset of the Wi-Fi subsystem
    return RETURN_OK;
}

/* wifi_factoryResetRadios() function */
/**

* Description:
*  Resets Implementation specifics may dictate some functionality since
*  different hardware implementations may have different requirements.
*  Parameters : None
*

* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.

* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_factoryResetRadios()
{
    //TODO:Restore all radio parameters without touch access point parameters
    return RETURN_OK;
}


/* wifi_factoryResetRadio() function */
/**

* Description:
*  Resets Implementation specifics may dictate some functionality since
*  different hardware implementations may have different requirements.
*  Parameters : None
*

* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.

* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_factoryResetRadio(int radioIndex) 	// G
{
    //TODO:Restore selected radio parameters without touch access point parameters
    return RETURN_OK;
}

/* wifi_initRadio() function */
/**
* Description: This function call initializes the specified radio.
*  Implementation specifics may dictate the functionality since
*  different hardware implementations may have different initilization requirements.
* Parameters : radioIndex - The index of the radio. First radio is index 0. 2nd radio is index 1   - type INT
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_initRadio(INT radioIndex)
{
    //TODO: Initializes the wifi subsystem (for specified radio)

    return RETURN_OK;
}

// Initializes the wifi subsystem (all radios)
INT wifi_init()                            //
{
    //TODO: Initializes the wifi subsystem
    return RETURN_OK;

}

/* wifi_reset() function */
/**
* Description: Resets the Wifi subsystem.  This includes reset of all AP varibles.
*  Implementation specifics may dictate what is actualy reset since
*  different hardware implementations may have different requirements.
* Parameters : None
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_reset()
{
    //TODO: resets the wifi subsystem, deletes all APs
    return RETURN_OK;
}

/* wifi_down() function */
/**
* Description:
*  Turns off transmit power to all radios.
*  Implementation specifics may dictate some functionality since
*  different hardware implementations may have different requirements.
* Parameters : None
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_down()
{
    //TODO: turns off transmit power for the entire Wifi subsystem, for all radios
    return RETURN_OK;
}


/* wifi_createInitialConfigFiles() function */
/**
* Description: 
*  This function creates wifi configuration files.  The format
*  and content of these files are implementation dependent.  This function call is
*  used to trigger this task if necessary. Some implementations may not need this
*  function. If an implementation does not need to create config files the function call can
*  do nothing and return RETURN_OK.
*  Parameters : None
* 
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT wifi_createInitialConfigFiles()
{
    //TODO: creates initial implementation dependent configuration files that are later used for variable storage.  Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)

    return RETURN_OK;
}

// outputs the country code to a max 64 character string
INT wifi_getRadioCountryCode(INT radioIndex, CHAR *output_string)
{
    if (!output_string) {
        return RETURN_ERR;
    } else {
        snprintf(output_string, 64, "%d", countryCode);
        return RETURN_OK;
    }
}

INT wifi_setRadioCountryCode(INT radioIndex, CHAR *CountryCode)
{
    //Set wifi config. Wait for wifi reset to apply
    if (!CountryCode) {
        return RETURN_ERR;
    }
    countryCode=atoi(CountryCode);
    return RETURN_OK;
}


INT wifi_getRadioNumberOfEntries(ULONG *output)
{
    if (!output) {
        return RETURN_ERR;
    }
    *output=2;

    printf("wifi_getRadioNumberOfEntries");
}

//Get the total number of SSID entries in this wifi subsystem
INT wifi_getSSIDNumberOfEntries(ULONG *output) //Tr181
{
    if (!output) {
        return RETURN_ERR;
    }
    *output=3;
    return RETURN_OK;
}

UINT wifi_getScanResults(INT radioIndex)
{
    return(sizeof(dummy_neighbor_ap) / sizeof(dummy_neighbor_ap[0]));
}

INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string)
{
    if (!output_string) {
        return RETURN_ERR;
    }

    snprintf(output_string, 64, "2mbps");
    return RETURN_OK;
    printf("wifi_getRadioMaxBitRate \n");
}

//Get the Radio Interface name from platform, eg "wifi0"
INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string) //Tr181
{
    if (!output_string)
        return RETURN_ERR;
    snprintf(output_string, 64, "%s%d", RADIO_PREFIX, radioIndex);
    return RETURN_OK;
}
INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string)
{
    if (!output_string) {
        return RETURN_ERR;
    }
    snprintf(output_string, 64, "2.4GHz,5GHz");
    return RETURN_OK;
    printf("wifi_getRadioSupportedFrequencyBands \n");
}
INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string)
{
    if (!output_string) {
        return RETURN_ERR;
    }
    snprintf(output_string, 64, (radioIndex==0)?"2.4GHz":"5GHz");
    return RETURN_OK;
    printf("wifi_getRadioOperatingFrequencyBand \n");
}
INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string)
{
    if (!output_string) {
        return RETURN_ERR;
    }
    snprintf(output_string, 64, (radioIndex==0)?"b,g,n":"n,ac");
    return RETURN_OK;
    printf("wifi_getRadioSupportedStandards \n");
}
INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string)
{
    if (!output_string) {
        return RETURN_ERR;
    }
    snprintf(output_string, 64, (radioIndex==0)?"1-11":"36,40");
    return RETURN_OK;
    printf("wifi_getRadioPossibleChannels \n");
}

//Get the list for used channel. eg: "1,6,9,11"
//The output_string is a max length 256 octet string that is allocated by the   code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioChannelsInUse(INT radioIndex, CHAR *output_string)	//
{
    if (!output_string)
        return RETURN_ERR;
    snprintf(output_string, 256, (radioIndex==0)?"1,6,11":"36,40");
    return RETURN_OK;
}
INT wifi_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string)
{
    if (!output_string) {
        return RETURN_ERR;
    }

    snprintf(output_string, 64,"%s",dummy_radioValues[radioIndex].OperatingChannelBandwidth);
    return RETURN_OK;
    printf("wifi_getRadioOperatingChannelBandwidth \n");
}
//Set the Operating Channel Bandwidth.
INT wifi_setRadioOperatingChannelBandwidth(INT radioIndex, CHAR *bandwidth) //Tr181	//
{
    if (!bandwidth) {
        return RETURN_ERR;
    }

    snprintf(dummy_radioValues[radioIndex].OperatingChannelBandwidth,64,"%s",bandwidth);
    return RETURN_OK;
}

//Get the secondary extension channel position, "AboveControlChannel" or "BelowControlChannel". (this is for 40MHz and 80MHz bandwith only)
INT wifi_getRadioExtChannel(INT radioIndex, CHAR *output_string)
{
    if (!output_string) {
        return RETURN_ERR;
    }
    snprintf(output_string, 64,"%s",dummy_radioValues[radioIndex].ExtChannel);
    return RETURN_OK;
    printf("wifi_getRadioExtChannel \n");
}

//Set the extension channel.
INT wifi_setRadioExtChannel(INT radioIndex, CHAR *string) //Tr181	//
{
    if (!string) {
        return RETURN_ERR;
    }
    snprintf(dummy_radioValues[radioIndex].ExtChannel,64,"%s",string);

    return RETURN_OK;
}

INT wifi_getRadioGuardInterval(INT radioIndex, CHAR *output_string)
{
    if (!output_string) {
        return RETURN_ERR;
    }
    snprintf(output_string, 64,"%s",dummy_radioValues[radioIndex].GuardInterval);
    return RETURN_OK;
    printf("wifi_getRadioGuardInterval \n");
}

//Set the guard interval value.
INT wifi_setRadioGuardInterval(INT radioIndex, CHAR *string)	//Tr181
{
    //Apply setting instantly
    if (!string) {
        return RETURN_ERR;
    }
    snprintf(dummy_radioValues[radioIndex].GuardInterval,64,"%s",string);

    return RETURN_OK;
}

INT wifi_getRadioTransmitPowerSupported(INT radioIndex, CHAR *output_list) //Tr181
{
    CHAR transmitPwrSupp[]="100,200,300 mW";
    if (!output_list) {
        return RETURN_ERR;
    }
    strcpy(output_list,transmitPwrSupp);
    return RETURN_OK;
    printf("wifi_getRadioTransmitPowerSupported \n");
}
int wifi_getRadioIEEE80211hSupported(INT radioIndex, BOOL *Supported)  //Tr181
{
    if (!Supported) {
        return RETURN_ERR;
    }
    strcpy(Supported,"TRUE");
    return RETURN_OK;
    printf("wifi_getRadioIEEE80211hSupported \n");
}
int wifi_getRadioIEEE80211hEnabled(INT radioIndex, BOOL *enable)  //Tr181
{
    if (!enable) {
        return RETURN_ERR;
    }
    *enable=bIEEE80211hEnabled;
    return RETURN_OK;
    printf("wifi_getRadioIEEE80211hEnabled \n");
}
//Set 80211h feature enable
INT wifi_setRadioIEEE80211hEnabled(INT radioIndex, BOOL enable)  //Tr181
{
    bIEEE80211hEnabled=enable;
    return RETURN_OK;
}
INT wifi_getRadioAutoChannelSupported(INT radioIndex, BOOL *output_bool) //Tr181
{
    if (!output_bool) {
        return RETURN_ERR;
    }
    strcpy(output_bool,"TRUE");
    printf("wifi_getRadioAutoChannelSupported \n");
}
INT wifi_getRadioAutoChannelEnable(INT radioIndex, BOOL *output_bool)	//
{
    if (!output_bool) {
        return RETURN_ERR;
    }
    *output_bool=bAutoChannelEnable;
    return RETURN_OK;
    printf("wifi_getRadioAutoChannelEnable \n");
}
INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool)	//
{
    if (!output_bool) {
        return RETURN_ERR;
    }
    if(bRadioEnable)
        strcpy(output_bool,"TRUE");
    else
        strcpy(output_bool,"FALSE");
    return RETURN_OK;
    printf("wifi_getRadioEnable \n");
}

//Set the Radio enable config parameter
INT wifi_setRadioEnable(INT radioIndex, BOOL enable)		//
{
    //Set wifi config. Wait for wifi reset to apply
    bRadioEnable=enable;
    return RETURN_OK;
}

INT wifi_getRadioStatus(INT radioIndex, CHAR *output_string)
{
    if (!output_string) {
        return RETURN_ERR;
    }
    strcpy(output_string,"UP");
    return RETURN_OK;
    printf("wifi_getRadioStatus \n");
}
//Get the radio operating mode, and pure mode flag. eg: "ac"
//The output_string is a max length 64 octet string that is allocated by the   code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioStandard(INT radioIndex, CHAR *output_string, BOOL *gOnly, BOOL *nOnly, BOOL *acOnly)	//
{
    if (!output_string)
        return RETURN_ERR;
    if(radioIndex==0) {
        snprintf(output_string, 64, "n");		//"ht" needs to be translated to "n" or others
        *gOnly=FALSE;
        *nOnly=TRUE;
        *acOnly=FALSE;
    } else {
        snprintf(output_string, 64, "ac");		//"vht" needs to be translated to "ac"
        *gOnly=FALSE;
        *nOnly=FALSE;
        *acOnly=FALSE;
    }
    return RETURN_OK;

}
//Get the running channel number
INT wifi_getRadioChannel(INT radioIndex,ULONG *output_ulong)	//
{
    if (!output_ulong)
        return RETURN_ERR;
    *output_ulong=runChannelNumber;
    return RETURN_OK;
}

//Set the running channel number
INT wifi_setRadioChannel(INT radioIndex, ULONG channel)	// 	//
{
    //Set to wifi config only. Wait for wifi reset or wifi_pushRadioChannel to apply.
    runChannelNumber=channel;
    return RETURN_ERR;
}

//Enables or disables a driver level variable to indicate if auto channel selection is enabled on this radio
//This "auto channel" means the auto channel selection when radio is up. (which is different from the dynamic channel/frequency selection (DFC/DCS))
INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable) //
{
    //Set to wifi config only. Wait for wifi reset to apply.
    bAutoChannelEnable=enable;
    return RETURN_ERR;
}

INT wifi_getRadioDCSSupported(INT radioIndex, BOOL *output_bool) 	//
{
    if (!output_bool)
        return RETURN_ERR;
    *output_bool=FALSE;
    return RETURN_OK;
}

INT wifi_getRadioDCSEnable(INT radioIndex, BOOL *output_bool)		//
{
    if (!output_bool)
        return RETURN_ERR;
    *output_bool=bDCSEnable;
    return RETURN_OK;
}

INT wifi_setRadioDCSEnable(INT radioIndex, BOOL enable)			//
{
    //Set to wifi config only. Wait for wifi reset to apply.
    bDCSEnable=enable;
    return RETURN_ERR;
}

//The output_string is a max length 256 octet string that is allocated by the   code.  Implementations must ensure that strings are not longer than this.
//The value of this parameter is a comma seperated list of channel number
INT wifi_getRadioDCSChannelPool(INT radioIndex, CHAR *output_pool)			//
{
    if (!output_pool)
        return RETURN_ERR;
    snprintf(output_pool, 256,"%s",DCSChannelPool);
    return RETURN_OK;
}

INT wifi_setRadioDCSChannelPool(INT radioIndex, CHAR *pool)			//
{
    //Set to wifi config. And apply instantly.
    if (!pool)
        return RETURN_ERR;
    snprintf(DCSChannelPool, 256,"%s",pool);
    return RETURN_OK;
}

INT wifi_getRadioDCSScanTime(INT radioIndex, INT *output_interval_seconds, INT *output_dwell_milliseconds)
{
    if (!output_interval_seconds || !output_dwell_milliseconds)
        return RETURN_ERR;
    *output_interval_seconds=intervalSeconds;
    *output_dwell_milliseconds=dwellMilliSeconds;
    return RETURN_OK;
}

INT wifi_setRadioDCSScanTime(INT radioIndex, INT interval_seconds, INT dwell_milliseconds)
{
    //Set to wifi config. And apply instantly.
    intervalSeconds=interval_seconds;
    dwellMilliSeconds=dwell_milliseconds;
    return RETURN_OK;
}

//Get the Dfs enable status
INT wifi_getRadioDfsEnable(INT radioIndex, BOOL *output_bool)	//Tr181
{
    if (!output_bool)
        return RETURN_ERR;
    *output_bool=bDfsEnable;
    return RETURN_OK;
}

//Set the Dfs enable status
INT wifi_setRadioDfsEnable(INT radioIndex, BOOL enable)	//Tr181
{
    bDfsEnable=enable;
    return RETURN_ERR;
}

//Check if the driver support the AutoChannelRefreshPeriod
INT wifi_getRadioAutoChannelRefreshPeriodSupported(INT radioIndex, BOOL *output_bool) //Tr181
{
    if (!output_bool)
        return RETURN_ERR;
    *output_bool=FALSE;		//not support
    return RETURN_OK;
}

//Get the ACS refresh period in seconds
INT wifi_getRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG *output_ulong) //Tr181
{
    if (!output_ulong)
        return RETURN_ERR;
    *output_ulong=300;
    return RETURN_OK;
}

//Set the ACS refresh period in seconds
INT wifi_setRadioDfsRefreshPeriod(INT radioIndex, ULONG seconds) //Tr181
{
    return RETURN_ERR;
}

//Get the Modulation Coding Scheme index, eg: "-1", "1", "15"
INT wifi_getRadioMCS(INT radioIndex, INT *output_int) //Tr181
{
    if (!output_int)
        return RETURN_ERR;
    *output_int=dummy_radioValues[radioIndex].RadioMCS;
    return RETURN_OK;
}

//Set the Modulation Coding Scheme index
INT wifi_setRadioMCS(INT radioIndex, INT MCS) //Tr181
{
    dummy_radioValues[radioIndex].RadioMCS=MCS;
    return RETURN_OK;
}
//Get current Transmit Power, eg "75", "100"
//The transmite power level is in units of full power for this radio.
INT wifi_getRadioTransmitPower(INT radioIndex, INT *output_INT)	//
{
    if (! output_INT)
        return RETURN_ERR;
    *output_INT=(INT)dummy_radioValues[radioIndex].TransmitPower;
    return RETURN_OK;
}

//Set Transmit Power
//The transmite power level is in units of full power for this radio.
INT wifi_setRadioTransmitPower(INT radioIndex, ULONG TransmitPower)	//
{
    dummy_radioValues[radioIndex].TransmitPower=TransmitPower;
    return RETURN_OK;
}

//Indicates the Carrier Sense ranges supported by the radio. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdRange(INT radioIndex, INT *output)  //P3
{
    if (!output)
        return RETURN_ERR;
    *output=100;
    return RETURN_OK;
}

//The RSSI signal level at which CS/CCA detects a busy condition. This attribute enables APs to increase minimum sensitivity to avoid detecting busy condition from multiple/weak Wi-Fi sources in dense Wi-Fi environments. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdInUse(INT radioIndex, INT *output)	//P3
{
    if (!output)
        return RETURN_ERR;
    *output=carrierSenseThresholdInUse;
    return RETURN_OK;
}

INT wifi_setRadioCarrierSenseThresholdInUse(INT radioIndex, INT threshold)	//P3
{
    carrierSenseThresholdInUse=threshold;
    return RETURN_OK;
}

//Time interval between transmitting beacons (expressed in milliseconds). This parameter is based ondot11BeaconPeriod from [802.11-2012].
INT wifi_getRadioBeaconPeriod(INT radioIndex, UINT *output)
{
    if (!output)
        return RETURN_ERR;
    *output=beaconPeriod;
    return RETURN_OK;
}

INT wifi_setRadioBeaconPeriod(INT radioIndex, UINT BeaconPeriod)
{
    beaconPeriod=BeaconPeriod;
    return RETURN_OK;
}

//Comma-separated list of strings. The set of data rates, in Mbps, that have to be supported by all stations that desire to join this BSS. The stations have to be able to receive and transmit at each of the data rates listed inBasicDataTransmitRates. For example, a value of "1,2", indicates that stations support 1 Mbps and 2 Mbps. Most control packets use a data rate in BasicDataTransmitRates.
INT wifi_getRadioBasicDataTransmitRates(INT radioIndex, CHAR *output)
{
    if (!output)
        return RETURN_ERR;
    snprintf(output, 64,"%s",dummy_radioValues[radioIndex].BasicDataTransmitRates);
    return RETURN_OK;
}

INT wifi_setRadioBasicDataTransmitRates(INT radioIndex, CHAR *TransmitRates)
{
    if (!TransmitRates)
        return RETURN_ERR;
    snprintf(dummy_radioValues[radioIndex].BasicDataTransmitRates,64,"%s",TransmitRates);
    return RETURN_OK;
}

//Clients associated with the AP over a specific interval.  The histogram MUST have a range from -110to 0 dBm and MUST be divided in bins of 3 dBM, with bins aligning on the -110 dBm end of the range.  Received signal levels equal to or greater than the smaller boundary of a bin and less than the larger boundary are included in the respective bin.  The bin associated with the client?s current received signal level MUST be incremented when a client associates with the AP.   Additionally, the respective bins associated with each connected client?s current received signal level MUST be incremented at the interval defined by "Radio Statistics Measuring Rate".  The histogram?s bins MUST NOT be incremented at any other time.  The histogram data collected during the interval MUST be published to the parameter only at the end of the interval defined by "Radio Statistics Measuring Interval".  The underlying histogram data MUST be cleared at the start of each interval defined by "Radio Statistics Measuring Interval?. If any of the parameter's representing this histogram is queried before the histogram has been updated with an initial set of data, it MUST return -1. Units dBm
INT wifi_getRadioStatsReceivedSignalLevel(INT radioIndex, INT signalIndex, INT *SignalLevel) //Tr181
{
    if (!SignalLevel)
        return RETURN_ERR;
    *SignalLevel=(radioIndex==0)?-19:-19;
    return RETURN_OK;
}

//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applyRadioSettings(INT radioIndex)
{
    return RETURN_OK;
}
