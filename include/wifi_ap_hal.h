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

    module: wifi_ap_hal.h

        For CCSP Component:  Wifi_Provisioning_and_management

    ---------------------------------------------------------------

    description:

        This header file gives the function call prototypes and
        structure definitions used for the RDK-Broadband
        Wifi AP hardware abstraction layer

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
        Charles Moreman, moremac@cisco.com


**********************************************************************/

#ifndef __WIFI_AP_HAL_H__
#define __WIFI_AP_HAL_H__

#include <wifi_common_hal.h>

/**
 * @defgroup WIFI_HAL  Wi-Fi HAL Public APIs and Data Types
 * @ingroup WIFI
 *
 * @defgroup WIFI_HAL_AP_API Wi-Fi Access Point HAL API List
 * Wi-Fi access Point HAL provides an interface (data structures and API) to create, secure and delete the access point
 * and also provides APIs to establish the client to connect to the access point.
 * @ingroup WIFI_HAL
 *
 */


//Please do not edit the elements for this data structure

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */

/**
 * @brief Client information
 *
 * Structure which holds the device information associated with the wifi access point.
 */
typedef struct _wifi_associated_dev
{
    //UCHAR cli_devMacAddress[6];
    //CHAR  cli_devIPAddress[64];
    //BOOL  cli_devAssociatedDeviceAuthentiationState;
    //INT   cli_devSignalStrength;
    //INT   cli_devTxRate;
    //INT   cli_devRxRate;

    UCHAR cli_MACAddress[6];		//<! The MAC address of an associated device.
    BOOL  cli_AuthenticationState; //<! Whether an associated device has authenticated (true) or not (false).
    UINT  cli_LastDataDownlinkRate; //<! The data transmit rate in kbps that was most recently used for transmission from the access point to the associated device.
    UINT  cli_LastDataUplinkRate; 	//<! The data transmit rate in kbps that was most recently used for transmission from the associated device to the access point.
    INT   cli_SignalStrength; 		//<! An indicator of radio signal strength of the uplink from the associated device to the access point, measured in dBm, as an average of the last 100 packets received from the device.
    UINT  cli_Retransmissions; 	//<! The number of packets that had to be re-transmitted, from the last 100 packets sent to the associated device. Multiple re-transmissions of the same packet count as one.
    BOOL  cli_Active; 				//<! boolean	-	Whether or not this node is currently present in the WiFi accessPoint network.

    CHAR  cli_OperatingStandard[64];	//<! Radio standard the associated Wi-Fi client device is operating under. Enumeration of:
    CHAR  cli_OperatingChannelBandwidth[64];	//<! The operating channel bandwidth of the associated device. The channel bandwidth (applicable to 802.11n and 802.11ac specifications only). Enumeration of:
    INT   cli_SNR;		//<! A signal-to-noise ratio (SNR) compares the level of the Wi-Fi signal to the level of background noise. Sources of noise can include microwave ovens, cordless phone, bluetooth devices, wireless video cameras, wireless game controllers, fluorescent lights and more. It is measured in decibels (dB).
    CHAR  cli_InterferenceSources[64]; //<! Wi-Fi operates in two frequency ranges (2.4 Ghz and 5 Ghz) which may become crowded other radio products which operate in the same ranges. This parameter reports the probable interference sources that this Wi-Fi access point may be observing. The value of this parameter is a comma seperated list of the following possible sources: eg: MicrowaveOven,CordlessPhone,BluetoothDevices,FluorescentLights,ContinuousWaves,Others
    ULONG cli_DataFramesSentAck;	//<! The DataFramesSentAck parameter indicates the total number of MSDU frames marked as duplicates and non duplicates acknowledged. The value of this counter may be reset to zero when the CPE is rebooted. Refer section A.2.3.14 of CableLabs Wi-Fi MGMT Specification.
    ULONG cli_DataFramesSentNoAck;	//<! The DataFramesSentNoAck parameter indicates the total number of MSDU frames retransmitted out of the interface (i.e., marked as duplicate and non-duplicate) and not acknowledged, but does not exclude those defined in the DataFramesLost parameter. The value of this counter may be reset to zero when the CPE is rebooted. Refer section A.2.3.14 of CableLabs Wi-Fi MGMT Specification.
    ULONG cli_BytesSent;	//<! The total number of bytes transmitted to the client device, including framing characters.
    ULONG cli_BytesReceived;	//<! The total number of bytes received from the client device, including framing characters.
    INT   cli_RSSI;	//<! The Received Signal Strength Indicator, RSSI, parameter is the energy observed at the antenna receiver for transmissions from the device averaged over past 100 packets recevied from the device.
    INT   cli_MinRSSI;	//<! The Minimum Received Signal Strength Indicator, RSSI, parameter is the minimum energy observed at the antenna receiver for past transmissions (100 packets).
    INT   cli_MaxRSSI;	//<! The Maximum Received Signal Strength Indicator, RSSI, parameter is the energy observed at the antenna receiver for past transmissions (100 packets).
    UINT  cli_Disassociations;	//<! This parameter  represents the total number of client disassociations. Reset the parameter evey 24hrs or reboot
    UINT  cli_AuthenticationFailures;	//<! This parameter indicates the total number of authentication failures.  Reset the parameter evey 24hrs or reboot

} wifi_associated_dev_t;	//COSA_DML_WIFI_AP_ASSOC_DEVICE

/**
 * @brief RADIUS Server information.
 *
 * Structure which holds the the RADIUS server settings.
 */
typedef struct _wifi_radius_setting_t
{
    INT  RadiusServerRetries; 			//<! Number of retries for Radius requests.
    INT  RadiusServerRequestTimeout; 	//<! Radius request timeout in seconds after which the request must be retransmitted for the # of retries available.
    INT  PMKLifetime; 					//<! Default time in seconds after which a Wi-Fi client is forced to ReAuthenticate (def 8 hrs).
    BOOL PMKCaching; 					//<! Enable or disable caching of PMK.
    INT  PMKCacheInterval; 			//<! Time interval in seconds after which the PMKSA (Pairwise Master Key Security Association) cache is purged (def 5 minutes).
    INT  MaxAuthenticationAttempts; 	//<! Indicates the # of time, a client can attempt to login with incorrect credentials. When this limit is reached, the client is blacklisted and not allowed to attempt loging into the network. Settings this parameter to 0 (zero) disables the blacklisting feature.
    INT  BlacklistTableTimeout; 		//<! Time interval in seconds for which a client will continue to be blacklisted once it is marked so.
    INT  IdentityRequestRetryInterval; //<! Time Interval in seconds between identity requests retries. A value of 0 (zero) disables it.
    INT  QuietPeriodAfterFailedAuthentication;  //<! The enforced quiet period (time interval) in seconds following failed authentication. A value of 0 (zero) disables it.
    UCHAR RadiusSecret[64];			//<! The secret used for handshaking with the RADIUS server [RFC2865]. When read, this parameter returns an empty string, regardless of the actual value.

} wifi_radius_setting_t;

//typedef struct wifi_AC_parameters_record  // Access Catagoriy parameters.  see 802.11-2012 spec for descriptions
//{
//     INT CWmin;       // CWmin variable
//     INT CWmax;       // CWmax vairable
//     INT AIFS;        // AIFS
//     ULONG TxOpLimit;  // TXOP Limit
//} wifi_AC_parameters_record_t;


//typedef struct _wifi_qos
//{
//     wifi_AC_parameters_record_t BE_AcParametersRecord;      // Best Effort QOS parameters, ACI == 0
//     wifi_AC_parameters_record_t BK_AcParametersRecord;      // Background QOS parameters, ACI == 1
//     wifi_AC_parameters_record_t VI_AcParametersRecord;      // Video QOS parameters, ACI == 2
//     wifi_AC_parameters_record_t VO_AcParametersRecord;      // Voice QOS parameters, ACI == 3
//}  wifi_qos_t;

/** @} */

//---------------------------------------------------------------------------------------------------
//
// Additional Wifi radio level APIs used for RDKB Access Point devices
//
//---------------------------------------------------------------------------------------------------

/**
 * @addtogroup WIFI_HAL_AP_API
 * @{
 */

/**
 * @brief Enables/Disables CTS protection for the radio used by this access point.
 *
 * The CTS (Clear To Send) protection mode determines which device on a wireless network can
 * transmit data at a given time.
 *
 * Following are the CTS Protection modes
 * - Auto : The Router will automatically use CTS Protection Mode when it experiences problems,
     when not able to transmit data in an environment with heavy traffic. This increases the
     ability of the router to catch wireless transmissions but the performance of the router
     will decrease.
 * - Enabled : If the CTS protection mode is enabled, it helps data to be tranmitted to the
     router in a network with heavy traffic more efficiently. This decreases throughput.
 * - Disabled : If the CTS protection mode is disabled, it significantly increases Wifi
     throughput in a network that has low transmission error.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  enable   Boolean value indicates the CTS protection.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setRadioCtsProtectionEnable(INT apIndex, BOOL enable);

/**
 * @brief Enables/Disables OBSS Coexistence for the radio used by this access point.
 *
 * OBSS(Overlapping BSS) enables the router to automatically change the channel width from
 * 40Mhz to 20Mhz to avoid interference with other access point.
 *
 * @param[in]  apIndex    The index of the access point array.
 * @param[in]  enable     Enables or Disables overlapping BSS coexistence..
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setRadioObssCoexistenceEnable(INT apIndex, BOOL enable);

/**
 * @brief Sets the fragmentation threshold in bytes for the radio used by this access point.
 *
 * @param[in]  apIndex    The index of the access point array.
 * @param[in]  threshold  The threshold value to limit the maximum frame size.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setRadioFragmentationThreshold(INT apIndex, UINT threshold);    //P3

/**
 * @brief Enable STBC mode in the hardware.
 *
 * STBC(Space Time Block Coding) transmits multiple copies of data stream across multiple
 * antennas. In the receiving side, there are multiple copies of same signal STBC combines
 * all these  signals results in higher probability of one or more received copies to be
 * correctly decoded.
 *
 * @param[in]  radioIndex   The index of the Wi-Fi radio.
 * @param[in]  STBC_Enable  Boolean value to enable/disable STBC.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setRadioSTBCEnable(INT radioIndex, BOOL STBC_Enable);

/**
 * @brief  This function outputs the  A-MSDU enable status.
 *
 * Aggregate MAC Service Data Unit(A-MSDU) is a frame aggregation method of combining multiple
 * frames into a single transmission with the purpose of improving power management to
 * increase throughput.
 *
 * @param[in]  radioIndex   The index of the Wi-Fi radio.
 * @param[out] output_bool  Boolean value which indicates the A-MSDU enable status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getRadioAMSDUEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief This function enables A-MSDU in the hardware.
 *
 * @param[in]  radioIndex   The index of the Wi-Fi radio.
 * @param[in]  amsduEnable  Boolean value to enable/disable A-MSDU.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setRadioAMSDUEnable(INT radioIndex, BOOL amsduEnable);

/**
 * @brief This function outputs the number of transmit streams.
 *
 * @param[in]  radioIndex  The index of the Wi-Fi radio.
 * @param[out] output_int  The number of transmit streams.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getRadioTxChainMask(INT radioIndex, INT *output_int);           //P2

/**
 * @brief Sets the number of transmit streams to an environment variable.
 *
 * @param[in]  radioIndex  The index of the Wi-Fi radio.
 * @param[in]  numStreams  The number of transmit  streams.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setRadioTxChainMask(INT radioIndex, INT numStreams);            //P2

/**
 * @brief This function outputs the number of receive streams.
 *
 * @param[in]  radioIndex  The index of the Wi-Fi radio.
 * @param[out] output_int  Outputs the number of receive streams.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getRadioRxChainMask(INT radioIndex, INT *output_int);           //P2

/**
 * @brief Sets the number of receive streams to an environment variable.
 *
 * @param[in]  radioIndex  The index of the Wi-Fi radio.
 * @param[in]  numStreams  The number of receive streams.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setRadioRxChainMask(INT radioIndex, INT numStreams);            //P2
//INT wifi_pushRadioChannel(INT radioIndex, UINT channel);                 //P2  // push the channel number setting to the hardware  //Applying changes with wifi_applyRadioSettings().
//INT wifi_pushRadioChannelMode(INT radioIndex);                           //P2  // push the channel mode environment variable that is set by "wifi_setChannelMode()" to the hardware  //Applying changes with wifi_applyRadioSettings().
//INT wifi_pushRadioTxChainMask(INT radioIndex);                           //P2  // push the environment varible that is set by "wifi_setTxChainMask()" to the hardware //Applying changes with wifi_applyRadioSettings().
//INT wifi_pushRadioRxChainMask(INT radioIndex);                           //P2  // push the environment varible that is set by "wifi_setRxChainMask()" to the hardware //Applying changes with wifi_applyRadioSettings().

/**
 * @brief Get radio RDG enable setting.
 *
 * RDG(Reverse Direction Grant) bit is used to eliminate the need for either devices to
 * initiate a new data transfer during its transmission opportunity granted by the access Point
 * to the Station.
 *
 * @param[in]  radioIndex   The index of the Wi-Fi radio.
 * @param[out] output_bool  Boolean value which indicates the RDG enabled status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getRadioReverseDirectionGrantEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Set radio RDG enable setting.
 *
 * @param[in]  radioIndex  The index of the Wi-Fi radio.
 * @param[in]  enable      Boolean value to enable/disable RDG.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setRadioReverseDirectionGrantEnable(INT radioIndex, BOOL enable);

/**
 * @brief Get radio ADDBA enable setting.
 *
 * @param[in]  radioIndex   The index of the Wi-Fi radio.
 * @param[out] output_bool  Boolean value which indicates the ADDBA enabled status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getRadioDeclineBARequestEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Set radio ADDBA enable setting.
 *
 * ADDBA(Add Block Acknowledgment) is a management action frame to set up and initialize
 * Block Acknowledgement between sender and receiver stations.
 *
 * @param[in]  radioIndex   The index of the Wi-Fi radio.
 * @param[in]  enable       Boolean value to enable/disable ADDBA.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setRadioDeclineBARequestEnable(INT radioIndex, BOOL enable);

/**
 * @brief Get radio auto block ack enable setting.
 *
 * @param[in]  radioIndex   The index of the Wi-Fi radio.
 * @param[out] output_bool  Boolean value which indicates the auto block acknowlegement enabled
 * status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getRadioAutoBlockAckEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Set radio auto block ack enable setting.
 *
 * @param[in]  radioIndex   The index of the Wi-Fi radio.
 * @param[in]  enable       Boolean value to enable/disable AutoBlock Acknowlegement.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setRadioAutoBlockAckEnable(INT radioIndex, BOOL enable);

/**
 * @brief Get radio 11n pure mode enable setting.
 *
 * @param[in]  radioIndex   The index of the Wi-Fi radio.
 * @param[out] output_bool  Boolean value which indicates the Greenfield enabled status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getRadio11nGreenfieldEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Set radio 11n pure mode enable setting.
 *
 * @param[in]  radioIndex   The index of the Wi-Fi radio.
 * @param[in]  enable       Boolean value to enable/disable Greenfield mode.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setRadio11nGreenfieldEnable(INT radioIndex, BOOL enable);

/**
 * @brief Get radio IGMP snooping enabled status
 *
 * IGMP Snooping allows the routers to send the  multicast traffic to only those interfaces
 * that are connected to devices that want to receive instead of flooding the traffic to all
 * VLAN interfaces.
 *
 * @param[in]  radioIndex   The index of the Wi-Fi radio.
 * @param[out] output_bool  Boolean value which indicates the IGMP enabled status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getRadioIGMPSnoopingEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Set radio IGMP snooping enable setting.
 *
 * @param[in]  radioIndex  The index of the Wi-Fi radio.
 * @param[in]  enable      Boolean value to enable/disable IGMP mode.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setRadioIGMPSnoopingEnable(INT radioIndex, BOOL enable);

/**
 * @brief  This function checks the Wi-Fi HAL driver supports the DFS.
 *
 * Dynamic Frequency Selection (DFS) detects radar interference in the channel devices are
 * operating  and switches the wireless network to another frequency  with no interference.
 *
 * @param[in]  radioIndex   The index of the Wi-Fi radio.
 * @param[out] output_uint  Output paramter which holds the radio DFS value.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getRadioDfsSupport(INT radioIndex, UINT *output_uint);						//Get radio DFS support

/**
 * @brief Get radio DFS enable setting.
 *
 * @param[in]  radioIndex   The index of the Wi-Fi radio.
 * @param[out] output_bool  Boolean value which indicates the DFS enabled status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getRadioDfsEnable(INT radioIndex, BOOL *output_bool);						//Get radio DFS enable setting

/**
 * @brief Set radio DFS enable setting.
 *
 * @param[in]  radioIndex  The index of the Wi-Fi radio.
 * @param[in]  enabled     Boolean value to enable/disable DFS.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setRadioDfsEnable(INT radioIndex, BOOL enabled);							//Set radio DFS enable setting
//---------------------------------------------------------------------------------------------------
//
// Additional Wifi AP level APIs used for Access Point devices
//
//---------------------------------------------------------------------------------------------------


//AP HAL
/**
 * @brief Creates a new access point and pushes these parameters to the hardware.
 *
 * @param[in]  apIndex     The index of the access point array.
 * @param[in]  radioIndex  The index of the Wi-Fi radio.
 * @param[in]  essid       Extended basic service set (ESS) consists of all of the
 *                         BSSs in the network.
 * @param[in]  hideSsid    Boolean value to hide/show the ssid.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 */
INT wifi_createAp(INT apIndex, INT radioIndex, CHAR *essid, BOOL hideSsid);

/**
 * @brief Deletes this access point entry on the hardware.
 *
 * This function clears all internal variables associated with this access point.
 *
 * @param[in]  apIndex  The index of the access point array.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_deleteAp(INT apIndex);

/**
 * @brief This API returns the name associated with the access point.
 *
 * @param[in]  apIndex        The index of the access point array.
 * @param[out] output_string  The name of the access point.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note Outputs a 16 byte or less name. String buffer must be pre-allocated by the caller.
 */
INT wifi_getApName(INT apIndex, CHAR *output_string);

/**
 * @brief This API returns the beacon type used by this access point.
 *
 * @param[in]  apIndex        The index of the access point array.
 * @param[out] output_string  Outputs the beacon type.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note Outputs a 32 byte or less string indicating the beacon type.
 */
INT wifi_getApBeaconType(INT apIndex, CHAR *output_string);

/**
 * @brief Sets the beacon type environment variable.
 *
 * Allowed input strings are "None", "Basic", "WPA, "11i", "WPAand11i".
 *
 * @param[in]  apIndex           The index of the access point array.
 * @param[in]  beaconTypeString  String to set the beacon type.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApBeaconType(INT apIndex, CHAR *beaconTypeString);

/**
 * @brief Sets the beacon interval on the hardware for this access Point.
 *
 * This is the time interval between beacon transmissions. Expressed in Time Unit (TU).
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  beaconInterval  The beaconInterval to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApBeaconInterval(INT apIndex, INT beaconInterval);

 /**
 * @brief Sets the packet size threshold in bytes to apply RTS/CTS backoff rules.
 *
 * @param[in]  apIndex    The index of the access point array.
 * @param[in]  threshold  The threshold value to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApRtsThreshold(INT apIndex, UINT threshold);

/**
 * @brief This API returns the WPA encryption modes.
 *
 * @param[in]  apIndex        The index of the access point array.
 * @param[out] output_string  Outputs the WPA encryption mode.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApWpaEncryptoinMode(INT apIndex, CHAR *output_string);

/**
 * @brief Sets the encyption mode environment variable.
 *
 * Allowed input strings are "TKIPEncryption", "AESEncryption", or "TKIP and AESEncryption".
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  encMode  The encryption mode to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApWpaEncryptionMode(INT apIndex, CHAR *encMode);

/**
 * @brief Deletes internal security variable settings for this access point.
 *
 * @param[in]  apIndex  The index of the access point array.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_removeApSecVaribles(INT apIndex);

/**
 * @brief Changes the hardware settings to disable encryption on this access point.
 *
 * @param[in]  apIndex  The index of the access point array.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_disableApEncryption(INT apIndex);

/**
 * @brief Set the authorization mode on this access point.
 *
 * Mode mapping can be:
 * - 1 : open
 * - 2 : shared
 * - 4 : auto
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  mode     The authorization mode to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApAuthMode(INT apIndex, INT mode);

/**
 * @brief Sets an environment variable for the authentication mode.
 *
 * Valid strings are "None", "EAPAuthentication" or "SharedAuthentication"
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  authMode The authentication  mode to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApBasicAuthenticationMode(INT apIndex, CHAR *authMode);

/**
 * @brief Manually removes any active wi-fi association with the device specified on this
 * access point.
 *
 * @param[in]  apIndex     The index of the access point array.
 * @param[in]  client_mac  Mac address of the device to be removed from this access point.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_kickApAssociatedDevice(INT apIndex, CHAR *client_mac);

/**
 * @brief Outputs the radio index for the specified access point.
 *
 * @param[in]  apIndex     The index of the access point array.
 * @param[out] output_int  The radio index of the access point.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApRadioIndex(INT apIndex, INT *output_int);

/**
 * @brief Sets the radio index for the specified  access point.
 *
 * @param[in]  apIndex      The index of the access point array.
 * @param[out] radioIndex   The index of the radio array.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApRadioIndex(INT apIndex, INT radioIndex);

/**
 * @brief This API adds the client mac address to the access control list.
 *
 * @param[in]  apIndex           The index of the access point array.
 * @param[in]  DeviceMacAddress  MAC address to be added.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
 */
INT wifi_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress);         // adds the mac address to the filter list

/**
 * @brief This API removes the client  mac address from the filter list.
 *
 * @param[in]  apIndex           The index of the access point array.
 * @param[in]  DeviceMacAddress  MAC address to be removed.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
 */
INT wifi_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress);

/**
 * @brief  This API lists the number of devices in the filter list.
 *
 * @param[in]  apIndex     The index of the access point array.
 * @param[out] output_uint The number of devices in the filter list.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApAclDeviceNum(INT apIndex, UINT *output_uint);

/**
 * @brief  Enable kick for devices on acl black list.
 *
 * @param[in] apIndex  The index of the access point array.
 * @param[in] enable   Boolean value to enable or disable the kick for the devices.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_kickApAclAssociatedDevices(INT apIndex,BOOL enable);

/**
 * @brief This API sets the mac address filter control mode.
 *
 * Following are the filter control modes
 * - 0 - filter disabled     - Disables the mac address filtering
 * - 1 - filter as whitelist - Permits access for the specified mac address, rest of them
                               will be blocked.
 * - 2 - filter as blacklist - Rejects access for the specified mac address, rest of them
                               will be permitted.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  filterMode The filter mode to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode);

/**
 * @brief  Enables internal gateway VLAN mode.
 *
 * In this mode a Vlan tag is added to upstream (received) data packets before exiting the
 * Wifi driver. VLAN tags in downstream data are stripped from data packets before
 * transmission.
 * Default is FALSE.
 *
 * @param[in]  apIndex      The index of the access point array.
 * @param[in]  VlanEnabled  Boolean value to enable/disable VLAN mode.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApVlanEnable(INT apIndex, BOOL VlanEnabled);

/**
 * @brief  Sets the vlan ID for this access point to an internal environment variable.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  vlanId   The VLAN id to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApVlanID(INT apIndex, INT vlanId);

/**
 * @brief  Gets bridgeName, IP address and Subnet.
 *
 * @param[in]  index       The index of the access point array.
 * @param[out] bridgeName  The access point bridge name.
 * @param[out] IP          The IP address of the bridge.
 * @param[out] subnet      The subnet mask of the bridge
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApBridgeInfo(INT index, CHAR *bridgeName, CHAR *IP, CHAR *subnet);

/**
 * @brief  Sets bridgeName, IP address and Subnet to internal environment variables.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  bridgeName The access point bridge name.
 * @param[in]  IP  The IP address of the bridge.
 * @param[in]  subnet The subnet mask of the bridge
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note  BridgeName is a maximum of 32 characters.
 */
INT wifi_setApBridgeInfo(INT apIndex, CHAR *bridgeName, CHAR *IP, CHAR *subnet);
//INT wifi_pushApBridgeInfo(INT apIndex);                               // push the BridgeInfo environment variables to the hardware //Applying changes with wifi_applyRadioSettings()

/**
 * @brief  Resets the vlan configuration for this access point.
 *
 * @param[in]  apIndex  The index of the access point array.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_resetApVlanCfg(INT apIndex);

/**
 * @brief  Set the environment variables to control bridging.
 *
 * @param[in]  apIndex       The index of the access point array.
 * @param[in]  bridgeEnable  Flag to enable bridging.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note If isolation is required then disable bridging.
 */
INT wifi_setApBridging(INT apIndex, BOOL bridgeEnable);
//INT wifi_getApRouterEnable(INT apIndex, BOOL *output_bool);           //P4 // Outputs a bool that indicates if router is enabled for this ap
//INT wifi_setApRouterEnable(INT apIndex, BOOL routerEnabled);          //P4 // sets the routerEnabled variable for this ap

/**
 * @brief Creates configuration variables needed for WPA/WPS.
 *
 * @param[in]  apIndex       The index of the access point array.
 * @param[in]  createWpsCfg  Boolean value which indicates the wps enabled status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note  These variables are implementation dependent and in some implementations these variables are used by hostapd
 * when it is started. Specific variables that are needed are dependent on the hostapd implementation.These variables are
 * set by WPA/WPS security functions in this wifi HAL. If not needed for a particular implementation this function may
 * simply return no error.
 */
INT wifi_createHostApdConfig(INT apIndex, BOOL createWpsCfg);

/**
 * @brief This API starts the hostapd.
 *
 * Uses the variables in the hostapd config with format compatible with the specific hostapd
 * implementation.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_startHostApd();

/**
 * @brief Stops the  hostapd.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_stopHostApd();

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.
//Device.WiFi.AccessPoint.{i}.Enable

/**
 * @brief Sets the access Point enable status variable for the specified access point.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  enable   Boolean value to enable/disable the specified access point.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApEnable(INT apIndex, BOOL enable);

/**
 * @brief This API outputs the setting of the internal variable that is set by wifi_setEnable().
 *
 * @param[in]  apIndex      The index of the access point array.
 * @param[out] output_bool  The access Point enable status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApEnable(INT apIndex, BOOL *output_bool);

//Device.WiFi.AccessPoint.{i}.Status

/**
 * @brief Outputs the access Point "Enabled" "Disabled" status from driver.
 *
 * @param[in]  apIndex        The index of the access point array.
 * @param[out] output_string  The Enabled/Disabled status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApStatus(INT apIndex, CHAR *output_string);

//Device.WiFi.AccessPoint.{i}.SSIDAdvertisementEnabled

/**
 * @brief Indicates whether  beacons include the SSID name or not.
 *
 * Outputs a 1 if SSID on the access Point is enabled, else ouputs 0.
 *
 * @param[in]  apIndex      The index of the access point array.
 * @param[out] output_bool  Indicates SSID on the access point is enabled or not.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApSsidAdvertisementEnable(INT apIndex, BOOL *output_bool);

/**
 * @brief Sets an internal variable for ssid advertisement.
 *
 * Possible values:
 * -  1 - enable
 * -  0 - disable
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  enable   Boolean value to enable/disable the SSID advertisement.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApSsidAdvertisementEnable(INT apIndex, BOOL enable);
//INT wifi_pushApSsidAdvertisementEnable(INT apIndex, BOOL enable);     // push the ssid advertisement enable variable to the hardware //Applying changs with wifi_applyRadioSettings()

//Device.WiFi.AccessPoint.{i}.RetryLimit
/**
 * @brief The maximum number of retransmission for a packet.
 *
 * This corresponds to IEEE 802.11 parameter dot11ShortRetryLimit.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   The maximum number of transmission attempts.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApRetryLimit(INT apIndex, UINT *output);

/**
 * @brief This API sets the maximum number of transmission attempts of a frame.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  number   The number of transmission attempts to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApRetryLimit(INT apIndex, UINT number);

//Device.WiFi.AccessPoint.{i}.WMMCapability

/**
 * @brief Indicates whether this access point supports WiFi Multimedia (WMM)
 * access Categories (AC).
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   The value indicates the WMM support of this access Point.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApWMMCapability(INT apIndex, UINT *output);

//Device.WiFi.AccessPoint.{i}.UAPSDCapability
/**
 * @brief Indicates whether this access point supports WMM Unscheduled Automatic Power Save
 * Delivery (U-APSD).
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   The value indicates the UAPSD support of this access Point.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note U-APSD support implies WMM support.
 */
INT wifi_getApUAPSDCapability(INT apIndex, UINT *output);

//Device.WiFi.AccessPoint.{i}.WMMEnable

/**
 * @brief Indicates whether WMM support is currently enabled.
 *
 * When enabled, this is indicated in beacon frames.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   Boolean value which indicates the WMM enabled status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApWmmEnable(INT apIndex, BOOL *output);

/**
 * @brief Enables/disables WMM on the hardwawre for this AP.
 *
 * Wireless Multimedia Extensions(WME) or Wi-Fi Multimedia (WMM), is a Wi-Fi Alliance
 * interoperability certification provides basic Quality of service (QoS) features to
 * IEEE 802.11 networks.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  enable   Boolean value to enable/disable WMM.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note Enable value for the WMM is 1 and the disable value is 0.
 */
INT wifi_setApWmmEnable(INT apIndex, BOOL enable);

//Device.WiFi.AccessPoint.{i}.UAPSDEnable

/**
 * @brief Indicates whether U-APSD support is currently enabled.
 * When enabled, this is indicated in beacon frames.
 *
 * U-APSD(Unscheduled Automatic Power Save Delivery) is a feature of Wi-Fi devices that allows
 * them to save power.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output  Boolean value which indicates the U-APSD is supported or not.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note U-APSD can only be enabled if WMM is also enabled.
 */
INT wifi_getApWmmUapsdEnable(INT apIndex, BOOL *output);

/**
 * @brief Enables/Disables Automatic Power Save Delivery on the hardware for this access Point.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  enable   Boolean value to enable/disable  U-APSD support.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApWmmUapsdEnable(INT apIndex, BOOL enable);

//Device.WiFi.AccessPoint.{i}.IsolationEnable

/**
 * @brief This API is used to check the device isolation is enabled for this access Point.
 *
 * A value of true means that the devices connected to the access Point are isolated from all
 * other devices within the home network (as is typically the case for a Wireless Hotspot).
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   The device isolation status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApIsolationEnable(INT apIndex, BOOL *output); //Tr181

/**
 * @brief Enables or disables device isolation.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  enable   Boolean value to enable/disable device isolation.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApIsolationEnable(INT apIndex, BOOL enable); //Tr181

//Device.WiFi.AccessPoint.{i}.MaxAssociatedDevices

/**
 * @brief The maximum number of devices that can simultaneously be connected to the
 * access point.
 *
 * A value of 0 means that there is no specific limit.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   The maximum number of devices associated with this access Point.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApMaxAssociatedDevices(INT apIndex, UINT *output); //Tr181

/**
 * @brief This API sets the maximum number of devices that can  be connected to this
 * access point.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  number   The maximum number of devices that can be connected.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApMaxAssociatedDevices(INT apIndex, UINT number); //Tr181

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_AssociatedDevicesHighWatermarkThreshold

/**
 * @brief This API returns the maximum number of devices that can be associated to this
 * access Point.
 *
 * The HighWatermarkThreshold value that is lesser than or equal to MaxAssociatedDevices.
 * Setting this parameter does not actually limit the number of clients that can associate with
 * this access point as that is controlled by MaxAssociatedDevices.
 * MaxAssociatedDevices or 50.
 * The default value of this parameter should be equal to MaxAssociatedDevices.
 * In case MaxAssociatedDevices is 0 (zero), the default value of this parameter should be 50.
 * A value of 0 means that there is no specific limit and Watermark calculation algorithm
 * should be turned off.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   Maximum associated devices.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT *output); //Tr181	//P3

/**
 * @brief This API sets the maximum number of devices connected to this access Point.
 *
 * @param[in]  apIndex    The index of the access point array.
 * @param[in]  Threshold  The threshold value to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT Threshold); //Tr181		//P3

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_AssociatedDevicesHighWatermarkThresholdReached

/**
 * @brief This API returns the number of times when the current total number of associated
 * device has reached the HighWatermarkThreshold value.
 *
 * This calculation can be based on the parameter AssociatedDeviceNumberOfEntries as well.
 * Implementation specifics about this parameter are left to the product group and the device
 * vendors. It can be updated whenever there is a new client association request to the
 * access point.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   Returns the count.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApAssociatedDevicesHighWatermarkThresholdReached(INT apIndex, UINT *output); //Tr181 //P3

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_AssociatedDevicesHighWatermark

/**
 * @brief Maximum number of associated devices that have ever associated with the access point
 * concurrently since the last reset of the device or WiFi module.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   The maximum number of devices associated.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApAssociatedDevicesHighWatermark(INT apIndex, UINT *output); //Tr181	//P3

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_AssociatedDevicesHighWatermarkDate
/**
 * @brief Date and Time at which the maximum number of associated devices ever associated with
 * the access point concurrently since the last reset of the device or WiFi module.
 *
 * Indicates when the operator defined "Associated Devices High WaterMark" threshhold value is
 * updated. This dateTime value is in UTC.
 *
 * @param[in]  apIndex            The index of the access point array.
 * @param[out] output_in_seconds  Outputs the date and time.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApAssociatedDevicesHighWatermarkDate(INT apIndex, ULONG *output_in_seconds); //Tr181	//P3


//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingServiceCapability	boolean	R
//When true, indicates whether the access point supports interworking with external networks.

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingServiceEnable	boolean	W
//Enables or disables capability of the access point to intework with external network. When enabled, the access point includes Interworking IE in the beacon frames.

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_PasspointCapability	boolean	R
//Indicates whether this access point supports Passpoint (aka Hotspot 2.0). The Passpoint enabled accessPoint must use WPA2-Enterprise security and WPS must not be enabled.

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_PasspointEnable	boolean	W
//Whether Passpoint (aka Hotspot 2.0) support is currently enabled. When enabled, Passpoint specific information elemenets are indicated in beacon frames.

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_MAC_FilteringMode	string	R
//"The current operational state of the MAC Filtering Mode, Enumeration of:    Allow-ALL, Allow, Deny

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.Security.

//Device.WiFi.AccessPoint.{i}.Security.ModesSupported
/**
 * @brief This API indicates which security modes this access Point instance is capable of
 * supporting.
 *
 * Security modes are used to prevent the unauthorized access or damage to computers using
 * wireless networks.
 *
 * This function provides the comma-separated list of strings, each list item is an
 * enumeration of:
 * - None - No Security
 * - WEP-64 - WEP with 64 bit encryption
 * - WEP-128 - WEP with 128 bit encryption
 * - WPA-Personal(WPA-PSK) -  A pre-shared key or passphrase is used for authentication.
     This pre-shared key is dynamically sent between the AP and clients.
 * - WPA2-Personal - WPA2 Personal uses pre-shared keys (PSK) and is designed for home use.
 * - WPA/WPA2-Personal - Mixed mode used in home networks.
 * - WPA-Enterprise - Should only be used when a RADIUS server is connected for client
     authentication.
 * - WPA2-Enterprise - Uses RADIUS server for client authentication and is designed for
     business environments.
 * - WPA/WPA2-Enterprise - Mixed mode used in business environments.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   Outputs the security modes supported by this access point.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApSecurityModesSupported(INT apIndex, CHAR *output);

//Device.WiFi.AccessPoint.{i}.Security.ModeEnabled	string	W
/**
 * @brief This API indicates which security mode is enabled.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   Security mode used by this access Point.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note The value MUST be a member of the list reported by the ModesSupported parameter.
 */
INT wifi_getApSecurityModeEnabled(INT apIndex, CHAR *output);

/**
 * @brief This API sets an environment variable for the basic encryption mode.
 *
 * Valid encryption mode strings are "None" or "WEPEncryption".
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  encMode  The encryption mode to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApSecurityModeEnabled(INT apIndex, CHAR *encMode);

//Device.WiFi.AccessPoint.{i}.Security.WEPKey
//A WEP key expressed as a hexadecimal string.

//Device.WiFi.AccessPoint.{i}.Security.PreSharedKey

/**
 * @brief This API returns the PreShared key.
 *
 * A literal PreSharedKey (PSK) expressed as a hexadecimal string.
 *
 * @param[in]  apIndex        The index of the access point array.
 * @param[out] output_string  The PreShared key.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note output_string must be pre-allocated as 64 character string by caller.
 */
INT wifi_getApSecurityPreSharedKey(INT apIndex, CHAR *output_string);

/**
 * @brief This API sets an environment variable for the PreShared key.
 *
 * @param[in]  apIndex       The index of the access point array.
 * @param[in]  preSharedKey  The Preshared key to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note Input string preSharedKey must be a maximum of 64 characters
 */
INT wifi_setApSecurityPreSharedKey(INT apIndex, CHAR *preSharedKey);

//Device.WiFi.AccessPoint.{i}.Security.KeyPassphrase	string­(63)	W
/**
 * @brief This function returns a  passphrase from which the PreSharedKey is to be generated,
 * for WPA-Personal or WPA2-Personal or WPA-WPA2-Personal security modes.
 *
 * @param[in]  apIndex        The index of the access point array.
 * @param[out] output_string  The passphrase value.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApSecurityKeyPassphrase(INT apIndex, CHAR *output_string);        // outputs the passphrase, maximum 63 characters

/**
 * @brief This API sets the passphrase environment variable.
 *
 * @param[in]  apIndex     The index of the access point array.
 * @param[in]  passPhrase  passphrase to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note passPhrase should be of maximum 63 characters.
 */
INT wifi_setApSecurityKeyPassphrase(INT apIndex, CHAR *passPhrase);

//Device.WiFi.AccessPoint.{i}.Security.RekeyingInterval	unsignedInt	W
//The interval (expressed in seconds) in which the keys are re-generated.
//INT wifi_getApSecurityWpaRekeyInterval(INT apIndex, INT *output_int);         // outputs the rekey interval
//INT wifi_setApSecurityWpaRekeyInterval(INT apIndex, INT rekeyInterval);       // sets the internal variable for the rekey interval

//Device.WiFi.AccessPoint.{i}.Security.Reset

/**
 * @brief This API is used to reset the security settings to the factory default values.
 *
 * The affected settings include ModeEnabled, WEPKey, PreSharedKey and KeyPassphrase.
 *
 * @param[in]  apIndex  The index of the access point array.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApSecurityReset(INT apIndex);

//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_KeyPassphrase	string­(63)	RW

/**
 * @brief This function is used to return the  passphrase used by this access point.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   The passphrase value.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApKeyPassphrase(INT apIndex, CHAR *output); //Tr181

/**
 * @brief This function sets the  passphrase from which the PreSharedKey is to be generated for
 * WPA-Personal or WPA2-Personal or WPA-WPA2-Personal security modes.
 *
 * If KeyPassphrase is written, then PreSharedKey is immediately generated.
 *
 * @param[in]  apIndex    The index of the access point array.
 * @param[in]  passphase  The passphrade to be set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note The ACS SHOULD NOT set both the KeyPassphrase and the PreSharedKey directly.
 * The key is generated as specified by WPA, which uses PBKDF2 from PKCS
 * (Password-based Cryptography Specification) Version 2.0 ([RFC2898]).
 * This custom parameter is defined to enable reading the Passphrase via TR-069 /ACS.
 */
INT wifi_setApKeyPassphrase(INT apIndex, CHAR *passphase); //Tr181

//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_WEPKey	string	RW
//A WEP key expressed as a hexadecimal string.	WEPKey is used only if ModeEnabled is set to WEP-64 or WEP-128.	A 5 byte WEPKey corresponds to security mode WEP-64 and a 13 byte WEPKey corresponds to security mode WEP-128.	This custom parameter is defined to enable reading the WEPKey via TR-069/ACS. When read it should return the actual WEPKey.	If User enters 10 or 26 Hexadecimal characters, it should return keys as Hexadecimal characters.	If user enters 5 or 13 ASCII character key it should return key as ASCII characters.

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.Security.RadiusServerIPAddr
//Device.WiFi.AccessPoint.{i}.Security.RadiusServerPort
/**
 * @brief This API returns the IP Address and port number of the RADIUS server used for WLAN
 * security.
 *
 * RadiusServerIPAddr is only applicable when ModeEnabled is an Enterprise type
 * (i.e. WPA-Enterprise, WPA2-Enterprise or WPA-WPA2-Enterprise).
 *
 * @param[in]  apIndex     The index of the access point array.
 * @param[out] IP_output   IP Address of the RADIUS server.
 * @param[out] Port_output Port number used by the RADIUS server.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApSecurityRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output); //Tr181

/**
 * @brief The IP Address and port number of the RADIUS server used for WLAN security.
 *
 * @param[in]  apIndex    The index of the access point array.
 * @param[in]  IPAddress  IP Address used by the  RADIUS server.
 * @param[in]  port       Port number to be used.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApSecurityRadiusServer(INT apIndex, CHAR *IPAddress, UINT port); //Tr181

//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.RadiusServerRetries	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.RadiusServerRequestTimeout	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.PMKLifetime	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.PMKCaching	boolean	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.PMKCacheInterval	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.MaxAuthenticationAttempts	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.BlacklistTableTimeout	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.IdentityRequestRetryInterval	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.QuietPeriodAfterFailedAuthentication	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.RadiusSecret

/**
 * @brief This API returns the RADIUS server information  used for WLAN security.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   The Output parameter which holds the RADIUS server details.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *output); //Tr181

/**
 * @brief This API sets the RADIUS server information  used for WLAN security.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  input    RADIUS server details to be set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *input); //Tr181


//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.WPS.
//Device.WiFi.AccessPoint.{i}.WPS.Enable

/**
 * @brief Enables or disables WPS functionality for this access point.
 *
 * @param[in]  apIndex      The index of the access point array.
 * @param[out] output_bool  The WPS enable state of this access point.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApWpsEnable(INT apIndex, BOOL *output_bool);

/**
 * @brief  Sets the WPS enable environment variable for this access point to the value
 * of enableValue, 1=enabled, 0=disabled.
 *
 * @param[in]  apIndex      The index of the access point array.
 * @param[in]  enableValue  Boolean value to enable or disable WPS.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApWpsEnable(INT apIndex, BOOL enableValue);

//Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsSupported

/**
 * @brief This API is used to get WPS configuration  methods supported by the device.
 *
 * This function provides the comma-separated list of strings, each list item is an
 * enumeration of:
 * - USBFlashDrive - User uses a USB flash drive to transfer data between the new client device
     and the network's access point.
 * - Ethernet - If there is no WPS button, User can configure the wireless settings using
     ethernet on a wifi-extender.
 * - ExternalNFCToken - NFC Tag contains a password token to authenticate Wi-Fi connection.
     Uses external program to write NDEF encapsulation data to the NFC tag using an external
     program.
 * - IntegratedNFCToken - The NFC Tag is integrated in the device.
 * - NFCInterface - User has to bring the client close to AP allowing a near field
     communication between the devices.
 * - PushButton - User has to push a button, either an actual or virtual one, on both the
     access point and the new wireless client device.
 * - PIN - User has to be read the PIN from either a sticker or display on the new wireless
     device.
 *
 * Device must support PushButton and PIN methods.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[out] output   The WPS supported methods.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApWpsConfigMethodsSupported(INT apIndex, CHAR *output); //Tr181

//Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsEnabled	string	W

/**
 * @brief This function indicates WPS configuration methods enabled on the device.
 *
 * The API provides the comma-separated list of the enabled WPS config methods.
 * Each list item MUST be a member of the list reported by the ConfigMethodsSupported parameter.
 *
 * @param[in]  apIndex        The index of the access point array.
 * @param[out] output_string  The current WPS method.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApWpsConfigMethodsEnabled(INT apIndex, CHAR *output_string);

/**
 * @brief  This API sets the active WPS method.
 *
 * @param[in]  apIndex       The index of the access point array.
 * @param[in]  methodString  The method to enable.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApWpsConfigMethodsEnabled(INT apIndex, CHAR *methodString);

/**
 * @brief  This API outputs the pin value required for the client to establish the WPS
 * connection with the access point.
 *
 * @param[in]  apIndex       The index of the access point array.
 * @param[out] output_ulong  Output parameter which saves the Device PIN.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note ulong_pin must be allocated by the caller.
 */
INT wifi_getApWpsDevicePIN(INT apIndex, ULONG *output_ulong);

/**
 * @brief  Sets WPS device PIN for the selected access point.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  pin      The PIN code to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApWpsDevicePIN(INT apIndex, ULONG pin);

/**
 * @brief  This API is used to get the WPS configured status.
 *
 * Outputs either "Configured" or "Not configured".
 *
 * @param[in]  apIndex        The index of the access point array.
 * @param[out] output_string  The output paramter which holds the wps config status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_getApWpsConfigurationState(INT apIndex, CHAR *output_string);

/**
 * @brief  Sets the WPS pin for this access Point.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  pin      The PIN code to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApWpsEnrolleePin(INT apIndex, CHAR *pin);

/**
 * @brief  This function is called when the WPS push button has been pressed for this access
 * Point.
 *
 * @param[in]  apIndex  The index of the access point array.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setApWpsButtonPush(INT apIndex);

/**
 * @brief  Cancels WPS mode for this access Point.
 *
 * @param[in] apIndex  The index of the access point array.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_cancelApWPS(INT apIndex);

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_OperatingStandard
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_OperatingChannelBandwidth
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_SNR
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_InterferenceSources	//P3
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_DataFramesSentAck		//P3
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_DataFramesSentNoAck	//P3
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_BytesSent
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_BytesReceived
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_RSSI
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_MinRSSI				//P3
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_MaxRSSI				//P3
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_Disassociations		//P3
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_AuthenticationFailures	//P3

/**
 * @brief The function  provides a list of the devices currently associated with the
 * access point.
 *
 * @param[in]  apIndex               The index of the access point array.
 * @param[out] associated_dev_array  Structure which holds the devices currently associated
 *                                   with the access point.
 * @param[out] output_array_size     The length of the output array
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 *
 * @note HAL function should allocate an data structure array, and return to caller
 * with "associated_dev_array".
 */
INT wifi_getApAssociatedDeviceDiagnosticResult(INT apIndex, wifi_associated_dev_t **associated_dev_array, UINT *output_array_size); //Tr181

//------------------------------------------------------------------------------------------------------
////SSID stearing APIs using blacklisting
//INT wifi_setSsidSteeringPreferredList(INT radioIndex,INT apIndex, INT *preferredAPs[32]);  // prevent any client device from assocating with this ipIndex that has previously had a valid assocation on any of the listed "preferred" SSIDs unless SsidSteeringTimeout has expired for this device. The array lists all APs that are preferred over this AP.  Valid AP values are 1 to 32. Unused positions in this array must be set to 0. This setting becomes active when committed.  The wifi subsystem must default to no preferred SSID when initalized.
////Using the concept of an “preferred list” provides a solution to most use cases that requrie SSID Steering.  To implement this approach, the AP places the STA into the Access Control DENY list for a given SSID only if the STA has previously associated to one of the SSIDs in the “preferred list” that for SSID.
//INT wifi_setSsidSteeringTimout(INT radioIndex,INT apIndex, ULONG SsidSteeringTimout);  // only prevent the client device from assocatign with this apIndex if the device has connected to a preferred SSID within this timeout period - in units of hours.  This setting becomes active when committed.

/**
 * @brief This callback will be invoked when a new wifi client comes to associate to the
 * access Point.
 *
 * @param[in]  apIndex         The index of the access point array.
 * @param[out] associated_dev  Indicates the clients associated with the access point.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
typedef INT (*wifi_newApAssociatedDevice_callback)(INT apIndex, wifi_associated_dev_t *associated_dev);

/**
 * @brief Callback registration function.
 *
 * @param[in] callback_proc the callback function to associate new client device to the
 * access point.
 */
void wifi_newApAssociatedDevice_callback_register(wifi_newApAssociatedDevice_callback callback_proc);

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.AccessNetworkType

/**
 * @brief This API sets the access Network Type value to be included in the Interworking IE
 * in the beacons.
 *
 * Interworking IE(Information Elements) provides information about the Interworking service
 * capabilities such as the Internet availability in a specific service provider network.
 *
 * Possible values are:
 * Access network type  |        Meaning                    |                Description
 * :------------------- |     -------------                 |                -----------
 * 0                    | Private network                   | Nonauthorized users are not permitted on this network.Eg:                                                                     Home networks and Enterprise networks.
 * 1                    | Private network with guest access | Private network but guest accounts are available.                                                                             Eg: enterprise network offering access to guest users.
 * 2                    | Chargeable public network         | Access to the network requires payment. Eg hotel offering                                                                     in-room internet access service for a fee.
 * 3                    | Free public network               | The network is accessible to anyone and no charges apply                                                                      for the network use. Eg airport hotspot
 * 4                    | Personal device network           | A network of personal devices.                                                                                                Eg: camera attaching to a printer, thereby forming a network                                                                  for the purpose of printing pictures.
 * 5                    | Emergency services only network   | A network dedicated and limited to accessing emergency services.
 * 6 to 13              | Reserved                          | Reserved
 * 14                   | Test or experimental              | The network is used for test or experimental purposes only.
 * 15                   | Wildcard                          | Wildcard access network type.
 *
 * @param[in]  apIndex  The index of the access point array.
 * @param[in]  accessNetworkType The access network value to be set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns 0 if successful, appropriate error code otherwise.
 */
INT wifi_setAccessNetworkType(INT apIndex, INT accessNetworkType);   // P3

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.Internet
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.VenueGroupCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.VenueTypeCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.HESSID
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.DGAFEnable
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.ANQPDomainID
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.VenueNamesNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.OperatorNamesNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.ConsortiumOIsNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.DomainNamesNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.3GPPNetworksNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.NAIRealmsNumberOfEntries

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.VenueNames.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.VenueNames.{i}.LanguageCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.VenueNames.{i}.VanueName

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OperatorNames.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OperatorNames.{i}.LanguageCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OperatorNames.{i}.OperatorName

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.ConsortiumOIs.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.ConsortiumOIs.{i}.OI

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.DomainNames.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.DomainNames.{i}.DomainName

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.3GPPNetworks.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.3GPPNetworks.{i}.MCC
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.3GPPNetworks.{i}.MNC

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.NAIRealmEncodingType
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.NAIRealm
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethodsNumberOfEntries

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.EAPMethod
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.AuthenticationParametersNumberOfEntries

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.AuthenticationParameters.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.AuthenticationParameters.{i}.ID
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.AuthenticationParameters.{i}.Value

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.LinkStatus
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.AtCapacity
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.DownlinkSpeed
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.UplinkSpeed
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.DownlinkLoad
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.UplinkLoad

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProvidersNumberOfEntries

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.OSUServerURI
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.OSUMethodsList
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.OSUNAI
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.NamesNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.IconsNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}ServiceDescriptionsNumberOfEntries

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Names.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Names.{i}.LanguageCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Names.{i}.OSUProviderFriendlyName

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Icons.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Icons.{i}.IconWidth
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Icons.{i}.IconHeight
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Icons.{i}.LanguageCode

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.ServiceDescriptions.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.ServiceDescriptions.{i}.LanguageCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.ServiceDescriptions.{i}.ServiceDescription

//-----------------------------------------------------------------------------------------------
//Device.IP.Diagnostics.
//Device.IP.Diagnostics.IPPing.
//Device.IP.Diagnostics.IPPing.DiagnosticsState
//Device.IP.Diagnostics.IPPing.Interface
//Device.IP.Diagnostics.IPPing.Host
//Device.IP.Diagnostics.IPPing.NumberOfRepetitions
//Device.IP.Diagnostics.IPPing.Timeout
//Device.IP.Diagnostics.IPPing.DataBlockSize
//Device.IP.Diagnostics.IPPing.DSCP

//Device.IP.Diagnostics.IPPing.SuccessCount
//Device.IP.Diagnostics.IPPing.FailureCount
//Device.IP.Diagnostics.IPPing.AverageResponseTime
//Device.IP.Diagnostics.IPPing.MinimumResponseTime
//Device.IP.Diagnostics.IPPing.MaximumResponseTime

//Start the ping test and get the result
//INT wifi_getIPDiagnosticsIPPingResult(wifi_diag_ipping_setting_t *input, wifi_diag_ipping_result_t *result); //Tr181
//--------------------------------------------------------------------------------------------------
// Wifi Airtime Management and QOS APIs to control contention based access to airtime
//INT wifi_clearDownLinkQos(INT apIndex);                             // clears the QOS parameters to the WMM default values for the downlink direction (from the access point to the stations.  This set must take affect when the api wifi_applySSIDSettings() is called.
//INT wifi_setDownLinkQos(INT apIndex, wifi_qos_t qosStruct);        // sets the QOS variables used in the downlink direction (from the access point to the stations).  Values must be allowable values per IEEE 802.11-2012 section 8.4.2.31.  Note:  Some implementations may requrie that all downlink APs on the same radio are set to the same QOS values. Default values are per the WMM spec.  This set must take affect when the api wifi_applySSIDSettings() is called.
//INT wifi_clearUpLinkQos(INT apIndex);                               // clears the QOS parameters to the WMM default values for the uplink direction (from the Wifi stations to the ap.  This must take affect when the api wifi_applySSIDSettings() is called.
//INT wifi_setUpLinkQos (INT apIndex, wifi_qos_t qosStruct);         // sets the QOS variables used in the uplink direction (from the Wifi stations to the AP). Values must be allowable values per IEEE 802.11-2012 section 8.4.2.31. The default values must be per the WMM spec.  This set must take affect when the api wifi_applySSIDSettings() is called.

//--------------------------------------------------------------------------------------------------
// Wifi Airtime Management and QOS APIs to control downlink queue prioritization
//INT wifi_getDownLinkQueuePrioritySupport (INT apIndex, INT *supportedPriorityLevels);  //This api is used to get the the number of supported downlink queuing priority levels for each AP/SSID.  If priority queuing levels for AP/SSIDs are not supported, the output should be set to 1. A value of 1 indicates that only the same priority level is supported for all AP/SSIDs.
//INT wifi_setDownLinkQueuePriority(INT apIndex, INT priorityLevel); // this sets the queue priority level for each AP/SSID in the downlink direction.  It is used with the downlink QOS api to manage priority access to airtime in the downlink direction.  This set must take affect when the api wifi_applySSIDSettings() is called.
/** @} */
#else
#error "! __WIFI_AP_HAL_H__"
#endif
