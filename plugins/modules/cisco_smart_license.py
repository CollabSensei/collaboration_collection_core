#!/usr/bin/env python3

# Copyright: (c) 2021, World Wide Technology, All Rights Reserved
# Written By: Dennis Heim (dennis.heim@wwt.com)

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: csr1k_smart_license

short_description: This module is used create a new token on the smart license server contained with in a vApp and register a CSR1k with the smart license server.

version_added: "2.9"

description:
    - "This module is used create a new token on the smart license server contained with in a vApp and register a CSR1k with the smart license server."

options:
    vapp_ip:
        description:
            - ATC IP Address off the vApp.
        required: true
    api_port:
        description:
            - Port that forwards to the API Endpoint.
        required: false
    ssms_ip:
        description: IP address of the Smart Satelite Server. This is only required if (use_proxy == true).
    ssms_port:
        description:
            - Port that forwards to the Smart License Satelite API. Default is 8443.
        required: false
    ip_address:
        description:
            - IP Address of the VM we are updating. This is only required if (use_proxy) is set to true
        required: false
    username:
        description:
            - Username to access endpoint API.
        required: true
    password:
        description:
            - Password to access endpoint API.
        required: true
    token_description:
        description:
            - Text Description of Smart License Token that will be created.
        required: false
    type:
        description:
            - Type of Device (csr1k).
        required: true
    version:
        description:
            - Version of Device
    cmm_pmp:
        description:
            - Quantity of Personal Multiparty Licenses to reserve (Cisco Meeting Manager Only)
    cmm_smp:
        description:
            - Quantity of Shared Multiparty Licenses to reserve (Cisco Meeting Manager Only)
    cmm_rec:
        description:
            - Quantity of Recording/Streaming Licenses to reserve (Cisco Meeting Manager Only)

author:
    - Dennis Heim (dennis.heim@wwt.com)
'''

EXAMPLES = '''
# Register CSR1K with Smart License
- name: CSR1K Smart License Register
  cisco_smart_license:
    vapp_ip: 10.246.32.161
    ssms_port: 1030
    api_port: 1026
    username: "wwt"
    password: "WWTwwt1!"
    token_description: "New Token"
    type: csr1k
    version: 1.0
'''

RETURN = '''
response:
    description: The Response Data from TrafficJam
    type: dict
    returned: always

status_code:
    description: The HTTP Status Code returned by TrafficJam
    type: int
    returned: always
'''

from ansible.module_utils.basic import AnsibleModule
from requests.exceptions import HTTPError
import requests
import json
import time
import sys
import xml.etree.ElementTree as ET
import warnings
import hashlib

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Global Variable for session management
pSession = requests.session()



def customSessionGet(*args, **kwargs):
    global pSession
    iHttp = 0
    while True:
        try:
            response = pSession.get(args[0], **kwargs)
            if(response.status_code == args[1]):
                return response
        except Exception as err:
            if (iHttp > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(response.text)
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                iHttp = iHttp + 1
                continue

def customSessionPost(*args, **kwargs):
    global pSession
    iHttp = 0
    while True:
        try:
            response = pSession.post(args[0], **kwargs)
            if(response.status_code == args[1]):
                return response
        except Exception as err:
            if (iHttp > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(response.text)
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                iHttp = iHttp + 1
                continue

def customHttpGet(*args, **kwargs):
    iHttp = 0
    while True:
        try:
            response = requests.get(args[0], **kwargs)
            return response
        except Exception as err:
            if (iHttp > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(response.text)
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                iHttp = iHttp + 1
                continue

def customHttpPost(*args, **kwargs):
    iHttp = 0
    while True:
        try:
            response = requests.post(args[0], **kwargs)
            return response
        except Exception as err:
            if (iHttp > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(response.text)
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                iHttp = iHttp + 1
                print('fail ' + str(iHttp))
                continue

def customHttpPut(*args, **kwargs):
    iHttp = 0
    while True:
        try:
            response = requests.put(args[0], **kwargs)
            return response
        except Exception as err:
            if (iHttp > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(response.text)
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                iHttp = iHttp + 1
                print('fail ' + str(iHttp))
                continue

def getSmartLicenseToken(tDescription):
    # Creates a Smart License Token with the given description and parameters
    
    # Get oAuth Token
    url = "https://" + (ssms_ip if use_proxy else vapp_ip) + ":" + ssms_port + "/backend/oauth/token"
    oAuthBody = {}
    oAuthBody['client_id'] = 'cf4e88982460dee6227e5d3aec1657ed355dca49117199b2dd85d080f48ebe77'
    oAuthBody['client_secret'] = 'd4958dd6c7440a882f43c03f84ea0bc2ba240e2f657a2fd8dd2437c1e0107e4a'
    oAuthBody['grant_type'] = "client_credentials"

    iHttp = 0
    while True:
        try:
            oAuthResponse = customHttpPost(url,json=oAuthBody, proxies=sock5Proxy, timeout=60, verify = False)
            oAuthAccessToken = (json.loads(oAuthResponse.text)['access_token'])
            break
        except Exception as err:
            if (iHttp > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                iHttp = iHttp + 1
                print('fail ' + str(iHttp))
                continue
    
    # Create Licensing Token
    url = "https://" + (ssms_ip if use_proxy else vapp_ip) + ":" + ssms_port + "/backend/api/v1/accounts/WORLD%20WIDE%20TECHNOLOGY%20INC/virtual-accounts/Default/tokens"
    createTokenHeader = {'Authorization': "Bearer " + oAuthAccessToken }
    createTokenJson = {}
    createTokenJson['description'] = tDescription
    createTokenJson['expiresAfterDays'] = '365'
    createTokenJson['exportControlled'] = 'Allowed'

    iHttp = 0
    while True:
        try:
            createTokenResponse = customHttpPost(url, json=createTokenJson, headers=createTokenHeader, proxies=sock5Proxy, timeout=60, verify = False)
            return (json.loads(createTokenResponse.text)['tokenInfo']['token'])
        except Exception as err:
            if (iHttp > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                iHttp = iHttp + 1
                print('fail ' + str(iHttp))
                continue


def validate_csr1k_connectivity():
    url = "https://" + hostname + ":" + api_port + "/restconf/data/cisco-smart-license:licensing/state/state-info/registration/registration-state"

    i = 0
    while True:
        try:
            response = (requests.get(url, auth=(username, password), timeout = 15, proxies=sock5Proxy, verify = False))
            if (response.status_code == 200):
                break
        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(response.text)
                
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

def validate_csr1k_licenseStatus():
    #Verify License Status
    url = "https://" + hostname+ ":" + api_port + "/restconf/data/cisco-smart-license:licensing/state/state-info/registration/registration-state"

    GetLicenseStatus = ''
    i = 0

    while (GetLicenseStatus != 'reg-state-complete'):

        try:
            GetLicenseResponse = customHttpGet(url, auth=(username, password), headers={'Content-Type': "application/yang-data+json"}, proxies=sock5Proxy, verify = False)
            GetLicenseStatus = json.loads(GetLicenseResponse.text)['cisco-smart-license:registration-state']
        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(GetLicenseResponse.text)
                
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

        if i > 100:
            # License status failed
            result['changed'] = False
            result['failed'] = True
            module.fail_json(msg=GetLicenseStatus, **result)
            break

        time.sleep(60)
        i = i + 1

    if (GetLicenseStatus == 'reg-state-complete'):
        # License status successful. Pass this back to ansible
        result['changed'] = True
        result['failed'] = False
        result['response'] = GetLicenseStatus
        module.exit_json(**result)

def validate_ssms_connectivity():
    # HTTP GET Request without authorization. Expect 403 Unauthorized. Prior to services coming up will receive 502 - Bad Gateway
    url = "https://" + (ssms_ip if use_proxy else vapp_ip) + ":" + ssms_port + "/backend/api/v1/accounts/WORLD%20WIDE%20TECHNOLOGY%20INC/virtual-accounts/Default/tokens"
    i = 0
    while True:
        try:
            response = (requests.get(url, auth=(username, password), timeout = 60, proxies=sock5Proxy, verify = False))
            
            if (response.status_code == 403):
                break
        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(response.text)
                
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

def validate_asav_connectivity():
    # Get Serial Number from ASA to verify it is responding to API request
    url = "https://" + hostname + ":" + api_port + "/api/monitoring/serialnumber"
    i = 0
    while True:
        try:
            response = (requests.get(url, auth=(username, password), headers={'User-Agent': 'REST API Agent'}, timeout = 60 , proxies=sock5Proxy, verify = False))
            if (response.status_code == 200):
                break
        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(response.text)
                
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

def validate_asav_licenseStatus():
    #Verify License Status
    url = "https://" + hostname + ":" + api_port + "/api/licensing/smart/asav/info"
    GetLicenseStatus = ''
    i = 0

    while (GetLicenseStatus != 'REGISTERED'):

        try:
            GetLicenseResponse = customHttpGet(url, auth=(username,password), headers={'User-Agent': "REST API Agent" }, proxies=sock5Proxy, verify = False)
            GetLicenseStatus = json.loads(GetLicenseResponse.text)['registration']
            ASALicenseDict = {}
            for regdata in GetLicenseStatus:
                ASALicenseDict.update({regdata.split(':')[0] : str.strip(regdata.split(':')[1])})
            # Extract License Registration Status
            GetLicenseStatus = ASALicenseDict["Status"]

        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(GetLicenseResponse.text)
                
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

        if i > 100:
            # License status failed
            result['changed'] = False
            result['failed'] = True
            result['response'] = GetLicenseStatus
            module.fail_json(**result)
            break

        time.sleep(60)
        i = i + 1

    if (GetLicenseStatus == 'REGISTERED'):
        # License status successful. Pass this back to ansible
        result['changed'] = True
        result['failed'] = False
        result['response'] = GetLicenseStatus
        module.exit_json(**result)

def validate_cucm_connectivity():
    url = "https://" + hostname + ":" + api_port + "/axl/"
    # Body to Query AXL to return list of CUCM nodes
    body = """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://www.cisco.com/AXL/API/%v">
        <soapenv:Header/>
        <soapenv:Body>
            <ns:listProcessNode sequence="?">
                <searchCriteria>
                    <name>%</name>
                </searchCriteria>
                <returnedTags>
                    <name/>
                </returnedTags>
            </ns:listProcessNode>
        </soapenv:Body>
        </soapenv:Envelope>"""
    
    # Replace request template with version number
    body = body.replace("%v",str(version))

    i = 0
    while True:
        try:
            axl_response = (requests.post(url, auth=(username, password), data=body, headers={'SOAPAction' : 'CUCM:DB ver=' + str(version), 'Content-Type' : 'text/xml' }, proxies=sock5Proxy, timeout = 60, verify = False))
            if (axl_response.status_code == 200):
                break
        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(axl_response.text)
                
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

def validate_cucm_licenseStatus():
    #Verify License Status
    url = "https://" + hostname + ":" + api_port + "/axl/"
    GetLicenseStatus = ''
    i = 0

    body = """
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://www.cisco.com/AXL/API/%version">
    <soapenv:Header/>
    <soapenv:Body>
        <ns:getSmartLicenseStatus/>
    </soapenv:Body>
    </soapenv:Envelope>""" 

    body = body.replace("%version",str(version))

    while (GetLicenseStatus != 'Registered'):
        try:
            GetLicenseResponse = customHttpPost(url, data=body, auth=(username,password), headers={'SOAPAction' : 'CUCM:DB ver=' + str(version), 'Content-Type' : 'text/xml'}, proxies=sock5Proxy, verify = False)
            GetLicenseStatus = ET.fromstring(GetLicenseResponse.text)[0][0][0][1][0].text

        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(GetLicenseResponse.text)
                
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

        if i > 100:
            # License status failed
            result['changed'] = False
            result['failed'] = True
            result['response'] = GetLicenseStatus
            module.fail_json(**result)
            break

        time.sleep(60)
        i = i + 1

    if (GetLicenseStatus == 'Registered'):
        # License status successful. Pass this back to ansible
        result['changed'] = True
        result['failed'] = False
        result['response'] = GetLicenseStatus
        module.exit_json(**result)

def validate_cuc_connectivity():
    # Get CUC API Availability
    url = "https://" + hostname + ":" + api_port + "/vmrest/smartlicense/licensedetails"
    i = 0
    while True:
        try:
            response = (requests.get(url, auth=(username, password), timeout = 60, proxies=sock5Proxy, verify = False))
            if (response.status_code == 200):
                break
        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(response.text)
                
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

def validate_cuc_licenseStatus():
    #Verify License Status
    url = "https://" + hostname + ":" + api_port + "/vmrest/smartlicense/licensedetails"
    cuc_headers = {
        'Accept' : 'application/json',
        'Content-Type' : 'application/json'
    }
    GetLicenseStatus = ''
    i = 0

    while (GetLicenseStatus != 'Registered'):
        try:
            GetLicenseResponse = customHttpGet(url, auth=(username,password), headers=cuc_headers, proxies=sock5Proxy, verify = False)
            GetLicenseStatus = json.loads(GetLicenseResponse.text)['Register']['Status']
        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(GetLicenseResponse.text)
                
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

        if i > 100:
            # License status failed
            result['changed'] = False
            result['failed'] = True
            result['response'] = GetLicenseStatus
            module.fail_json(**result)
            break

        time.sleep(60)
        i = i + 1

    if (GetLicenseStatus == 'Registered'):
        # License status successful. Pass this back to ansible
        result['changed'] = True
        result['failed'] = False
        result['response'] = GetLicenseStatus
        module.exit_json(**result)

def validate_uccx_connectivity():
    url = 'https://' + hostname + ":" + api_port + '/adminapi/systemConfig'

    i = 0
    uccx_headers = {
    'Host': hostname + ":" + api_port
    }
    while True:
        try:
            response = (requests.get(url, auth=(username,password), headers=uccx_headers, timeout = 60, proxies=sock5Proxy, verify = False))
            if (response.status_code == 200):
                result['response'] = response.text
                break
        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

def validate_uccx_licenseStatus(uccx_response):
    # Request includes status. Unlike other modules where we poll for status. We will force success condition.
    GetLicenseStatus = 'success'
    i = 0

    while (GetLicenseStatus != 'success'):
        try:
            #GetLicenseStatus = json.loads(uccx_response.text)['status']
            GetLicenseStatus = 'success'

        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(uccx_response.text)
                
                module.fail_json(msg=str(uccx_response.text),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

        
        if (i > 100):
            # License status failed
            result['changed'] = False
            result['failed'] = True
            module.fail_json(msg=GetLicenseStatus, **result)
            break

        time.sleep(60)
        i = i + 1

    if (GetLicenseStatus == 'success'):
        # License status successful. Pass this back to ansible
        result['changed'] = True
        result['failed'] = False
        result['response'] = GetLicenseStatus
        module.exit_json(**result)

def validate_expw_connectivity():
    url = "https://" + hostname + ":" + api_port + "/api/status/common/smartlicensing/licensing"
    i = 0

    while True:
        try:
            response = (requests.get(url, auth=(username, password), timeout = 60, proxies=sock5Proxy, verify = False))
            if (response.status_code == 200):
                break
        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(response.text)
                
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

def validate_expw_licenseStatus():
    #Verify License Status
    url = "https://" + hostname + ":" + api_port + "/api/status/common/smartlicensing/licensing"
    GetLicenseStatus = ''
    i = 0

    while (GetLicenseStatus != 'REGISTERED'):
        try:
            GetLicenseResponse = customHttpGet(url, auth=(username,password), proxies=sock5Proxy, timeout=60, verify = False)
            GetLicenseStatus = json.loads(GetLicenseResponse.text)['Registration']['RegistrationStatus']

        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(GetLicenseResponse.text)
                
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

        if i > 100:
            # License status failed
            result['changed'] = False
            result['failed'] = True
            result['response'] = GetLicenseStatus
            module.fail_json(**result)
            break

        time.sleep(60)
        i = i + 1

    if (GetLicenseStatus == 'REGISTERED'):
        # License status successful. Pass this back to ansible
        result['changed'] = True
        result['failed'] = False
        result['response'] = GetLicenseStatus
        module.exit_json(**result)

def validate_cmm_connectivity():
    url = "https://" + hostname + ":" + api_port + "/api_login"
    
    i = 0

    while True:
        try:
            response = (requests.get(url, timeout = 60, proxies=sock5Proxy, verify = False))
            if (response.status_code == 200):
                break
        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(response.text)
                
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

def validate_cmm_licenseStatus(cmm_session):
    # cmm_session is a request session object. This provides for authentication. Because there is no api, this eliminates the authentication process

    # Verify License Status
    url = 'https://' + hostname + ":" + api_port + '/licensing/api/smart'
    cmm_session.headers = ''
    GetLicenseStatus = ''
    i = 0

    while (GetLicenseStatus != 'registered'):
        iHttp = 0
        while True:
            try:
                GetLicenseResponse = cmm_session.get(url, timeout=60, proxies=sock5Proxy, verify = False)
                GetLicenseStatus = json.loads((GetLicenseResponse.text))['registration_status']
                break
            except Exception as err:
                if (iHttp > 100):
                    # Failed to connect for 60 minutes
                    result['changed'] = False
                    result['failed'] = True
                    if 'response' in locals():
                        result['response'] = str(GetLicenseResponse.text)
                    module.fail_json(msg=str(err),**result)
                else:
                    # Unable to connect, pausing for 1 minutes
                    time.sleep(60)
                    iHttp = iHttp + 1
                    continue
      

        if i > 100:
            # License status failed
            result['changed'] = False
            result['failed'] = True
            result['response'] = GetLicenseStatus
            module.fail_json(**result)
            break

        if (GetLicenseStatus != 'registered'):
            time.sleep(60)
            i = i + 1

    if (GetLicenseStatus == 'registered'):
        # License status successful. Pass this back to ansible. This is turned off because CMM registration requires a 2nd step of setting license quantities.
        #result['changed'] = True
        #result['failed'] = False
        #result['response'] = GetLicenseStatus
        #module.exit_json(**result)
        pass

def validate_cer_connectivity():
    url = 'https://' + hostname + ":" + api_port + '/cerappservices/export/authenticate/status/' + username + '/' + str(hashlib.sha256(password.encode()).hexdigest())

    i = 0
    cer_headers = {
    'Host': hostname + ":" + api_port
    }
    while True:
        try:
            response = (requests.get(url, auth=(username,password), headers=cer_headers, timeout = 60, proxies=sock5Proxy, verify = False))
            if (response.status_code == 200):
                result['response'] = response.text
                break
        except Exception as err:
            if (i > 100):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(60)
                i = i + 1
                continue

def run_module():

    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        vapp_ip=dict(type='str', required=True),
        api_port=dict(type='str', required=False),
        ssms_ip=dict(type='str', required=False),
        ssms_port=dict(type='str', default=8443, required=False),
        ip_address=dict(type='str', required=False),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        token_description=dict(type='str', required=False),
        model=dict(type='str', required=True),
        version=dict(type='float', required=True),
        cmm_pmp=dict(type='str', default=10, required=False),
        cmm_smp=dict(type='str', default=2, required=False),
        cmm_rec=dict(type='str', default=20, required=False),
        use_proxy=dict(type='bool', required=True)
    )
    
    # seed the result dict in the object
    # we primarily care about changed and the response data
    # change is if this module effectively modified the target
    # response is the data returned by TrafficJam
    # status_code is the HTTP status code returned by the requests module

    global result
    result = dict(
        changed=False,
        response='',
        status_code=''
    )

    global module
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    global pSession


    # Collect Module Parameters
    global vapp_ip
    vapp_ip = module.params['vapp_ip']
    global api_port
    api_port = module.params['api_port']
    global ssms_ip
    ssms_ip = module.params['ssms_ip']
    global ssms_port
    ssms_port = module.params['ssms_port']
    global ip_address
    ip_address = module.params['ip_address']
    global username
    username = module.params['username']
    global password
    password = module.params['password']
    global token_description
    token_description = module.params['token_description']
    global model
    model = module.params['model']
    global version
    version = module.params['version']
    global cmm_pmp
    cmm_pmp = module.params['cmm_pmp']
    global cmm_smp
    cmm_smp = module.params['cmm_smp']
    global cmm_rec
    cmm_rec = module.params['cmm_rec']
    global use_proxy
    use_proxy = module.params['use_proxy']

    # Set Hostname to use (if using proxy use ip_address, otherwise use vapp_ip)
    global hostname
    global sock5Proxy
    if (use_proxy):
        hostname = ip_address
        sock5Proxy = {
            'http': 'socks5h://' + vapp_ip + ':1080',
            'https':'socks5h://' + vapp_ip + ':1080'
        }
    else:
        hostname = vapp_ip
        sock5Proxy = ''

    if (model == "csr1k"):
        # Verify CSR1K is responding to API requests
        validate_csr1k_connectivity()

        # Verify SSMS is responding to API requests
        validate_ssms_connectivity()

        # License CSR1000v
        url = "https://" + hostname + ":" + api_port + "/restconf/data/cisco-smart-license:register-id-token"
        CSRLicenseJSON = {}
        CSRLicenseJSONChild = {}
        CSRLicenseJSONChild['id-token'] = getSmartLicenseToken(token_description)
        CSRLicenseJSONChild['force'] = True
        CSRLicenseJSON['cisco-smart-license:register-id-token'] = CSRLicenseJSONChild
        customHttpPost(url, json=CSRLicenseJSON, auth=(username,password), headers={'Content-Type': 'application/yang-data+json'},proxies=sock5Proxy,  verify = False)

        # Verify CSR1Kv is licensed
        validate_csr1k_licenseStatus()

    if (model == 'asav'):
        # Verify ASAv is responding to API requests
        validate_asav_connectivity()

        # Verify SSMS is responding to API requests
        validate_ssms_connectivity()

        # License ASAv
        url = "https://" + hostname + ":" + api_port + "/api/licensing/smart/asav/register"
        ASALicenseJSON = {}
        ASALicenseJSON['kind'] = 'object#SmartLicenseRegId'
        ASALicenseJSON['idToken'] = getSmartLicenseToken(token_description)
        ASALicenseJSON['force'] = True
        customHttpPost(url, json=ASALicenseJSON, auth=(username,password), headers={'User-Agent': "REST API Agent" }, proxies=sock5Proxy, verify = False)

        # Verify ASAv is licensed
        validate_asav_licenseStatus()
        
    if (model == 'cucm'):
        # Verify ASAv is responding to API requests
        validate_cucm_connectivity()

        # Verify SSMS is responding to API requests
        validate_ssms_connectivity()

        # License CUCM
        url = "https://" + hostname + ":" + api_port + "/axl/"
        body = """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://www.cisco.com/AXL/API/%version">
        <soapenv:Header/>
        <soapenv:Body>
            <ns:doSmartLicenseRegister>
                <token>%token</token>
                <force>true</force>
            </ns:doSmartLicenseRegister>
        </soapenv:Body>
        </soapenv:Envelope>""" 

        body = body.replace("%version",str(version))
        body = body.replace("%token", getSmartLicenseToken(token_description))
        if(format(version,".0f") == '12'):
            customHttpPost(url, data=body, auth=(username,password), headers={'SOAPAction' : 'CUCM:DB ver=' + str(version) }, proxies=sock5Proxy, timeout=(300,300), verify = False)
        elif((format(version,".0f") == '14')):
            iHttp = 0
            while True:
                try:
                    response = requests.post(url, data=body, auth=(username,password),headers={'SOAPAction' : 'CUCM:DB ver=' + str(version) }, proxies=sock5Proxy, timeout=(300,300), verify = False)
                    break
                except requests.exceptions.ConnectionError as err:
                    if ('RemoteDisconnected' in str(err)):
                        # Request Actually Succeeded (handling delay's and SOCKS issues)
                        time.sleep(120)
                        break
                except Exception as err:
                    if (iHttp > 100):
                        # Failed to connect for 60 minutes
                        result['changed'] = False
                        result['failed'] = True
                        if 'response' in locals():
                            result['response'] = str(response.text)
                        module.fail_json(msg=str(err),**result)
                    else:
                        # Unable to connect, pausing for 1 minutes
                        time.sleep(60)
                        iHttp = iHttp + 1
                        print('fail ' + str(iHttp))
                        continue

        # Verify CUCM is licensed
        validate_cucm_licenseStatus()

    if (model == 'cuc'):
        # Verify cuc is responding to API requests
        validate_cuc_connectivity()

        # Verify SSMS is responding to API requests
        validate_ssms_connectivity()

        # License CUC
        url = "https://" + hostname + ":" + api_port + "/vmrest/smartlicense/register"
        CUCLicenseJSON = {}
        CUCLicenseJSON['token'] = getSmartLicenseToken(token_description)
        CUCLicenseJSON['force'] = True
        customHttpPut(url, json=CUCLicenseJSON, auth=(username,password), proxies=sock5Proxy, verify = False)

        # Verify CUC is licensed
        validate_cuc_licenseStatus()

    if (model == "uccx"):

        # Verify UCCx is responding to API requests
        validate_uccx_connectivity()
        

        # Verify SSMS is responding to API requests
        validate_ssms_connectivity()

        # Get jSession Cookie
        url = "https://" + hostname + ":" + api_port + "/appadmin/main"
        uccx_headers = {
            'Host': hostname + ":" + api_port
        }

        
        pSession.headers = uccx_headers
        uccx_response = customSessionGet(url, 302, auth=(username,password), timeout=60, allow_redirects=False, proxies=sock5Proxy, verify=False)

        # Get CSRF Token
        url = 'https://' + hostname + ":" + api_port + '/appadmin/JavaScriptServlet'
        uccx_headers = {
            'Host': hostname + ":" + api_port,
            'Origin': 'https://' + hostname + ':' + api_port,
            'FETCH-CSRF-TOKEN': '1'
        }
        pSession.headers = uccx_headers
        uccx_response = customSessionPost(url, 200, timeout=60, allow_redirects=False, proxies=sock5Proxy, verify=False)
        CSRFToken = (uccx_response.text.split(':', 1)[1])

        # Perform User Authentication
        url = 'https://' + hostname + ':' + api_port + '/appadmin/j_security_check'
        uccx_headers = {
            'Host': hostname + ":" + api_port,
            'Origin': 'https://' + hostname + ':' + api_port,
            'Referer': 'https://' + hostname + ':' + api_port  + '/appadmin/main',
            'Upgrade-Insecure-Requests': '1'
        }
        uccx_body = {
            'j_username': username,
            'j_password': password,
            'appNav': 'appadmin',
            'CSRFTOKEN': CSRFToken
        }
        pSession.headers = uccx_headers
        uccx_response = customSessionPost(url, 302,data=uccx_body, timeout=60, allow_redirects=False, proxies=sock5Proxy, verify=False)

        # Perform Smart License Registration
        url = 'https://' + hostname + ':' + api_port + '/appadmin/smartlicense/register.do'
        uccx_headers = {
            'Host': hostname + ":" + api_port,
            'Refer': 'https://' + hostname + api_port + '/appadmin/smartlicense/registerdisplay.do?request_type=register',
            'CSRFTOKEN': CSRFToken,
            'Origin': 'https://' + hostname + ':' + api_port,
            'X-Requested-With': 'XMLHttpRequest, XMLHttpRequest',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/json; charset=utf-8'
        }

        uccx_json = {
            'forceFlag': True,
            'IdToken': getSmartLicenseToken(token_description)
        }

        
        pSession.headers = uccx_headers
        uccx_response = customSessionPost(url, 200, json=uccx_json, timeout=60, allow_redirects=False, proxies=sock5Proxy, verify=False)
        result['response'] = uccx_response.text

        # Verify UCCx is licensed
        validate_uccx_licenseStatus(uccx_response)
        pSession.close()



    if (model == 'expressway'):
        # Verify Expressway is responding to API requests
        validate_expw_connectivity()

        # Verify SSMS is responding to API requests
        validate_ssms_connectivity()

        # License Expressway
        url = "https://" + hostname + ":" + api_port + "/api/provisioning/common/smartlicensing/registration"
        expw_LicenseJSON = {}
        expw_LicenseJSON['Reregister'] = 'Yes'
        expw_LicenseJSON['Token'] = getSmartLicenseToken(token_description)
        customHttpPost(url, json=expw_LicenseJSON, auth=(username,password), proxies=sock5Proxy, verify = False)

        # Verify Expressway is licensed
        validate_expw_licenseStatus()
    
    if (model == 'cmm'):
        # Verify Cisco Meeting Manager is responding to API requests
        validate_cmm_connectivity()

        # Verify SSMS is responding to API requests
        validate_ssms_connectivity()
        
        # Get CSRF Token
        url = 'https://' + hostname + ":" + api_port + '/api_login'
        cmm_headers = {
            'Host': hostname + ":" + api_port
        }
        pSession.headers = cmm_headers

        iHttp = 0
        while True:
            try:
                cmm_response = customSessionGet(url, 200, timeout=60, proxies=sock5Proxy, verify=False)
                CSRFToken = (json.loads(cmm_response.text))['token']
                break
            except Exception as err:
                if (iHttp > 100):
                    # Failed to connect for 60 minutes
                    result['changed'] = False
                    result['failed'] = True
                    if 'response' in locals():
                        result['response'] = str(cmm_response.text)
                    
                    module.fail_json(msg=str(err),**result)
                else:
                    # Unable to connect, pausing for 1 minutes
                    time.sleep(60)
                    iHttp = iHttp + 1
                    continue

        # Perform User Authentication
        url = 'https://' + hostname + ":" + api_port + '/api_login/'
        cmm_headers = {
            'Host': hostname + ":" + api_port,
            'X-CSRFToken': CSRFToken,
            'X-Requested-With': 'XMLHttpRequest'
        }

        cmm_body = {
            'username': username,
            'password': password,
            'source': 'local'
        }
        pSession.headers = cmm_headers

        iHttp = 0
        while True:
            try:
                cmm_response = customSessionPost(url, 200, data=cmm_body, proxies=sock5Proxy, timeout=60, verify=False)
                CSRFToken = json.loads(cmm_response.text)['token']
                break
            except Exception as err:
                if (iHttp > 100):
                    # Failed to connect for 60 minutes
                    result['changed'] = False
                    result['failed'] = True
                    if 'response' in locals():
                        result['response'] = str(cmm_response.text)
                    
                    module.fail_json(msg=str(err),**result)
                else:
                    # Unable to connect, pausing for 1 minutes
                    time.sleep(60)
                    iHttp = iHttp + 1
                    continue



        # Perform Smart License Registration
        url = 'https://' + hostname + ":" + api_port + '/licensing/api/smart/register/'
        cmm_headers = {
            'Host': hostname + ":" + api_port,
            'Origin': 'https://' + hostname + ":" + api_port,
            'X-CSRFToken': CSRFToken,
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        cmm_LicenseJSON = {}
        cmm_LicenseJSON['token'] = getSmartLicenseToken(token_description)
        cmm_LicenseJSON['force'] = True
        pSession.headers = cmm_headers
        cmm_response = customSessionPost(url, 200, timeout=400, json=cmm_LicenseJSON, proxies=sock5Proxy, verify = False)

 




        
        # Verify CMM is licensed (need to reenable)
        validate_cmm_licenseStatus(pSession)

        # Configure License Quantity
        url = 'https://' + hostname + ":" + api_port + '/licensing/api/smart/set_license_limits/'
        cmm_headers = {
            'Host': hostname + ":" + api_port,
            'Origin': 'https://' + hostname + ":" + api_port,
            'X-CSRFToken': CSRFToken,
            'X-Requested-With': 'XMLHttpRequest'
        }

        cmm_LicenseQuantityJSON = {}
        cmm_LicenseQuantityJSON['shared'] = cmm_smp
        cmm_LicenseQuantityJSON['personal'] = cmm_pmp
        cmm_LicenseQuantityJSON['viewer'] = cmm_rec

        cmm_LicenseLimitsJSON = {}
        cmm_LicenseLimitsJSON['limits'] = cmm_LicenseQuantityJSON
        pSession.headers = cmm_headers


        cmm_response = customSessionPost(url, 200, timeout=400, json=cmm_LicenseLimitsJSON, proxies=sock5Proxy, verify = False)

        if (json.loads(cmm_response.text)['success']):
            result['changed'] = True
            result['failed'] = False
            result['response'] = cmm_response.text
            module.exit_json(**result)
        else:
            result['changed'] = False
            result['failed'] = True
            result['response'] = cmm_response.text
            module.fail_json(msg=str(cmm_response.text),**result)

        # Verify CMM is licensed (need to delete)
        #validate_cmm_licenseStatus(pSession)
        

    if (model == 'cer'):
        validate_cer_connectivity()
        validate_ssms_connectivity()

        # Perform User Authentication
        url = 'https://' + hostname + ":" + api_port + '/ceradmin/servlet/CERAdminServlet'
        cer_headers = {
            'Host': hostname + ":" + api_port,
            'Upgrade-Insecure-Requests': '1'
        }

        cer_body = {
            'formname': 'login',
            'actionname': 'Login',
            'name': username,
            'passwd': password
        }
        pSession.headers = cer_headers

        iHttp = 0
        while True:
            try:
                cer_response = customSessionPost(url, 200, data=cer_body, proxies=sock5Proxy, timeout=60, verify=False)
                break
            except Exception as err:
                if (iHttp > 100):
                    # Failed to connect for 60 minutes
                    result['changed'] = False
                    result['failed'] = True
                    if 'response' in locals():
                        result['response'] = str(cer_response.text)
                    
                    module.fail_json(msg=str(err),**result)
                else:
                    # Unable to connect, pausing for 1 minutes
                    time.sleep(60)
                    iHttp = iHttp + 1
                    continue


        # Perform Smart License Registration
        url = 'https://' + hostname + ":" + api_port + '/ceradmin/servlet/CERAdminServlet'
        cer_headers = {
            'Host': hostname + ":" + api_port,
            'Upgrade-Insecure-Requests' : '1',
            'Origin': hostname + ":" + api_port,
            'Referer': 'https://' + hostname + ':' + api_port + '/ceradmin/servlet/CERAdminServlet'

        }

        cer_body = {
            'formname': 'licRegistration',
            'hiddenaction': 'registerLic',
            'regToken': getSmartLicenseToken(token_description),
            'forceRegister': 'forceRegisterEnabled'
        }

        pSession.headers = cer_headers
        cer_response = customSessionPost(url, 200, headers=cer_headers, data=cer_body, proxies=sock5Proxy, verify = False)

        # CER has no validation mechanism, assume success.
        result['changed'] = True
        result['failed'] = False
        result['response'] = cer_response.text
        module.exit_json(**result)
        
def main():
    run_module()


if __name__ == '__main__':
    main()