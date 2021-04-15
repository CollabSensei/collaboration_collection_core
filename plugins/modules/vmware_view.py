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
module: VMware View

short_description: This module is used with Horizon View

version_added: "2.9"

description:
    - "This module is used with Horizon View"

options:
    vapp_ip:
        description:
            - ATC IP Address off the vApp.
        required: true
    restconf_port:
        description:
            - Port that forwards to the Unified Access Gateway API. Default is 9443.
        required: false
    restconf_username:
        description:
            - Username to access restconf API. Default is admin
        required: false
    restconf_password:
        description:
            - Password to access restconf API. Default is WWTwwt1!
        required: false
    version:
        description:
            - Version of Device
        required: true
    ip_address:
        description:
            - IP Address of the VM we are updating. This is only required if (use_proxy) is set to true
        required: false
    use_proxy:
        description:
            - Use Direct Connection (False) or use a Socks5 Proxy (True)

author:
    - Dennis Heim (dennis.heim@wwt.com)
'''

EXAMPLES = '''
# Reconfigure VMware View Edge Settings
- name: Update Edge Configuration
  vmware_view:
    vapp_ip: 10.246.32.161
    restconf_port: 9443
    restconf_username: "admin"
    restconf_password: "WWTwwt1!"
    version: 3.8
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
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')


def validate_uag_connectivity():
    i = 0
    url = 'https://' + (ip_address if use_proxy else vapp_ip) + ':' + restconf_port + '/rest/swagger.yaml'
    while True:
        try:
            response = (requests.get(url, auth=(restconf_username, restconf_password), timeout = 15, proxies=sock5Proxy, verify = False))
            if (response.status_code == 200):
                break
        except Exception as err:
            if (i > 60):
                # Failed to connect for 60 minutes
                result['changed'] = False
                result['failed'] = True
                if 'response' in locals():
                    result['response'] = str(response.text)
                
                module.fail_json(msg=str(err),**result)
            else:
                # Unable to connect, pausing for 1 minutes
                time.sleep(45)
                i = i + 1
                continue

def run_module():

    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        vapp_ip=dict(type='str', required=True),
        restconf_port=dict(type='str', default='9443', required=False),
        restconf_username=dict(type='str', default='admin', required=False),
        restconf_password=dict(type='str', default='WWTwwt1!', required=False, no_log=True),
        use_proxy=dict(type='bool', default=False, required=False),
        ip_address=dict(type='str', required=False),
        version=dict(type='float', required=True)
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

    # Collect Module Parameters
    global vapp_ip
    vapp_ip = module.params['vapp_ip']
    global ip_address
    ip_address = module.params['ip_address']
    global restconf_port
    restconf_port = module.params['restconf_port']
    global restconf_username
    restconf_username = module.params['restconf_username']
    global restconf_password
    restconf_password = module.params['restconf_password']
    global use_proxy
    use_proxy = module.params['use_proxy']
    global version
    version = module.params['version']

    global sock5Proxy

    if (use_proxy):
        sock5Proxy = {
            'http': 'socks5h://' + vapp_ip + ':1080',
            'https':'socks5h://' + vapp_ip + ':1080'
        }
    else:
        sock5Proxy = ''

    # Verify Unified Access Gateway is responding to API requests
    url = 'https://' + (ip_address if use_proxy else vapp_ip) + ':' + restconf_port + '/rest/swagger.yaml'
    validate_uag_connectivity()

    # Get Existing Edge Configuration
    url = 'https://' + (ip_address if use_proxy else vapp_ip) + ':' + restconf_port + '/rest/v1/config/edgeservice'
    getEdgeConfigurationResponse = requests.get(url,auth=(restconf_username,restconf_password), proxies=sock5Proxy, verify = False)
    getEdgeJSON = json.loads(getEdgeConfigurationResponse.text)
    getEdgeJSON = getEdgeJSON['edgeServiceSettingsList'][0]

    # Modify JSON Object to reflect requested changes
    getEdgeJSON['pcoipExternalUrl'] = vapp_ip + ":4172"
    getEdgeJSON['blastExternalUrl'] = 'https://' + vapp_ip + ':443'
    getEdgeJSON['tunnelExternalUrl'] = 'https://' + vapp_ip + ':443'
    getEdgeJSON['proxyPattern'] = "/|/(.*)"

    # Update Unified Access Gateway Edge Configuration
    url = 'https://' + (ip_address if use_proxy else vapp_ip) + ':' + restconf_port + '/rest/v1/config/edgeservice/view'
    updateEdgeResponse = requests.put(url, json=getEdgeJSON, auth=(restconf_username, restconf_password), proxies=sock5Proxy, verify = False)
    result['response'] = updateEdgeResponse.text
   
    # Verify Update Succeeded
    i = 0
    while (updateEdgeResponse.status_code != 200):
        updateEdgeResponse = requests.put(url, json=getEdgeJSON, auth=(restconf_username, restconf_password), timeout=30, proxies=sock5Proxy, verify = False)

        if i > 5:
            # License status failed
            result['changed'] = False
            result['failed'] = True
            result['response'] = updateEdgeResponse.text
            module.fail_json(msg='Update UAG Failed', **result)
            break

        time.sleep(10)
        i = i + 1

    if (updateEdgeResponse.status_code == 200):
        # UAG Update Successful. Pass this back to ansible
        result['changed'] = True
        result['failed'] = False
        result['response'] = updateEdgeResponse.text
        module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()