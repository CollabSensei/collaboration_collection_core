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
    - "This module is used with the WWT Platform"

options:
    deployment_id:
        description:
            - Platform deployment id
        required: true
    deployment_uuid:
        description:
            - Platform deployment uuid
        required: true
    message:
        description:
            - Text Message to send to user
        required: false
    external_status:
        description:
            - Status for access links. If this is set to active the links are exposed to the user. All other statuses, result in access being blocked.
        required: false

author:
    - Dennis Heim (dennis.heim@wwt.com)
'''

EXAMPLES = '''
# Send a status message to the platform
- name: Update Edge Configuration
  wwt_platform:
    deployment_id: {{ deployment_id }}  <--- Passed in from platform as extra_vars
    deployment_uuid: {{ deployment_uuid }} <--- Passed in from platfrom as extra_vars
    message: "Automation Status Update"

# Enable Platform access links
- name: Update Edge Configuration
  wwt_platform:
    deployment_id: {{ deployment_id }}  <--- Passed in from platform as extra_vars
    deployment_uuid: {{ deployment_uuid }} <--- Passed in from platfrom as extra_vars
    external_status: 'active'

# Send a status message and enable platform access links
- name: Update Edge Configuration
  wwt_platform:
    deployment_id: {{ deployment_id }}  <--- Passed in from platform as extra_vars
    deployment_uuid: {{ deployment_uuid }} <--- Passed in from platfrom as extra_vars
    message: "Automation Status Update"
    external_status: 'active'

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

def run_module():

    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        deployment_id=dict(type='str', required=True),
        deployment_uuid=dict(type='str', required=True),
        message=dict(type='str', default='', required=False),
        external_status=dict(type=str, default='', required=False)
    )
 
    # seed the result dict in the object
    # we primarily care about changed and the response data
    # change is if this module effectively modified the target
    # response is the data returned by TrafficJam
    # status_code is the HTTP status code returned by the requests module

    result = dict(
        changed=False,
        response='',
        status_code=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    # Collect Module Parameters
    deployment_id = module.params['deployment_id']
    deployment_uuid = module.params['deployment_uuid']
    message = module.params['message']
    external_status = module.params['external_status']

    # Send Request to WWT Platform
    url = 'https://deployment-proxy.apps.wwtatc.com/deployments/' + deployment_id + '?uuid=' + deployment_uuid
    jsonPayload = {}

    if(len(message) != 0):
        jsonPayload['userMessage'] = message

    if(len(external_status) != 0):
        jsonPayload['externalStatus'] = external_status

    requests.patch(url,json=jsonPayload, verify=False)

    # Ansible Status
    result['changed'] = True
    result['failed'] = False
    module.exit_json(**result)

 


def main():
    run_module()


if __name__ == '__main__':
    main()
