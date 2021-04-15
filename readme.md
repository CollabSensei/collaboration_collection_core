# Summary #3
This repo contains the core automation used for On-Demand Collaboration labs.

The following modules exist for usage:
* cisco-smart-license: Provides smart licensing registration automation for numberous device types. This module is written by WWT.
* vmware-vcd: Provides automation for performing vCloud functions. These modules are written by VMware.
* vmware-view: Provides VMware View configuration automation. This module is written by WWT.

# Example 1: On-Demand Lab with Status Callback to the ATC platform.
This example performs the follows functions
* Create instance of Smart Licensing VM from Catalog template
* License Cisco UC Components with Smart Licensing
* Update VMware View Access Gateway with proper IP Address
* Set lab status to "active" so access links are active/functional.

## Platform Variables
The following variables are passed in from the platform through the webhook
* deployment_id (Automatic)
* deployment_uuid (Automatic)
* vapp_name (Automatic)
* vcd_catalog (User Defined)
* vcd_org (User Defined)
* vcd_vdc (User Defined)

## Ansible Tower Variables
* env_user: vCloud user credential
* env_password: vCloud user credential
* env_host: vCloud FQDN (vcloud-vars.yml)
## Platform Webhook Configuration
|Type|Method|URL|
|----|------|---|
|On Create|Post|https://atc-tower.wwtatc.com/api/v2/job_templates/{JobID}/launch/|

Body:
```json
{
  "extra_vars": {
    "deployment_id": "$deployment_id",
    "deployment_uuid": "$deployment_uuid",
    "vapp_name": "$vapp_vcloud_name",
    "vcd_catalog": "web-vApps",
    "vcd_org": "vCD-Prod",
    "vcd_vdc": "vCD-Prod-vApps"
  }
}
```

## Ansible Playbook
```yaml
---
- name: vApp Automation
  hosts: localhost
  gather_facts: false

  tasks:
          - include_vars: vCloud-vars.yml
          - name: Import Cisco Smart License VM
            vcd_vapp_vm:
              user:  "{{ env_user }}"
              password: "{{ env_password }}"
              org: "{{ vcd_org }}"
              host: "{{ env_host }}"
              target_vdc: "{{ vcd_vdc }}"
              source_catalog_name: "{{ vcd_catalog }}"
              source_template_name: "ps-collab-ssms01-012821"
              source_vm_name: "Collab-SSMS01"
              target_vapp: "{{ vapp_name }}"
              target_vm_name: "Collab-SSMS01"
              state: "present"


          - name: 'License CSR1000v'
            cisco_smart_license:
              vapp_ip: "{{ vapp_ip }}"
              ssms_ip: "192.168.10.7"
              ssms_port: 8443
              api_port: 1026
              ip_address: "192.168.10.1"
              username: "wwt"
              password: "WWTwwt1!"
              token_description: "CSR1K-1"
              model: "csr1k"
              version: 17.3
              use_proxy: True
          
          - name: 'License CUCM # 1'
            cisco_smart_license:
              vapp_ip: "{{ vapp_ip }}"
              ssms_ip: "192.168.10.7"
              ssms_port: 8443
              api_port: 8443
              ip_address: "192.168.10.21"
              username: "administrator"
              password: "WWTwwt1!"
              token_description: "CUCM #1"
              model: "cucm"
              version: 12.5
              use_proxy: True

          - name: 'License CUCM # 2'
            cisco_smart_license:
              vapp_ip: "{{ vapp_ip }}"
              ssms_ip: "192.168.10.7"
              ssms_port: 8443
              api_port: 8443
              ip_address: "192.168.11.21"
              username: "administrator"
              password: "WWTwwt1!"
              token_description: "CUCM #2"
              model: "cucm"
              version: 12.5
              use_proxy: True

          - name: 'License CUC # 1'
            cisco_smart_license:
              vapp_ip: "{{ vapp_ip }}"
              ssms_ip: "192.168.10.7"
              ssms_port: 8443
              api_port: 443
              ip_address: "192.168.10.31"
              username: "administrator"
              password: "WWTwwt1!"
              token_description: "CUC #1"
              model: "cuc"
              version: 12.5
              use_proxy: True

          - name: 'License UCCx #1'
            cisco_smart_license:
              vapp_ip: "{{ vapp_ip }}"
              ssms_ip: "192.168.10.7"
              ssms_port: 8443
              api_port: 443
              ip_address: "192.168.10.35"
              username: "administrator"
              password: "WWTwwt1!"
              token_description: "UCCx #1"
              model: "uccx"
              version: 12.5
              use_proxy: True

          - name: 'License CMM #1'
            cisco_smart_license:
              vapp_ip: "{{ vapp_ip }}"
              ssms_ip: "192.168.10.7"
              ssms_port: 8443
              api_port: 443
              ip_address: "192.168.10.41"
              username: "admin"
              password: "WWTwwt1!"
              token_description: "CMM #1"
              model: "cmm"
              version: 12.5
              use_proxy: True

          - name: 'License Expressway'
            cisco_smart_license:
              vapp_ip: "{{ vapp_ip }}"
              ssms_ip: "192.168.10.7"
              ssms_port: 8443
              api_port: 443
              ip_address: "192.168.10.80"
              username: "admin"
              password: "WWTwwt1!"
              token_description: "License Expressway 1"
              model: "expressway"
              version: 12.7
              use_proxy: True

          - name: 'License ASA'
            cisco_smart_license:
              vapp_ip: "{{ vapp_ip }}"
              ssms_ip: "192.168.10.7"
              ssms_port: 8443
              api_port: 443
              ip_address: "192.168.10.60"
              username: "wwt"
              password: "WWTwwt1!"
              token_description: "License ASA"
              model: "asav"
              version: 12.7
              use_proxy: True


          - name: 'License CER'
            cisco_smart_license:
              vapp_ip: "{{ vapp_ip }}"
              ssms_ip: "192.168.10.7"
              ssms_port: 8443
              api_port: 443
              ip_address: "192.168.10.50"
              username: "administrator"
              password: "WWTwwt1!"
              token_description: "License ASA"
              model: "cer"
              version: 12.5
              use_proxy: True

          - name: Update UAG Configuration
            vmware_view:
              vapp_ip: "{{ vapp_ip }}"
              restconf_port: "9443"
              restconf_username: "admin"
              restconf_password: "WWTwwt1!"
              version: 3.8

          - name: Activate Access Links
            wwt_platform:
              deployment_id: "{{ deployment_id }}"
              deployment_uuid: "{{ deployment_uuid }}"
              external_status: 'active'
```
