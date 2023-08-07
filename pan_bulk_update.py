"""
Author: Phatkone
Description: Bulk update tool for Palo Alto NAT and security policies. Can be used with Panorama or the firewalls directly.
Dependencies: pan-python - Packaged
Usage: `python3 pan_bulk_update.py` or `python3 pan_bulk_update.py <host ip or fqdn>`
 All inputs required are in prompt format within the script.

GNU GPL License applies.

           ,,,
          (. .)
-------ooO-(_)-Ooo-------

"""
from pan.xapi import PanXapi
from pan.xapi import PanXapiError
from getpass import getpass
from time import sleep
from re import match
import binascii
import base64
import os
import sys
import lib.pan_security as pan_security
import lib.pan_nat as pan_nat
import lib.pan_int_mgmt as pan_int_mgmt
from lib.common import file_exists, verify_selection



def main(pan_host: str = None) -> None:
    if pan_host is None:
        pan_host = input("Enter the address of the firewall:\n ")
    save_key = False
    key_file = ".{}".format(pan_host.replace('.','-'))
    fw_key = None
    fw_uid = None
    fw_pwd = None
    panorama = False
    
    data = {
        'hostname':pan_host
    }

    if file_exists(key_file):
        f = open(key_file, 'r')
        try:
            fw_key = base64.standard_b64decode(f.readline()).decode()
        except binascii.Error:
            main(pan_host)
        f.close()
        del f
        data['api_key'] = fw_key
    else:
        fw_uid = input("Enter the API username:\n ")
        fw_pwd = getpass("Enter the API password:\n ")
        sk = input("Save API key for later use? (Y/N):\n ")
        if sk[0].lower() == 'y':
            save_key = True
            del sk
        data['api_username'] = fw_uid
        data['api_password'] = fw_pwd
    
    panx = PanXapi(**data)
    print("Connecting to device...")
    # Save the key if desired.
    if fw_key is None and save_key:
        try:
            key = base64.standard_b64encode(panx.keygen().encode()).decode()
            f = open(key_file, 'w')
            print("Saving API key...")
            f.write(key)
            f.close
        except PanXapiError as e:
            print("API Error: {}".format(e))
            exit()

    #Check system reachable and retrieve system information
    try:
        panx.op(cmd='show system info', cmd_xml=True)
        xm = panx.element_root.find('result').find('system')
        sysinfo = {}
        for e in xm:
            sysinfo[e.tag] = e.text
        del e,xm
        hostname = sysinfo['hostname']
        model = sysinfo['model']
        version = sysinfo['sw-version']
        print("\n" + "".center(80,'*'))
        print("Successfully connected to: {} ({})".format(hostname, pan_host).center(80) + "\n" + "Model: {}".format(model).center(80) +"\n" + "Version: {}".format(version).center(80))
        print("".center(80,'*')+"\n")
        sleep(1)
        # Uncomment to dump device info into text file
        #import json
        #f = open("{}-info.txt".format(fw_host.replace('.','-')),'w')
        #f.write(json.dumps(sysinfo,indent=2))
        #f.close()
    except PanXapiError as e:
        print("API Error: {}".format(e))
        if 'getaddrinfo failed' in e:
            exit()
        if '403' in str(e) and fw_key is not None:
            # Delete the saved key if an unauthorised result is returned (case of password/key roll over)
            os.remove(key_file)
            print("Deleting saved key, please try again.")
        main(pan_host)
        exit()

    if model == "Panorama":
        panorama = True
    
    rule_type = verify_selection({
        1: 'Security',
        2: 'NAT',
        3: 'Interface Management Profile'
    }, "Which type of policy do you wish to update?\n", False, True)
    file_mapping = {
        'Security': 'pan_security',
        'NAT': 'pan_nat',
        'Interface Management Profile': 'pan_int_mgmt'
    }
    globals()[file_mapping[rule_type]].main(panx, panorama) 
    #pan_security.main(panx, panorama)

if __name__ == '__main__':
    # Set firewall / panorama address
    pan_host = sys.argv[1:2][0] if len(sys.argv) > 1 else input("What is the firewall or Panorama address?:\n")
    
    if pan_host is not None:
        if not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$',pan_host) and not match (r'^([a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+$',pan_host):
            print("Invalid host entered...{}".format(pan_host)) 
            pan_host = None
        try:
            main(pan_host)
        except KeyboardInterrupt:
            print("Cancelled by keyboard interrupt")
            exit()
