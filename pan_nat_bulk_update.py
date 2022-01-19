"""
Author: Craig Beamish
Date Written: 2020/12/10
Last Modified By: Craig Beamish
Date Last Modified: 2020/12/10
Date Last Tested: Placeholder - still to be formed
Result: 
Description: Bulk update tool for Palo Alto NAT policies. Can be used with Panorama or the firewalls directly.
Dependencies: pan-python
Usage: python3 pan_nat_bulk_update.py
 All inputs required are in prompt format within the script.
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

import json

def file_exists(file: str) -> bool:
    try:
        f = open(file,'r')
        f.close()
        del f
        return True
    except:
        return False


def get_selection(d: dict, s: str, r: bool = False) -> str:
    print()
    print()
    for k, v in d.items():
        print("[{}] {}".format(k,v))
    print(s)
    if r:
        print("Enter a single value, or multiple values separated by a space.")
        print("Ranges can be entered with a hyphen (I.E. 2-5) or type all for all values.")
    else:
        print("Enter a single value.")
    return input("> ")


def verify_selection(d: dict, s: str, is_range: bool = False):
    valid_option = False
    if len(d) < 1:
        print("{}\n Oops. No options found.".format(s))
        exit(-1)
    if is_range:
        ret = {}
    else:
        ret = ""
    while not valid_option:
        response = get_selection(d, s, is_range).strip()
        if not is_range:
            try:
                ret = int(response)
            except ValueError:
                print("Invalid Selection.")
                continue
            if ret not in range(1,len(d)+1):
                print("Invalid Selection.")
                continue
        else:
            if response.lower() == 'all':
                return d
            sub_valid = True
            count = 1
            for r in response.split(' '):
                try:
                    if '-' in r:
                        split = r.split('-')
                        r1 = int(split[0])
                        r2 = int(split[1])
                        if r1 not in range(1,len(d)+1) or r2 not in range(1,len(d)+1):
                            print("Invalid Selection.")
                            sub_valid = False
                            continue
                        for i in range(r1, r2+1):
                            ret[count] = d[i]
                            count += 1
                        continue
                    r = int(r)
                except ValueError:
                    print("Invalid Selection.")
                    sub_valid = False
                    continue
                if r not in range(1,len(d)+1):
                    print("Invalid Selection.")
                    sub_valid = False
                    continue
                ret[count] = d[r]
                count += 1
            if not sub_valid:
                continue
        valid_option = True
    del valid_option, d, s, is_range
    return ret


def job_status(xapi: PanXapi, job: str) -> tuple:
	xapi.op(cmd='<show><jobs><id>{}</id></jobs></show>'.format(job))
	results = {}
	devices = xapi.element_root[0][0].find('devices')
	for device in devices:
		results[device.find('devicename').text] = device.find('result').text
	return xapi.status, results


def get_device_group_stack(xapi: PanXapi, dg_stack: dict = {}) -> dict:
    xpath = '/config/readonly/devices/entry[@name=\'localhost.localdomain\']/device-group'
    xapi.get(xpath=xpath)
    xm_root = xapi.element_root.find('result')
    if int(xm_root.get('count')) < 1:
        return dg_stack
    dgs = xm_root.find('device-group')
    for dg in dgs:
        parent_dg = dg.find('parent-dg')
        if parent_dg is not None:
            dg_stack[dg.get('name')] = parent_dg.text
    return dg_stack


def get_parent_dgs(xapi: PanXapi, dg: str, dg_stack: dict, response_list: list = []) -> list:
    if dg not in response_list:
        response_list.append(dg)
    if dg in dg_stack.keys():
        if dg_stack[dg] not in response_list:
            response_list.append(dg_stack[dg])
        if dg_stack[dg] in dg_stack.keys():
            response_list = get_parent_dgs(xapi, dg_stack[dg], dg_stack, response_list)
    return response_list


def enable_disable_rules(panx: PanXapi, rules: dict, panorama: bool, action : str, devicegroup: str = "") -> None:
    if panorama:
        for rulebase, rulelist in rules.items():
            for rule in rulelist:
                print("{} rule: '{}' in rulebase: {}".format('Enabling' if action == 'enable' else 'Disabling', rule, rulebase))
                panx.set(xpath='/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/{}/nat/rules/entry[@name=\'{}\']'.format(devicegroup, rulebase,rule), element='<disabled>{}</disabled>'.format('no' if action == 'enable' else 'yes'))
                print(panx.status.capitalize())
    else:
        for rule in rules['devicelocal']:
            print("{} rule: '{}'".format('Enabling' if action == 'enable' else 'Disabling', rule))
            panx.set(xpath='/config/devices/entry/vsys/entry/rulebase/nat/rules/entry[@name=\'{}\']'.format(rule), element='<disabled>{}</disabled>'.format('no' if action == 'enable' else 'yes'))
            print(panx.status.capitalize())


def add_remove_rule_zones(panx : PanXapi, rules: dict, panorama : bool, action : str, source_dest: str, rule_data : dict, devicegroup: str = "") -> None:
    zones = {}
    # Get template if Panorama
    if panorama: 
        panx.get('/config/devices/entry/template')
        templates = {}
        templates_xml = panx.element_root.find('result')
        count = 1
        for template in templates_xml[0]:
            templates[count] = template.get("name")
            count += 1
        template = templates[verify_selection(templates, "Which Template does the zone belong to?:", False)]
        del templates_xml, count, templates      
        xpath = '/config/devices/entry/template/entry[@name=\'{}\']/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/zone'.format(template)
    else:
        xpath = '/config/devices/entry/vsys/entry/zone'

    #Get Zones list for selection
    panx.get(xpath)
    xm = panx.element_root.find('result')
    count = 1
    for zone in xm[0]:
        zones[count] = zone.get('name')
        count+=1
    del count
    zone_selection = verify_selection(zones, "Which Zone(s) do you wish to {}?:".format(action), True)

    new_zone_list = {}
    # Get current zones belonging to the selected rules. these have to be pushed in with the new zone (or without the zones for removal)
    # Will remove duplicates of any zones in a rule
    for rules_list in rules.values():
        for rule in rules_list:
            new_zone_list[rule] = []
            for zone in rule_data[rule][source_dest]:
                if action == 'add' and zone == 'any':
                    pass
                elif action == 'add' and zone not in new_zone_list[rule]:
                    new_zone_list[rule].append(zone)
                elif action == 'remove' and zone not in zone_selection.values():
                    new_zone_list[rule].append(zone)
            for zone in zone_selection.values():
                if action == 'add' and zone not in new_zone_list[rule]:
                    new_zone_list[rule].append(zone)
                # If removing last zone, must put member any in
                if len(new_zone_list[rule]) < 1:
                    new_zone_list[rule].append('any')

    # Create XML object to push with API call
    zone_xml = {} 
    for rule, zone_list in new_zone_list.items():
        zone_xml[rule] = "<{}>".format(source_dest)
        for zone in zone_list:
            zone_xml[rule] += '<member>{}</member>'.format(zone)
        zone_xml[rule] += "</{}>".format(source_dest)

    if panorama:
        for rulebase, rulelist in rules.items():
            for rule in rulelist:
                xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/{}/nat/rules/entry[@name=\'{}\']/{}'.format(devicegroup, rulebase, rule, source_dest)
                print("{} zone(s): {} {} rule: '{}' in rulebase: {}".format('Adding' if action == 'add' else 'Removing', " ".join(zone_selection.values()), 'to' if action == 'add' else 'from', rule, rulebase))
                panx.edit(xpath=xpath,element=zone_xml[rule])
                print(panx.status.capitalize())
    else:
        for rule in rules['devicelocal']:
            xpath = '/config/devices/entry/vsys/entry/rulebase/nat/rules/entry[@name=\'{}\']/{}'.format(rule, source_dest)
            print("{} zone(s): {} {} rule: '{}'".format('Adding' if action == 'add' else 'Removing', " ".join(zone_selection.values()), 'to' if action == 'add' else 'from', rule))
            panx.edit(xpath=xpath,element=zone_xml[rule])
            print(panx.status.capitalize())


def add_remove_rule_address(panx : PanXapi, rules: dict, panorama : bool, action : str, source_dest: str, rule_data : dict, devicegroup: str = "") -> None:
    if action == 'add':
        address = input("What address would you like to add?: (Use CIDR Notation I.E. 10.0.0.0/8)\n")
        if not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/([0-9]|[1-2][0-9]|3[0-2])$', address) and not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$', address):
            print('Invalid IP Address')
            exit()
        if '/' not in address:
            address += '/32'
            print("No CIDR Notation found, treating as /32")
    else:
        address = input("Which address would you like to remove?: (Ensure it matches exactly)\n")

    new_address_list = {}
    # Get current zones belonging to the selected rules. these have to be pushed in with the new zone (or without the zones for removal)
    for rules_list in rules.values():
        for rule in rules_list:
            new_address_list[rule] = []
            for addr in rule_data[rule][source_dest]:
                if action == 'add' and addr == 'any':
                    pass
                elif action == 'add':
                    new_address_list[rule].append(addr)
                elif action == 'remove' and not addr == address:
                    new_address_list[rule].append(addr)
            if action == 'add':
                new_address_list[rule].append(address)

    # If removing last address, must put member 'any' in
    for rule in new_address_list.keys():
        print(rule, len(new_address_list[rule]))
        if len(new_address_list[rule]) < 1:
            new_address_list[rule].append('any')


    # Create XML object to push with API call
    addr_xml = {} 
    for rule, address_list in new_address_list.items():
        addr_xml[rule] = "<{}>".format(source_dest)
        for addr in address_list:
            addr_xml[rule] += '<member>{}</member>'.format(addr)
        addr_xml[rule] += "</{}>".format(source_dest)

    if panorama:
        for rulebase, rulelist in rules.items():
            for rule in rulelist:
                xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/{}/nat/rules/entry[@name=\'{}\']/{}'.format(devicegroup, rulebase, rule, source_dest)
                print("{} address: {} {} rule: '{}' in rulebase: {}".format('Adding' if action == 'add' else "Removing", address, 'to' if action == 'add' else "from", rule, rulebase))
                panx.edit(xpath=xpath,element=addr_xml[rule])
                print(panx.status.capitalize())
    else:
        for rule in rules['devicelocal']:
            xpath = '/config/devices/entry/vsys/entry/rulebase/nat/rules/entry[@name=\'{}\']/{}'.format(rule, source_dest)
            print("{} address: {} {} rule: '{}'".format('Adding' if action == 'add' else "Removing", address, 'to' if action == 'add' else "from", rule))
            panx.edit(xpath=xpath,element=addr_xml[rule])
            print(panx.status.capitalize())


def add_remove_rule_tags(panx : PanXapi, rules : dict, panorama : bool, action : str, rule_data : dict, devicegroup : str = "") -> None:
    tags = {}
    # Set xpath
    dg_stack = get_device_group_stack(panx) if panorama else {}
    dg_list = get_parent_dgs(panx, devicegroup, dg_stack)
    
    if len(dg_list) > 0 and devicegroup != "":
        for dg in dg_list:
            xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/tag'.format(dg)
            panx.get(xpath)
            xm = panx.element_root.find('result')
            count = 1
            for tag in xm[0]:
                tags[count] = tag.get('name')
                count+=1
    
    if devicegroup not in dg_list or not panorama:
        xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/tag'.format(devicegroup) if panorama else '/config/devices/entry/vsys/entry/tag'
        #Get tag list for selection
        panx.get(xpath)
        xm = panx.element_root.find('result')
        count = 1
        for tag in xm[0]:
            tags[count] = tag.get('name')
            count+=1
            
    if panorama: #get tags from 'Shared'
        xpath = '/config/shared/tag'
        panx.get(xpath)
        xm = panx.element_root.find('result')
        count = 1
        if len(xm) > 0:
            for tag in xm[0]:
                tags[count] = tag.get('name')
                count+=1
    del count


    tag_selection = verify_selection(tags, "Which Tag(s) do you wish to {}?:".format(action), True)

    new_tag_list = {}
    # Get current tags belonging to the selected rules. these have to be pushed in with the new tags (or without the tags for removal)
    for rules_list in rules.values():
        for rule in rules_list:
            new_tag_list[rule] = []
            for tag in rule_data[rule]['tag']:
                if action == 'add' or (action == 'remove' and tag not in tag_selection.values() and tag.replace('>','&gt;').replace('<','&lt;') not in tag_selection.values()):
                    new_tag_list[rule].append(tag.replace('>','&gt;').replace('<','&lt;'))
            for tag in tag_selection.values():
                if action == 'add' and tag.replace('>','&gt;').replace('<','&lt;') not in new_tag_list[rule]:
                    new_tag_list[rule].append(tag.replace('>','&gt;').replace('<','&lt;'))

    # Create XML object to push with API call
    tag_xml = {} 
    for rule, tag_list in new_tag_list.items():
        tag_xml[rule] = "<tag>"
        for tag in tag_list:
            tag_xml[rule] += '<member>{}</member>'.format(tag)
        tag_xml[rule] += "</tag>"

    if panorama:
        for rulebase, rulelist in rules.items():
            for rule in rulelist:
                xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/{}/nat/rules/entry[@name=\'{}\']/tag'.format(devicegroup, rulebase, rule)
                print("{} tag(s): {} {}  rule: '{}' in rulebase: {}".format('Adding' if action == 'add' else 'Removing', " ".join(tag_selection.values()), 'to' if action == 'add' else 'from', rule, rulebase))
                panx.edit(xpath=xpath,element=tag_xml[rule])
                print(panx.status.capitalize())
    else:
        for rule in rules['devicelocal']:
            xpath = '/config/devices/entry/vsys/entry/rulebase/nat/rules/entry[@name=\'{}\']/tag'.format(rule)
            print("{} tag(s): {} {}  rule: '{}'".format('Adding' if action == 'add' else 'Removing', " ".join(tag_selection.values()), 'to' if action == 'add' else 'from', rule))
            panx.edit(xpath=xpath,element=tag_xml[rule])
            print(panx.status.capitalize())


def add_remove_rule_group_by_tags(panx : PanXapi, rules : dict, panorama : bool, action : str, rule_data : dict, devicegroup : str = "") -> None:
    tags = {}
    dg_stack = get_device_group_stack(panx) if panorama else {}
    dg_list = get_parent_dgs(panx, devicegroup, dg_stack)
    
    ### need to do this cleanly....
    if len(dg_list) > 0 and devicegroup != "":
        for dg in dg_list:
            xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/tag'.format(dg)
            panx.get(xpath)
            xm = panx.element_root.find('result')
            count = 1
            if len(xm):
                for tag in xm[0]:
                    tags[count] = tag.get('name')
                    count+=1
    
    if devicegroup not in dg_list or not panorama:
        xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/tag'.format(devicegroup) if panorama else '/config/devices/entry/vsys/entry/tag'
        #Get tag list for selection
        panx.get(xpath)
        xm = panx.element_root.find('result')
        count = 1
        for tag in xm[0]:
            tags[count] = tag.get('name')
            count+=1
            
    if panorama: #get tags from 'Shared'
        xpath = '/config/shared/tag'
        panx.get(xpath)
        xm = panx.element_root.find('result')
        count = 1
        if len(xm) > 0:
            for tag in xm[0]:
                tags[count] = tag.get('name')
                count+=1
    del count
    
    if (action == 'add'):
        tag = tags[verify_selection(tags, "Which Tag(s) do you wish to {}?:".format(action))]
        # Create XML object to push with API call
        tag_xml = "<group-tag>{}</group-tag>".format(tag) 

    if panorama:
        for rulebase, rulelist in rules.items():
            for rule in rulelist:
                xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/{}/nat/rules/entry[@name=\'{}\']/group-tag'.format(devicegroup, rulebase, rule)
                print("{} {}  rule: '{}' in rulebase: {}".format('Adding {}'.format(tag) if action == 'add' else 'Removing tag', 'to' if action == 'add' else 'from', rule, rulebase))
                if action == 'add':
                    panx.edit(xpath=xpath, element=tag_xml)
                else:
                    panx.delete(xpath=xpath)
                print(panx.status.capitalize())
    else:
        for rule in rules['devicelocal']:
            xpath = '/config/devices/entry/vsys/entry/rulebase/nat/rules/entry[@name=\'{}\']/group-tag'.format(rule)
            print("{} {}  rule: '{}'".format('Adding {}'.format(tag) if action == 'add' else 'Removing tag', 'to' if action == 'add' else 'from', rule))
            if action == 'add':
                panx.edit(xpath=xpath, element=tag_xml)
            else:
                panx.delete(xpath=xpath)
            print(panx.status.capitalize())
    

def rename_rules(panx : PanXapi, rules : dict, panorama : bool, rule_data : dict, devicegroup : str = "") -> None:
    action = verify_selection({
        1: 'Append rule names',
        2: 'Prepend rule names',
        3: 'Left trim rule names',
        4: 'Right trim rule names'
    }, "Which action would you like to take?")
    name_reg = r'^[a-zA-Z0-9][a-zA-Z0-9\.\s\_\-]+[a-zA-Z0-9\-\.\_]$'
    if action in [1,2]: #Append/Prepend
        str_add = input("What string would you like to add.\n Note, policy names must start with alphanumeric, contain only alphanumeric, hypen (-), underscore (_), period (.) and spaces.\n Policy names cannot end with a space.\n> ")
        if action == 1:
            if not str_add[-1:].isalnum():
                print("Invalid string. String must start with an alphanumeric characters")
                rename_rules(panx, rules, panorama, rule_data, devicegroup)
                return
           
        if action == 2:
            if not match(r'[a-zA-Z0-9\.\_\-]',str_add[0:1]):
                print("Invalid string. Policy name must end with period (.), underscore (_), hyphen (-) or an alphanumeric character")
                rename_rules(panx, rules, panorama, rule_data, devicegroup)
                return
        if panorama:
            for rulebase, rulelist in rules.items():
                for rule in rulelist:
                    xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/{}/nat/rules/entry[@name=\'{}\']'.format(devicegroup, rulebase, rule)
                    new_name = rule+str_add if action == 1 else str_add+rule
                    if len(new_name) > 63:
                        print("Name length is too long. Skipping for {}.".format(rule))
                        continue
                    if not match(name_reg, new_name):
                        print("Invalid Name {}. Skipping".format(new_name))
                        continue
                    if rule == new_name:
                        print("No changed to be made for {}. Skipping...".format(rule))
                        continue
                    print("Renaming {} to {}.".format(rule, new_name))
                    panx.rename(xpath=xpath,newname=new_name)
                    print(panx.status.capitalize())
        else:
            for rule in rules['devicelocal']:
                xpath = '/config/devices/entry/vsys/entry/rulebase/nat/rules/entry[@name=\'{}\']'.format(rule)
                new_name = rule+str_add if action == 1 else str_add+rule
                if len(new_name) > 63:
                    print("Name length is too long. Skipping for {}.".format(rule))
                    continue
                if not match(name_reg, new_name):
                    print("Invalid Name {}. Skipping".format(new_name))
                    continue
                if rule == new_name:
                    print("No changed to be made for {}. Skipping...".format(rule))
                    continue
                print("Renaming {} to {}.".format(rule, new_name))
                panx.rename(xpath=xpath,newname=new_name)
                print(panx.status.capitalize())
                
    elif action in [3,4]: #Left/Right trim
        str_trim = input("What string would you like to trim?\n> ")
        trimlen = len(str_trim)
        if panorama:
            for rulebase, rulelist in rules.items():
                for rule in rulelist:
                    xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/{}/nat/rules/entry[@name=\'{}\']'.format(devicegroup, rulebase, rule)
                    if action == 3:
                        new_name = rule[trimlen:] if rule[0:trimlen] == str_trim else rule
                    if action == 4:
                        new_name = rule[0:len(rule)-trimlen] if rule[-trimlen:] == str_trim else rule
                    if len(new_name) > 63:
                        print("Name length is too long. Skipping for {}.".format(rule))
                        continue
                    if not match(name_reg, new_name):
                        print("Invalid Name {}. Skipping".format(new_name))
                        continue
                    if rule == new_name:
                        print("No changed to be made for {}. Skipping...".format(rule))
                        continue
                    print("Renaming {} to {}.".format(rule, new_name))
                    panx.rename(xpath=xpath,newname=new_name)
                    print(panx.status.capitalize())
        else:
            for rule in rules['devicelocal']:
                xpath = '/config/devices/entry/vsys/entry/rulebase/nat/rules/entry[@name=\'{}\']'.format(rule)
                if action == 3:
                    new_name = rule[trimlen:] if rule[0:trimlen] == str_trim else rule
                if action == 4:
                    new_name = rule[0:len(rule)-trimlen] if rule[-trimlen:] == str_trim else rule
                if len(new_name) > 63:
                    print("Name length is too long. Skipping for {}.".format(rule))
                    continue
                if not match(name_reg, new_name):
                    print("Invalid Name {}. Skipping".format(new_name))
                    continue
                if rule == new_name:
                    print("No changed to be made for {}. Skipping...".format(rule))
                    continue
                print("Renaming {} to {}.".format(rule, new_name))
                panx.rename(xpath=xpath,newname=new_name)
                print(panx.status.capitalize())



def main(fw_host: str = None) -> None:
    if fw_host is None:
        fw_host = input("Enter the address of the firewall:\n ")
    save_key = False
    key_file = ".{}".format(fw_host.replace('.','-'))
    fw_key = None
    fw_uid = None
    fw_pwd = None
    panorama = False
    
    data = {
        'hostname':fw_host
    }

    if file_exists(key_file):
        f = open(key_file, 'r')
        try:
            fw_key = base64.standard_b64decode(f.readline()).decode()
        except binascii.Error:
            main(fw_host)
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
        print("\n" + "".center(60,'*'))
        print("Successfully connected to: {} ({})".format(hostname, fw_host).center(60) + "\n" + "Model: {}".format(model).center(60) +"\n" + "Version: {}".format(version).center(60))
        print("".center(60,'*')+"\n")
        sleep(1)
        # Uncomment to dump device info into text file
        #import json
        #f = open("{}-info.txt".format(fw_host.replace('.','-')),'w')
        #f.write(json.dumps(sysinfo,indent=2))
        #f.close()
    except PanXapiError as e:
        print("API Error: {}".format(e))
        if '403' in str(e) and fw_key is not None:
            # Delete the saved key if an unauthorised result is returned (case of password/key roll over)
            os.remove(key_file)
            print("Deleting saved key, please try again.")
        main()
        exit()

    if model == "Panorama":
        panorama = True
    actions = {
        1:'Add to Rule(s)',
        2:'Delete from Rule(s)',
        3:'Enable Rule(s)',
        4:'Disable Rule(s)',
        5:'Rename Rule(s)' #,
        #6:'Update Profiles',  to add later
        #7:'Change Rule Action' to add later
    }
    add_delete_actions = {
        1:'Source Zone',
        2:'Destination Zone',
        3:'Source Address',
        4:'Destination Address',
        5:'Destination Interface',
        6:'Service',
        7:'Source Translation Type',
        8:'Destination Translation Type',
        9: 'Tag',
        10: 'Group by Tag'#,
        #11: 'Description' # to add later
    }


    get_task = verify_selection(actions,"Input an action to perform:", False)
    if get_task in [1,2]: #Add/Remove elements
        sub_task = verify_selection(add_delete_actions, "Which element do you wish to {} rule(s):\n ".format("add to" if get_task == 1 else "remove from"), False)

    if panorama:
        panx.op('show devicegroups', cmd_xml=True)
        xm = panx.element_root.find('result')
        devicegroups = {}
        count = 1
        for dg in xm.find('devicegroups'):
            devicegroups[count] = dg.get('name')
            count+=1
        devicegroup = devicegroups[verify_selection(devicegroups, "Which Device Group do you want to modify:", False)]
        del devicegroups, count
    else:
        devicegroup = ""

    print('\nRetrieving current rules...\n')
    if panorama:        
        xpath = '/config/devices/entry/device-group/entry[@name="{}"]'.format(devicegroup)
    else:
        xpath = '/config/devices/entry/vsys/entry/rulebase/nat/rules'

    panx.get(xpath)
    xm = panx.element_root.find('result')
    rules = {}
    rule_data = {}

    if panorama:
        xm = xm[0]
        if xm.find('pre-rulebase'):
            pre_rules = xm.find('pre-rulebase').find('nat')
        else:
            pre_rules = None

        if xm.find('post-rulebase'):
            post_rules = xm.find('post-rulebase').find('nat')
        else:
            post_rules = None

        rules['pre-rulebase'] = []
        rules['post-rulebase'] = []

        if pre_rules:
            for e in pre_rules.find('rules'):
                rules['pre-rulebase'].append(e.get('name'))
                rname = e.get('name')
                rule_data[rname] = {}
                rule_data[rname]['xml'] = e

        if post_rules:
            for e in post_rules.find('rules'):
                rules['post-rulebase'].append(e.get('name'))
                rname = e.get('name')
                rule_data[rname] = {}
                rule_data[rname]['xml'] = e

    else:
        rules['devicelocal'] = []
        count = 1
        for e in xm.find('rules'):
            rules['devicelocal'].append(e.get('name'))
            rname = e.get('name')
            rule_data[rname] = {}
            rule_data[rname]['xml'] = e
            count+=1
    
    for rule in rule_data.keys():
        r = rule_data[rule]
        to_zones = r['xml'].find('to')
        from_zones = r['xml'].find('from')
        to_address = r['xml'].find('destination')
        from_address = r['xml'].find('source')
        service = r['xml'].find('service')
        target = r['xml'].find('target')

        ###########################################################################################################################################
        ############################################################ CONTINUE #####################################################################
        ###########################################################################################################################################
        if r['xml'].find('to-interface') is not None:
            rule_data[rule]['to-interface'] = r['xml'].find('to-interface').text
        
        tag = r['xml'].find('tag')
        source_translation = r['xml'].find('source-translation')
        if source_translation is not None:
            source_type = source_translation[0].tag
            rule_data[rule]['source-nat-type'] = source_type
            if source_type == 'dynamic-ip-and-port':
                if source_translation[0].find('interface-address') is not None:
                    rule_data[rule]['source-interface'] = source_translation[0].find('interface-address').find('interface').text
                if source_translation[0].find('translated-address') is not None:
                    source_ips = []
                    for s in source_translation[0].find('translated-address'):
                        source_ips.append(s.text)
                    rule_data[rule]['source-ips'] = source_ips

            if source_type == 'dynamic-ip':
                source_ips = []
                for s in source_translation[0].find('translated-address'):
                    source_ips.append(s.text)
                rule_data[rule]['source-ips'] = source_ips

            if source_type == 'static-ip':
                rule_data[rule]['source-ip'] = source_translation[0].find('translated-address').text
                if source_translation[0].find('translated-address').find('bi-directional') is not None:
                    rule_data[rule]['bi-directional'] = source_translation[0].find('translated-address').find('bi-directional').text
                

        destination_translation = r['xml'].find('dynamic-destination-translation')
        if destination_translation is not None:
            rule_data[rule]['destination-address'] = destination_translation.find('translated-address').text
            rule_data[rule]['destination-port'] = destination_translation.find('translated-port').text if destination_translation.find('translated-port') is not None else None
            if destination_translation.find('distribution') is not None:
                rule_data[rule]['distribution'] = destination_translation.find('distribution').text

        destination_translation = r['xml'].find('destination-translation')
        if destination_translation is not None:
            rule_data[rule]['destination-address'] = destination_translation.find('translated-address').text
            rule_data[rule]['destination-port'] = destination_translation.find('translated-port').text if destination_translation.find('translated-port') is not None else None
            if destination_translation.find('dns-rewrite') is not None:
                rule_data[rule]['dns-rewrite'] = destination_translation.find('dns-rewrite').find('direction').text


        ###########################################################################################################################################
        ###########################################################################################################################################
        ###########################################################################################################################################
        
        if r['xml'].find('group-tag') is not None:
            rule_data[rule]['group-tag'] = r['xml'].find('group-tag').text

        if r['xml'].find('description') is not None:
            rule_data[rule]['description'] = r['xml'].find('description').text

        if r['xml'].find('active-active-device-binding') is not None:
            rule_data[rule]['active-active-device-binding'] = r['xml'].find('active-active-device-binding').text

        rule_data[rule]['to'] = []
        for z in to_zones:
            rule_data[rule]['to'].append(z.text)

        rule_data[rule]['from'] = []
        for z in from_zones:
            rule_data[rule]['from'].append(z.text)

        rule_data[rule]['destination'] = []
        for z in to_address:
            rule_data[rule]['destination'].append(z.text)

        rule_data[rule]['source'] = []
        for z in from_address:
            rule_data[rule]['source'].append(z.text)

        rule_data[rule]['service'] = []
        for z in service:
            rule_data[rule]['service'].append(z.text)

        rule_data[rule]['tag'] = []
        if tag is not None:
            for z in tag:
                rule_data[rule]['tag'].append(z.text)
        
        rule_data[rule]['target'] = []
        if target is not None:
            for z in target:
                rule_data[rule]['target'].append(z.text)

        r['xml'] = None

    print(json.dumps(rule_data, indent=2))
    exit()
    rules_selection = {}
    count = 1
    for k,v in rules.items():
        rulebase = k
        for sv in v:
            rules_selection[count] = "{} - {}".format(rulebase,sv)
            count+=1
    del count, k, v
    
    chosen_rules = verify_selection(rules_selection, "Which rules do you want to apply to?", True)
    # Create dictionary of only rules affected within each rulesbase, removing rulebase from selection.
    contexts = ['pre-rulebase', 'post-rulebase', 'devicelocal']
    chosen_rules_polished = {}
    for count in contexts:
        chosen_rules_polished[count] = []
        for r in chosen_rules.values():
            if r[0:len(count)] == count:
                chosen_rules_polished[count].append(r.replace("{} - ".format(count),""))
    del chosen_rules

    # Remove unaffected rulebases. (removing empty keys from the dictionary)
    rules = {}
    for k,v in chosen_rules_polished.items():
        if len(v):
            rules[k] = []
            for r in v:
                rules[k].append(r)
    del k, r, chosen_rules_polished

    # Add To nat Policies
    if get_task == 1:
        # Source / Destination Zone
        if sub_task in [1,2]:
            add_remove_rule_zones(panx, rules, panorama, 'add', 'from' if sub_task == 1 else 'to', rule_data, devicegroup)
        
        # Source / Destination Address
        if sub_task in [3,4]:
            add_remove_rule_address(panx, rules, panorama, 'add', 'source' if sub_task == 3 else 'destination', rule_data, devicegroup)
        
        # Tags
        if sub_task == 9:
            add_remove_rule_tags(panx,rules,panorama,'add',rule_data, devicegroup)

        # Group by Tags
        if sub_task == 10:
            add_remove_rule_group_by_tags(panx,rules,panorama,'add',rule_data, devicegroup)

    # Remove From nat Policies
    if get_task == 2: 
        # Source / Destination Zone
        if sub_task in [1,2]:
            add_remove_rule_zones(panx, rules, panorama, 'remove', 'from' if sub_task == 1 else 'to', rule_data, devicegroup)
        
        # Source / Destination Address
        if sub_task in [3,4]:
            add_remove_rule_address(panx, rules, panorama, 'remove', 'source' if sub_task == 3 else 'destination', rule_data, devicegroup)
        
        # Tags
        if sub_task == 9:
            add_remove_rule_tags(panx,rules,panorama,'remove',rule_data, devicegroup)

        # Group by Tags
        if sub_task == 10:
            add_remove_rule_group_by_tags(panx,rules,panorama,'remove',rule_data, devicegroup)

    # Enable Rules
    if get_task == 3:
        enable_disable_rules(panx, rules, panorama, 'enable', devicegroup)

    #  Disable Rules    
    if get_task == 4:
        enable_disable_rules(panx, rules, panorama, 'disable', devicegroup)

    # Rename Rules
    if get_task == 5:
        rename_rules(panx, rules, panorama, rule_data, devicegroup)

    # Commit and Push
    do_commit = input("Would you like to commit? (Y/N):\n Note. this will push to all devices in selected the device group.\n ") if panorama else input("Would you like to commit? (Y/N):\n ")
    
    if len(do_commit) >= 1 and do_commit[0].lower() == 'y':
        # Get Commit Description
        commit_description = input("\n\nCommit description?: \n ")
        
        print("Committing...")

        # Commit to Firewall / Panorama
        panx.commit(cmd='<commit><description>{}</description></commit>'.format(commit_description), sync=True, interval=2)
        
        # Push policies down to firewalls in chosen device group.
        if panorama:
            if panx.status == 'success':
                print("Commit Successful, Pushing to devices...")
                panx.commit(cmd='<commit-all><shared-policy><description>{}</description><device-group><entry name="{}"/></device-group></shared-policy></commit-all>'.format(commit_description, devicegroup), action='all')
    
        # Find policy push job status'
        if panx.status == 'success' and panorama:
            job = panx.element_root[0].find('job').text 
            status, results = job_status(panx, job)
            complete = False
            print("Job #{} Committed".format(job))
            count = 1
            while (complete != True and count <= 5):
                if status == 'success':
                    if 'PEND' in results.values():
                        print("Device push still in progress. Checking again in 30 seconds")
                        sleep(30)
                        status, results = job_status(panx, job)
                    else:
                        complete = True
                        print("Commit Complete!")
                count = count + 1   
            res = "\n"+ "Results".center(63) + "\n" + "".center(63,"*") +"\n|" 
            res += "Device".center(30) + "|" + "Status".center(30) + "|\n|" + " ".center(30) + "|" + " ".center(30) + "|\n"
            for device, result in results.items():
                res += "|" + device.center(30) + "|" + result.center(30) + "|\n"
            res += "".center(63, "*")
            print(res)
        elif panx.status == 'success':
            job = panx.element_root[0].find('job')
            job_id = job.find('id').text
            job_result = job.find('result').text
            print("Job #{} Completed:".format(job_id), job_result)
        else:
            print('Failed to commit: {}'.format(panx.xml_document))

    #show dhcp server lease interface all
    #panx.op('show dhcp server lease interface "all"', cmd_xml=True)
    #print(panx.xml_document)

if __name__ == '__main__':
    # Set firewall / panorama address
    fw_host = sys.argv[1:2][0] if len(sys.argv) > 1 else input("What is the firewall or Panorama address?:\n")
    
    if fw_host is not None:
        if not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$',fw_host) and not match (r'^([a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+$',fw_host):
            print("Invalid host entered...{}".format(fw_host)) 
            fw_host = None
        try:
            main(fw_host)
        except KeyboardInterrupt:
            print("Cancelled by keyboard interrupt")
            exit()
