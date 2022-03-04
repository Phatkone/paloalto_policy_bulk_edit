"""
Author: Craig Beamish
Date Written: 2020/12/10
Last Modified By: Craig Beamish
Date Last Modified: 2020/12/10
Date Last Tested: Placeholder - still to be formed
Result: 
Description: Bulk update tool for Palo Alto NAT policies. Can be used with Panorama or the firewalls directly.
Dependencies: pan-python
Usage: `python3 pan_nat_bulk_update.py` or `python3 pan_nat_bulk_update.py <host ip or fqdn>`
 All inputs required are in prompt format within the script.
"""

from pan.xapi import PanXapi
from re import match
from re import split
try:
    from lib.common import verify_selection
    from lib.common import get_device_group_stack
    from lib.common import get_parent_dgs
    from lib.common import get_interfaces
    from lib.common import get_services
    from lib.common import get_address_objects
    from lib.common import commit
    from lib.common import list_to_dict
    from lib.common import panorama_xpath_objects_base
    from lib.common import panorama_xpath_templates_base
    from lib.common import device_xpath_base
except ImportError:
    pass

def update_rule_zones(panx: PanXapi, rules: dict, panorama: bool, action: str, source_dest: str, rule_data: dict, devicegroup: str = "") -> None:
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
        xpath = panorama_xpath_templates_base.format(template) + 'vsys/entry[@name=\'vsys1\']/zone'
    else:
        xpath = device_xpath_base + 'zone'

    #Get Zones list for selection
    panx.get(xpath)
    xm = panx.element_root.find('result')
    count = 1
    for zone in xm[0]:
        zones[count] = zone.get('name')
        count+=1
    del count
    zone_selection = verify_selection(zones, "Which Zone(s) do you wish to {}?:".format(action) if source_dest == 'from' else "Which destination zone do you wish to set?:", True, True)

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
                elif action == 'remove' and zone not in zone_selection:
                    new_zone_list[rule].append(zone)
            for zone in zone_selection:
                if action == 'add' and zone not in new_zone_list[rule]:
                    new_zone_list[rule].append(zone)
                # If removing last zone, must put member any in
                if len(new_zone_list[rule]) < 1 and source_dest == 'from':
                    new_zone_list[rule].append('any')

    # Create XML object to push with API call
    zone_xml = {} 
    for rule, zone_list in new_zone_list.items():
        zone_xml[rule] = "<{}>".format(source_dest)
        if source_dest == 'from':
                for zone in zone_list:
                    zone_xml[rule] += '<member>{}</member>'.format(zone)
        if source_dest == 'to':
                zone_xml[rule] += '<member>{}</member>'.format(zone_selection[0])            
        zone_xml[rule] += "</{}>".format(source_dest)

    if panorama:
        for rulebase, rulelist in rules.items():
            for rule in rulelist:
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/{}'.format(rulebase, rule, source_dest)
                print("{} zone(s): {} {} rule: '{}' in rulebase: {}".format('Adding' if action == 'add' else 'Removing', " ".join(zone_selection), 'to' if action == 'add' else 'from', rule, rulebase))
                panx.edit(xpath=xpath,element=zone_xml[rule])
                print(panx.status.capitalize())
    else:
        for rule in rules['devicelocal']:
            xpath = device_xpath_base + 'rulebase/nat/rules/entry[@name=\'{}\']/{}'.format(rule, source_dest)
            print("{} zone(s): {} {} rule: '{}'".format('Adding' if action == 'add' else 'Removing', " ".join(zone_selection), 'to' if action == 'add' else 'from', rule))
            panx.edit(xpath=xpath,element=zone_xml[rule])
            print(panx.status.capitalize())


def update_rule_address(panx: PanXapi, rules: dict, panorama: bool, action: str, source_dest: str, rule_data: dict, devicegroup: str = "") -> None:
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
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/{}'.format(rulebase, rule, source_dest)
                print("{} address: {} {} rule: '{}' in rulebase: {}".format('Adding' if action == 'add' else "Removing", address, 'to' if action == 'add' else "from", rule, rulebase))
                panx.edit(xpath=xpath,element=addr_xml[rule])
                print(panx.status.capitalize())
    else:
        for rule in rules['devicelocal']:
            xpath = device_xpath_base + 'rulebase/nat/rules/entry[@name=\'{}\']/{}'.format(rule, source_dest)
            print("{} address: {} {} rule: '{}'".format('Adding' if action == 'add' else "Removing", address, 'to' if action == 'add' else "from", rule))
            panx.edit(xpath=xpath,element=addr_xml[rule])
            print(panx.status.capitalize())


def update_destination_interface(panx: PanXapi, rules: dict, panorama: bool, action: str, rule_data: dict, devicegroup: str = "") -> None:
    if action == 'set':
        interfaces = {}
        template = ""
        # Get template if Panorama
        if panorama: 
            panx.get('/config/devices/entry/template')
            templates = {}
            templates_xml = panx.element_root.find('result')
            count = 1
            for template in templates_xml[0]:
                templates[count] = template.get("name")
                count += 1
            template = templates[verify_selection(templates, "Which Template does the interface belong to?:", False)]
            del templates_xml, count, templates

        interfaces = get_interfaces(panx, panorama, template).keys()
        interfaces = list_to_dict(interfaces, 1)
        interface_selection = verify_selection(interfaces, "Which interface do you wish to set?:", False, True)
        
        if panorama:
            for rulebase, rulelist in rules.items():
                for rule in rulelist:
                    xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/to-interface'.format(rulebase, rule)
                    print("Setting destination interface to {} rule: '{}' in rulebase: {}".format(interface_selection, rule, rulebase))
                    panx.edit(xpath=xpath,element="<to-interface>{}</to-interface>".format(interface_selection))
                    print(panx.status.capitalize())
        else:
            for rule in rules['devicelocal']:
                xpath = device_xpath_base + 'rulebase/nat/rules/entry[@name=\'{}\']/to-interface'.format(rule)
                print("Setting destination interface to {} rule: '{}'".format(interface_selection, rule))
                panx.edit(xpath=xpath,element="<to-interface>{}</to-interface>".format(interface_selection))
                print(panx.status.capitalize())
    else:
        # Remove destination interface
        if panorama:
            for rulebase, rulelist in rules.items():
                for rule in rulelist:
                    xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/to-interface'.format(rulebase, rule)
                    print("Removing destination interface from rule: '{}' in rulebase: {}".format(rule, rulebase))
                    panx.delete(xpath=xpath)
                    print(panx.status.capitalize())
        else:
            for rule in rules['devicelocal']:
                xpath = device_xpath_base + 'rulebase/nat/rules/entry[@name=\'{}\']/to-interface'.format(rule)
                print("Removing destination interface from rule: '{}'".format(rule))
                panx.delete(xpath=xpath)
                print(panx.status.capitalize())


def update_service(panx: PanXapi, rules: dict, panorama: bool, action: str, rule_data: dict, devicegroup: str = "") -> None:
    if action == 'set':
        services = get_services(panx, panorama, devicegroup)
        service_selection = verify_selection(services, "Which Service do you wish to set?:", False, True)
    else:
        service_selection = 'any'
        
    if panorama:
        for rulebase, rulelist in rules.items():
            for rule in rulelist:
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/service'.format(rulebase, rule)
                print("Setting service to {} for rule '{}' in rulebase: {}".format(service_selection, rule, rulebase))
                panx.edit(xpath=xpath,element="<service>{}</service>".format(service_selection))
                print(panx.status.capitalize())
    else:
        for rule in rules['devicelocal']:
            xpath = device_xpath_base + 'rulebase/nat/rules/entry[@name=\'{}\']/service'.format(rule)
            print("Setting service to {} for rule '{}'".format(service_selection, rule))
            panx.edit(xpath=xpath,element="<service>{}</service>".format(service_selection))
            print(panx.status.capitalize())


def update_rule_tags(panx: PanXapi, rules: dict, panorama: bool, action: str, rule_data: dict, devicegroup: str = "") -> None:
    tags = {}
    # Set xpath
    dg_stack = get_device_group_stack(panx) if panorama else {}
    dg_list = get_parent_dgs(panx, devicegroup, dg_stack)
    
    if len(dg_list) > 0 and devicegroup != "":
        for dg in dg_list:
            xpath = panorama_xpath_objects_base.format(dg) + 'tag'
            panx.get(xpath)
            xm = panx.element_root.find('result')
            count = 1
            for tag in xm[0]:
                tags[count] = tag.get('name')
                count+=1
    
    if devicegroup not in dg_list or not panorama:
        xpath = panorama_xpath_objects_base.format(devicegroup) + 'tag'.format(devicegroup) if panorama else device_xpath_base + 'tag'
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
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/tag'.format(rulebase, rule)
                print("{} tag(s): {} {}  rule: '{}' in rulebase: {}".format('Adding' if action == 'add' else 'Removing', " ".join(tag_selection.values()), 'to' if action == 'add' else 'from', rule, rulebase))
                panx.edit(xpath=xpath,element=tag_xml[rule])
                print(panx.status.capitalize())
    else:
        for rule in rules['devicelocal']:
            xpath = device_xpath_base + 'rulebase/nat/rules/entry[@name=\'{}\']/tag'.format(rule)
            print("{} tag(s): {} {}  rule: '{}'".format('Adding' if action == 'add' else 'Removing', " ".join(tag_selection.values()), 'to' if action == 'add' else 'from', rule))
            panx.edit(xpath=xpath,element=tag_xml[rule])
            print(panx.status.capitalize())


def update_rule_group_by_tags(panx: PanXapi, rules: dict, panorama: bool, action: str, rule_data: dict, devicegroup: str = "") -> None:
    tags = {}
    dg_stack = get_device_group_stack(panx) if panorama else {}
    dg_list = get_parent_dgs(panx, devicegroup, dg_stack)
    
    if len(dg_list) > 0 and devicegroup != "":
        for dg in dg_list:
            xpath = panorama_xpath_objects_base.format(dg) + 'tag'
            panx.get(xpath)
            xm = panx.element_root.find('result')
            count = 1
            if len(xm):
                for tag in xm[0]:
                    tags[count] = tag.get('name')
                    count+=1
    
    if devicegroup not in dg_list or not panorama:
        xpath = panorama_xpath_objects_base.format(devicegroup) + 'tag'.format(devicegroup) if panorama else device_xpath_base + 'tag'
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
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/group-tag'.format(rulebase, rule)
                print("{} {}  rule: '{}' in rulebase: {}".format('Adding {}'.format(tag) if action == 'add' else 'Removing tag', 'to' if action == 'add' else 'from', rule, rulebase))
                if action == 'add':
                    panx.edit(xpath=xpath, element=tag_xml)
                else:
                    panx.delete(xpath=xpath)
                print(panx.status.capitalize())
    else:
        for rule in rules['devicelocal']:
            xpath = device_xpath_base + 'rulebase/nat/rules/entry[@name=\'{}\']/group-tag'.format(rule)
            print("{} {}  rule: '{}'".format('Adding {}'.format(tag) if action == 'add' else 'Removing tag', 'to' if action == 'add' else 'from', rule))
            if action == 'add':
                panx.edit(xpath=xpath, element=tag_xml)
            else:
                panx.delete(xpath=xpath)
            print(panx.status.capitalize())
    

def enable_disable_rules(panx: PanXapi, rules: dict, panorama: bool, action: str, devicegroup: str = "") -> None:
    if panorama:
        for rulebase, rulelist in rules.items():
            for rule in rulelist:
                print("{} rule: '{}' in rulebase: {}".format('Enabling' if action == 'enable' else 'Disabling', rule, rulebase))
                panx.set(xpath=panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']'.format(rulebase,rule), element='<disabled>{}</disabled>'.format('no' if action == 'enable' else 'yes'))
                print(panx.status.capitalize())
    else:
        for rule in rules['devicelocal']:
            print("{} rule: '{}'".format('Enabling' if action == 'enable' else 'Disabling', rule))
            panx.set(xpath=device_xpath_base + 'rulebase/nat/rules/entry[@name=\'{}\']'.format(rule), element='<disabled>{}</disabled>'.format('no' if action == 'enable' else 'yes'))
            print(panx.status.capitalize())


def rename_rules(panx: PanXapi, rules: dict, panorama: bool, rule_data: dict, devicegroup: str = "") -> None:
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
                    xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']'.format(rulebase, rule)
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
                xpath = device_xpath_base + 'rulebase/nat/rules/entry[@name=\'{}\']'.format(rule)
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
                    xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']'.format(rulebase, rule)
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
                xpath = device_xpath_base + 'rulebase/nat/rules/entry[@name=\'{}\']'.format(rule)
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


def update_source_translation(panx: PanXapi, rules: dict, panorama: bool, rule_data: dict, devicegroup: str = "") -> None:
    source_translation_type = verify_selection({
        1: 'Dynamic Source IP and Port Translation',
        2: 'Dynamic Source IP Translation',
        3: 'Static Source IP Translation',
        4: 'Remove (None)'
    }, "What source translation type would you like?")
    
    if source_translation_type == 1:
        address_type = verify_selection({
            1: 'Interface Address',
            2: 'Translated Address'
        }, "Address Type?", False, True).lower().replace(' ','-')
        element = "<source-translation><dynamic-ip-and-port><{}>".format(address_type)
        if address_type == 'interface-address':
            if panorama: 
                panx.get('/config/devices/entry/template')
                templates = {}
                templates_xml = panx.element_root.find('result')
                count = 1
                for template in templates_xml[0]:
                    templates[count] = template.get("name")
                    count += 1
                template = verify_selection(templates, "Which Template does the zone belong to?:", False, True)
                del templates_xml, count, templates      
            else:
                template = ""
            interfaces = get_interfaces(panx, panorama, template, True)
            interface = verify_selection(list_to_dict(interfaces.keys(), 1), "Which Source Interface?:", False, True)
            element += "<interface>{}</interface>".format(interface)
            int_ips = ['None']
            if 'ip' in interfaces[interface].keys():
                for i in interfaces[interface]['ip']:
                    int_ips.append(i)
            interface_ip = verify_selection(list_to_dict(int_ips, 1), "Specify Source IP?", False, True)
            if interface_ip != 'None':
                element += "<ip>{}</ip>".format(interface_ip)
        else:
            address_objects = get_address_objects(panx, panorama, devicegroup, True)
            addresses = input("Enter address object names or IP addresses of source address? (Separate by single space) (case sensitive):\n> ").replace(', ',' ').replace(',',' ').split(' ')
            count = 0
            for address in addresses:
                if not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/([0-9]|[1-2][0-9]|3[0-2])$', address) and not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$', address) and (address not in address_objects.values()):
                    print('Invalid Address Entered: {}'.format(address))
                    exit()
                if '/' not in address and address not in address_objects.values():
                    addresses[count] = "{}/32".format(address)
                    print("No CIDR Notation found, treating as /32")
                element += "<member>{}</member>".format(address)
                count += 1
        element += "</{}></dynamic-ip-and-port></source-translation>".format(address_type)
        for rulebase, rule_list in rules.items():
            for rule in rule_list:
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/source-translation'.format(rulebase, rule) if panorama else 'nat/rules/entry[@name=\'{}\']/source-translation'.format(rule)
                panx.edit(xpath=xpath, element=element)
                print("Setting Dynamic Source IP and Port for rule {} in rulebase {}".format(rule, rulebase) if panorama else "Setting Dynamic Source IP and Port for rule {}".format(rule))

        pass
        for rulebase, rule_list in rules.items():
            for rule in rule_list:
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/source-translation'.format(rulebase, rule) if panorama else 'nat/rules/entry[@name=\'{}\']/source-translation'.format(rule)

    if source_translation_type == 2:
        address_objects = get_address_objects(panx, panorama, devicegroup, True)
        addresses = input("Enter address object names or IP addresses of source address? (Separate by single space) (case sensitive):\n> ").replace(', ',' ').replace(',',' ').split(' ')
        count = 0
        element = "<source-translation><dynamic-ip><translated-address>"
        for address in addresses:
            if not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/([0-9]|[1-2][0-9]|3[0-2])$', address) and not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$', address) and (address not in address_objects.values()):
                print('Invalid Address Entered: {}'.format(address))
                exit()
            if '/' not in address and address not in address_objects.values():
                addresses[count] = "{}/32".format(address)
                print("No CIDR Notation found, treating as /32")
            element += "<member>{}</member>".format(address)
            count += 1
        element += "</translated-address></dynamic-ip></source-translation>"
        for rulebase, rule_list in rules.items():
            for rule in rule_list:
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/source-translation'.format(rulebase, rule) if panorama else 'nat/rules/entry[@name=\'{}\']/source-translation'.format(rule)
                panx.edit(xpath=xpath, element=element)
                print("Setting Dynamic Source IP(s) '{}' for rule {} in rulebase {}".format(" ".join(addresses), rule, rulebase) if panorama else "Setting Dynamic Source IP(s) '{}' for rule {}".format(" ".join(addresses), rule))

    if source_translation_type == 3:
        address_objects = get_address_objects(panx, panorama, devicegroup, True)
        address = input("Enter address object name or IP address of source address (case sensitive):\n> ")
        if not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/([0-9]|[1-2][0-9]|3[0-2])$', address) and not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$', address) and (address not in address_objects.values()):
            print('Invalid Address Entered: {}'.format(address))
            exit()
        if '/' not in address and address not in address_objects.values():
            address += '/32'
            print("No CIDR Notation found, treating as /32")
        element = "<source-translation><static-ip><translated-address>{}</translated-address>".format(address)
        if verify_selection({
            1: 'Yes',
            2: 'No'
        }, "Enable Bi-Directional Translation") == 1:
            element += "<bi-directional>yes</bi-directional>"
        element += "</static-ip></source-translation>"
        for rulebase, rule_list in rules.items():
            for rule in rule_list:
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/source-translation'.format(rulebase, rule) if panorama else 'nat/rules/entry[@name=\'{}\']/source-translation'.format(rule)     
                panx.edit(xpath=xpath, element=element)
                print("Setting Static Source IP '{}' for rule {} in rulebase {}".format(address, rule, rulebase) if panorama else "Setting Static Source IP '{}' for rule {}".format(address, rule))

    if source_translation_type == 4:
        for rulebase, rule_list in rules.items():
            for rule in rule_list:
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/source-translation'.format(rulebase, rule) if panorama else 'nat/rules/entry[@name=\'{}\']/source-translation'.format(rule)
                panx.delete(xpath=xpath)
                print("Removing Destination Translation from {} in {}".format(rule, rulebase) if panorama else "Removing Destination Translation from {}".format(rule))


def update_destination_translation(panx: PanXapi, rules: dict, panorama: bool, rule_data: dict, devicegroup: str = "") -> None:
    destination_translation_type = verify_selection({
        1: 'Dynamic Destination Translation',
        2: 'Destination Translation',
        3: 'Remove (None)'
    }, "What destination translation type would you like?")
    if destination_translation_type == 1:
        address_objects = get_address_objects(panx, panorama, devicegroup, True)
        address = input("Enter address object name or IP address of destination (case sensitive):\n> ")
        if not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/([0-9]|[1-2][0-9]|3[0-2])$', address) and not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$', address) and (address not in address_objects.values()):
            print('Invalid Address Entered: {}'.format(address))
            exit()
        if '/' not in address and address not in address_objects.values():
            address += '/32'
            print("No CIDR Notation found, treating as /32")
        port = input("Destination port? (Leave blank for default traffic port, numberical value only I.E. 443):\n> ")
        if port == "":
            port = None
        if port is not None and not match(r'^\d{1,5}$', port):
            print("Invalid port number")
        session_distribution = verify_selection({
            1: 'round-robin',
            2: 'source-ip-hash',
            3: 'ip-modulo',
            4: 'ip-hash',
            5: 'least-sessions'
        }, "Session Distribution Method?",False , True)
        element = "<dynamic-destination-translation><translated-address>{}</translated-address>".format(address)
        if port is not None:
            element += "<translated-port>{}</translated-port>".format(port)
        element += "<distribution>{}</distribution></dynamic-destination-translation>".format(session_distribution)

        for rulebase, rule_list in rules.items():
            for rule in rule_list:
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/dynamic-destination-translation'.format(rulebase, rule) if panorama else 'nat/rules/entry[@name=\'{}\']/dynamic-destination-translation'.format(rule)
                panx.edit(xpath=xpath, element=element)
                print("Setting Dynamic Destination Translation for {} in {}".format(rule, rulebase) if panorama else "Setting Dynamic Destination Translation for {}".format(rule))

    if destination_translation_type == 2:
        address_objects = get_address_objects(panx, panorama, devicegroup, False)
        address = input("Enter address object name or IP address of destination (case sensitive):\n> ")
        if not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/([0-9]|[1-2][0-9]|3[0-2])$', address) and not match(r'^((0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(0?0?[0-9]|0?[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$', address) and (address not in address_objects.values()):
            print('Invalid Address Entered: {}'.format(address))
            exit()
        if '/' not in address and address not in address_objects.values():
            address += '/32'
            print("No CIDR Notation found, treating as /32")
        port = input("Destination port? (Leave blank for default traffic port, numberical value only I.E. 443):\n> ")
        if port == "":
            port = None
        if port is not None and not match(r'^\d{1,5}$', port):
            print("Invalid port number")
        dns_rewrite = verify_selection({
            1: 'Yes',
            2: 'No'
        }, "Enable DNS Rewrite?")
        element = "<destination-translation><translated-address>{}</translated-address>".format(address)
        if port is not None:
            element += "<translated-port>{}</translated-port>".format(port)
        if dns_rewrite == 1:
            dns_rewrite_direction = verify_selection({
                1: 'Forward',
                2: 'Reverse'
            }, "DNS Rewrite Direction?", False, True)
            element += "<dns-rewrite><direction>{}</direction></dns-rewrite>".format(dns_rewrite_direction.lower())
        element += "</destination-translation>"

        for rulebase, rule_list in rules.items():
            for rule in rule_list:
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/destination-translation'.format(rulebase, rule) if panorama else 'nat/rules/entry[@name=\'{}\']/destination-translation'.format(rule)
                panx.edit(xpath=xpath, element=element)
                print("Setting Destination Translation for {} in {}".format(rule, rulebase) if panorama else "Setting Destination Translation for {}".format(rule))
               
    if destination_translation_type == 3:
        for rulebase, rule_list in rules.items():
            for rule in rule_list:
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/destination-translation'.format(rulebase, rule) if panorama else 'nat/rules/entry[@name=\'{}\']/destination-translation'.format(rule)
                panx.delete(xpath=xpath)
                xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']/dynamic-destination-translation'.format(rulebase, rule) if panorama else 'nat/rules/entry[@name=\'{}\']/dynamic-destination-translation'.format(rule)
                panx.delete(xpath=xpath)
                print("Removing Destination Translation from {} in {}".format(rule, rulebase) if panorama else "Removing Destination Translation from {}".format(rule))
                

def update_description(panx: PanXapi, rules: dict, panorama: bool, rule_data: dict, devicegroup: str = "") -> None:
    action = verify_selection({
        1: 'Append rule description',
        2: 'Prepend rule description',
        3: 'Left trim rule description',
        4: 'Right trim rule description',
        5: 'Replace rule description'
    }, "Which action would you like to take?")
    if action in [1,2,5]: #Append/Prepend
        str_add = input("What string would you like to add?\n> " if action in [1,2] else "What string would you like to set?\n> ")

        if panorama:
            for rulebase, rulelist in rules.items():
                for rule in rulelist:
                    xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']'.format(rulebase, rule)
                    new_des = rule_data[rule]['description']+str_add if action == 1 else str_add+rule_data[rule]['description']
                    new_des = str_add if action == 5 else new_des
                    if len(new_des) > 1023:
                        print("Description length is too long. Skipping for {}.".format(rule))
                        continue
                    print("Setting description for: {}.".format(rule))
                    panx.set(xpath=xpath,element="<description>{}</description>".format(new_des))
                    print(panx.status.capitalize())
        else:
            for rule in rules['devicelocal']:
                xpath = device_xpath_base + 'rulebase/nat/rules/entry[@name=\'{}\']'.format(rule)
                new_des = rule_data[rule]['description']+str_add if action == 1 else str_add+rule_data[rule]['description']
                new_des = str_add if action == 5 else new_des
                if len(new_des) > 1023:
                    print("Name length is too long. Skipping for {}.".format(rule))
                    continue
                print("Setting description for: {}.".format(rule))
                panx.set(xpath=xpath,element="<description>{}</description>".format(new_des))
                print(panx.status.capitalize())
                
    elif action in [3,4]: #Left/Right trim
        str_trim = input("What string would you like to trim?\n> ")
        trimlen = len(str_trim)
        if panorama:
            for rulebase, rulelist in rules.items():
                for rule in rulelist:
                    xpath = panorama_xpath_objects_base.format(devicegroup) + '{}/nat/rules/entry[@name=\'{}\']'.format(rulebase, rule)
                    if action == 3:
                        new_des = rule_data[rule]['description'][trimlen:] if rule_data[rule]['description'][0:trimlen] == str_trim else rule_data[rule]['description']
                    if action == 4:
                        new_des = rule_data[rule]['description'][0:len(rule)-trimlen] if rule_data[rule]['description'][-trimlen:] == str_trim else rule_data[rule]['description']
                    if len(new_des) > 1023:
                        print("Description length is too long. Skipping for {}.".format(rule))
                        continue
                    print("Setting description for: {}.".format(rule))
                    panx.set(xpath=xpath,element="<description>{}</description>".format(new_des))
                    print(panx.status.capitalize())
        else:
            for rule in rules['devicelocal']:
                xpath = device_xpath_base + 'rulebase/nat/rules/entry[@name=\'{}\']'.format(rule)
                if action == 3:
                    new_des = rule_data[rule]['description'][trimlen:] if rule_data[rule]['description'][0:trimlen] == str_trim else rule_data[rule]['description']
                if action == 4:
                    new_des = rule_data[rule]['description'][0:len(rule)-trimlen] if rule_data[rule]['description'][-trimlen:] == str_trim else rule_data[rule]['description']
                if len(new_des) > 1023:
                    print("Name length is too long. Skipping for {}.".format(rule))
                    continue
                print("Setting description for: {}.".format(rule))
                panx.set(xpath=xpath,element="<description>{}</description>".format(new_des))
                print(panx.status.capitalize())


def main(panx: PanXapi, panorama: bool = False) -> None:
    actions = {
        1: 'Add to Rule(s)',
        2: 'Delete from Rule(s)',
        3: 'Enable Rule(s)',
        4: 'Disable Rule(s)',
        5: 'Rename Rule(s)',
        6: 'Update Destination Zone',
        7: 'Source Translation Type',
        8: 'Destination Translation Type',
        9: 'Update Description'
    }
    add_delete_actions = {
        1: 'Source Zone',
        2: 'Source Address',
        3: 'Destination Address',
        4: 'Destination Interface',
        5: 'Service',
        7: 'Tag',
        8: 'Group by Tag'
    }


    get_task = verify_selection(actions,"Input an action to perform:", False)
    if get_task in [1,2]: #Add/Remove elements
        sub_task = verify_selection(add_delete_actions, "Which element do you wish to {} rule(s):".format("add to" if get_task == 1 else "remove from"), False)

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
        xpath = device_xpath_base + 'rulebase/nat/rules'

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
        target = r['xml'].find('target')

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
                    rule_data[rule]['source-ip'] = source_translation[0].find('interface-address').find('ip').text if source_translation[0].find('interface-address').find('ip') is not None else None
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
        
        if r['xml'].find('group-tag') is not None:
            rule_data[rule]['group-tag'] = r['xml'].find('group-tag').text

        if r['xml'].find('description') is not None:
            rule_data[rule]['description'] = r['xml'].find('description').text

        if r['xml'].find('active-active-device-binding') is not None:
            rule_data[rule]['active-active-device-binding'] = r['xml'].find('active-active-device-binding').text
        
        rule_data[rule]['service'] = r['xml'].find('service').text if r['xml'].find('service') is not None else None

        rule_data[rule]['group-tag'] = r['xml'].find('group-tag').text if r['xml'].find('group-tag') is not None else ""

        rule_data[rule]['nat-type'] = r['xml'].find('nat-type').text if r['xml'].find('nat-type') is not None else ""

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

        rule_data[rule]['tag'] = []
        if tag is not None:
            for z in tag:
                rule_data[rule]['tag'].append(z.text)
        
        rule_data[rule]['target'] = {}
        if target is not None:
            rule_data[rule]['target']['targets'] = []
            for z in target:
                rule_data[rule]['target']['targets'].append(z.text)
            if target.find('negate') is not None:
                rule_data[rule]['target']['negate'] = target.find('negate').text

        r['xml'] = None

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
        # Source Zone
        if sub_task == 1:
            update_rule_zones(panx, rules, panorama, 'add', 'from', rule_data, devicegroup)
        
        # Source / Destination Address
        if sub_task in [2,3]:
            update_rule_address(panx, rules, panorama, 'add', 'source' if sub_task == 2 else 'destination', rule_data, devicegroup)
        
        # Destination Interface
        if sub_task == 4:
            update_destination_interface(panx, rules, panorama, 'set', rule_data, devicegroup)
        
        # Service
        if sub_task == 5:
            update_service(panx, rules, panorama, 'set', rule_data, devicegroup)
        # Tags
        if sub_task == 6:
            update_rule_tags(panx,rules,panorama,'add',rule_data, devicegroup)

        # Group by Tags
        if sub_task == 7:
            update_rule_group_by_tags(panx,rules,panorama,'add',rule_data, devicegroup)

    # Remove From nat Policies
    if get_task == 2: 
        # Source Zone
        if sub_task == 1:
            update_rule_zones(panx, rules, panorama, 'remove', 'from', rule_data, devicegroup)
        
        # Source / Destination Address
        if sub_task in [2,3]:
            update_rule_address(panx, rules, panorama, 'remove', 'source' if sub_task == 2 else 'destination', rule_data, devicegroup)
        
        # Destination Interface
        if sub_task == 4:
            update_destination_interface(panx, rules, panorama, 'remove', rule_data, devicegroup)
        
        # Service
        if sub_task == 5:
            update_service(panx, rules, panorama, 'remove', rule_data, devicegroup)
        
        # Tags
        if sub_task == 6:
            update_rule_tags(panx,rules,panorama,'remove',rule_data, devicegroup)

        # Group by Tags
        if sub_task == 7:
            update_rule_group_by_tags(panx,rules,panorama,'remove',rule_data, devicegroup)

    # Enable Rules
    if get_task == 3:
        enable_disable_rules(panx, rules, panorama, 'enable', devicegroup)

    #  Disable Rules    
    if get_task == 4:
        enable_disable_rules(panx, rules, panorama, 'disable', devicegroup)

    # Rename Rules
    if get_task == 5:
        rename_rules(panx, rules, panorama, rule_data, devicegroup)
    
    # Destination Zone
    if get_task == 6:
        update_rule_zones(panx, rules, panorama, 'add', 'to', rule_data, devicegroup)

    # Source Translation
    if get_task == 7:
        update_source_translation(panx, rules, panorama, rule_data, devicegroup)

    # Destination Translation
    if get_task == 8:
        update_destination_translation(panx, rules, panorama, rule_data, devicegroup)

    # Description
    if get_task == 9:
        update_description(panx, rules, panorama, rule_data, devicegroup)

    # Commit and Push
    do_commit = input("Would you like to commit? (Y/N):\n Note. this will push to all devices in selected the device group.\n ") if panorama else input("Would you like to commit? (Y/N):\n ")
    
    if len(do_commit) >= 1 and do_commit[0].lower() == 'y':
        commit(panx, panorama, devicegroup)

if __name__ == '__main__':
    print("Illegal call. Call script from pan_bulk_update.py")
    exit()
