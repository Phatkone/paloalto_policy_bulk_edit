"""
Author: Phatkone
Description: Bulk update tool for Palo Alto security policies. Can be used with Panorama or the firewalls directly.
Dependencies: pan-python
Usage: `python3 pan_security_bulk_update.py` or `python3 pan_security_bulk_update.py <host ip or fqdn>`
 All inputs required are in prompt format within the script.

GNU GPL License applies.

           ,,,
          (. .)
-------ooO-(_)-Ooo-------

"""
from re import match
from re import split
from re import sub
try:
    from pan.xapi import PanXapi
    from lib.common import verify_selection
    from lib.common import commit
    from lib.common import list_to_dict
    from lib.common import panorama_xpath_templates_base
    from lib.common import device_xpath_base
except ImportError:
    print("Error importing required libraries")
    exit()

def update_int_mgmt_prof(panx: PanXapi, ints: dict, panorama: bool, action: str, template: str = "") -> None:
    if action == 'remove':
        int_selection = verify_selection(ints, "Which interfaces do you wish to remove the profile from?", True, True)
        for intf in int_selection:
            parent_intf = ""
            intf_type = sub(r'\d.+','', intf)
            print(intf_type)
            if intf_type[0:2] == 'ae':
                intf_type = 'aggregate-ethernet'
            if '.' in intf:
                parent_intf = intf.split('.')[0]
            if panorama:
                if parent_intf == "":
                    xpath = panorama_xpath_templates_base.format(template) + 'network/interface/{}/entry[@name=\'{}\']/layer3/interface-management-profile'.format(intf_type, intf)
                else:
                    xpath = panorama_xpath_templates_base.format(template) + 'network/interface/{}/entry[@name=\'{}\']/layer3/units/entry[@name=\'{}\']/interface-management-profile'.format(intf_type, parent_intf, intf)
            else:
                if parent_intf == "":
                    xpath = device_xpath_base + 'network/interface/{}/entry[@name=\'{}\']/layer3/interface-management-profile'.format(intf_type, intf)
                else:
                    xpath = device_xpath_base + 'network/interface/{}/entry[@name=\'{}\']/layer3/units/entry[@name=\'{}\']/interface-management-profile'.format(intf_type, parent_intf, intf)
            panx.delete(xpath)
        return

    profiles = {}
    if panorama: 
        xpath = panorama_xpath_templates_base.format(template) + 'network/profiles/interface-management-profile'
    else:
        xpath = device_xpath_base + 'network/profiles/interface-management-profile'
        
    #Get Profiles list for selection
    panx.get(xpath)
    xm = panx.element_result
    count = 1
    if len(xm):
        for profile in xm[0]:
            profiles[count] = profile.get('name')
            count+=1
    del count
    profile_selection = verify_selection(profiles, "Which Profile do you wish to set?:", False, True)
    int_selection = verify_selection(ints, "Which interfaces do you wish to update?", True, True)
    for intf in int_selection:
        parent_intf = ""
        intf_type = sub(r'\d.+','', intf)
        print(intf_type)
        if intf_type[0:2] == 'ae':
            intf_type = 'aggregate-ethernet'
        if '.' in intf:
            parent_intf = intf.split('.')[0]
        if panorama:
            if parent_intf == "":
                xpath = panorama_xpath_templates_base.format(template) + 'network/interface/{}/entry[@name=\'{}\']/layer3/interface-management-profile'.format(intf_type, intf)
            else:
                xpath = panorama_xpath_templates_base.format(template) + 'network/interface/{}/entry[@name=\'{}\']/layer3/units/entry[@name=\'{}\']/interface-management-profile'.format(intf_type, parent_intf, intf)
        else:
            if parent_intf == "":
                xpath = device_xpath_base + 'network/interface/{}/entry[@name=\'{}\']/layer3/interface-management-profile'.format(intf_type, intf)
            else:
                xpath = device_xpath_base + 'network/interface/{}/entry[@name=\'{}\']/layer3/units/entry[@name=\'{}\']/interface-management-profile'.format(intf_type, parent_intf, intf)
        panx.edit(xpath, "<interface-management-profile>{}</interface-management-profile>".format(profile_selection))
    return


def get_interfaces(panx: PanXapi = None, panorama: bool = False, template: str = "") -> dict:
    if panorama:
        xpath = panorama_xpath_templates_base.format(template) + 'network/interface'
    else:
        xpath = device_xpath_base + '/network/interface'
    
    # Get interfaces
    panx.get(xpath)
    xm = panx.element_result
    count = 1
    l3_ints = {}
    if len(xm):
        for t in xm[0]:
            if t.tag in ['tunnel', 'vlan', 'loopback']:
                for entry in t[0].findall('entry'):
                    l3_ints[count] = entry.get('name')
                    count += 1
            elif t.tag in ['aggregate-ethernet', 'ethernet']:
                for entry in t.findall('entry'):
                    if entry[0].tag != 'layer3':
                        continue
                    l3_ints[count] = entry.get('name')
                    count += 1
                    units = entry[0].find('units')
                    if units is not None and len(units):
                        units = units.findall('entry')
                        for unit in units:
                            l3_ints[count] = unit.get('name')
                            count += 1
    return l3_ints


#    with open('interfaces.xml','w') as f:
#        f.write(panx.xml_document)


def main(panx: PanXapi = None, panorama: bool = False) -> None:

    actions = {
        1: 'Update Interface Management Profile',
        2: 'Remove Interface Management Profile'
    }

    get_task = verify_selection(actions,"Input an action to perform:", False)
    ints = {}
    template = ""
    if panorama: 
        panx.get('/config/devices/entry/template')
        templates = {}
        templates_xml = panx.element_root.find('result')
        count = 1
        for template in templates_xml[0]:
            templates[count] = template.get("name")
            count += 1
        template = verify_selection(templates, "Which Template does the management profile belong to?:", False, True)
        del templates_xml, count, templates

    ints = get_interfaces(panx, panorama, template)

    # Update Interface Management Profile
    if get_task == 1:
        update_int_mgmt_prof(panx, ints, panorama, 'update', template)

    # Remove Interface Management Profile
    if get_task == 2: 
        update_int_mgmt_prof(panx, ints, panorama, 'remove', template)

    # Commit and Push
    #do_commit = input("Would you like to commit? (Y/N):\n Note. this will push to all devices in selected the device group.\n ") if panorama else input("Would you like to commit? (Y/N):\n ")
    
    #if len(do_commit) >= 1 and do_commit[0].lower() == 'y':
        # Get Commit Description
    #    commit(panx, panorama, devicegroup)


if __name__ == '__main__':
    print("Illegal call. Call script from pan_bulk_update.py")
    exit()