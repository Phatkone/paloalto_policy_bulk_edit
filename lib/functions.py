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

from email.mime import application
from pan.xapi import PanXapi

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


def verify_selection(d: dict, s: str, is_range: bool = False, return_values: bool = False) -> ( dict | list | str):
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
                if return_values:
                    return list(d.values())
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
    if return_values:
        if not is_range:
            return d[ret]
        else:
            return list(ret.values())
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

def get_url_categories(xapi: PanXapi, devicegroup: str, panorama: bool = False) -> list:
    dg_stack = get_device_group_stack(xapi) if panorama else {}
    dg_list = get_parent_dgs(xapi, devicegroup, dg_stack)
    categories = []
    
    if len(dg_list) > 0 and devicegroup != "":
        for dg in dg_list:
            xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/profiles/custom-url-category'.format(dg)
            xapi.get(xpath)
            xm = xapi.element_root.find('result')
            if len(xm):
                for cat in xm[0]:
                    categories.append(cat.get('name'))
    
    if devicegroup not in dg_list or not panorama:
        xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/profiles/custom-url-category'.format(devicegroup) if panorama else '/config/devices/entry/vsys/entry/profiles/custom-url-category'
        #Get tag list for selection
        xapi.get(xpath)
        xm = xapi.element_root.find('result')
        if len(xm):
            for cat in xm[0]:
                categories.append(cat.get('name'))
    
    #xpath = '/config/predefined/url-categories'
    #xapi.get(xpath)
    xapi.op(cmd="<show><predefined><xpath>/predefined/pan-url-categories</xpath></predefined></show>")
    xm = xapi.element_root.find('result')
    if len(xm):
        for cat in xm[0]:
            categories.append(cat.get('name'))
    
    return categories

def get_applications(xapi: PanXapi, devicegroup: str, panorama: bool = False) -> list:
    dg_stack = get_device_group_stack(xapi) if panorama else {}
    dg_list = get_parent_dgs(xapi, devicegroup, dg_stack)
    applications = []
    
    if len(dg_list) > 0 and devicegroup != "":
        # Applications
        for dg in dg_list:
            xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/application'.format(dg)
            xapi.get(xpath)
            xm = xapi.element_root.find('result')
            if len(xm):
                for app in xm[0]:
                    applications.append(app.get('name'))
        # Application Groups
        for dg in dg_list:
            xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/application-group'.format(dg)
            xapi.get(xpath)
            xm = xapi.element_root.find('result')
            if len(xm):
                for app in xm[0]:
                    applications.append(app.get('name'))
    
    if devicegroup not in dg_list or not panorama:
        # Applications
        xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/application'.format(devicegroup) if panorama else '/config/devices/entry/vsys/entry/application'
        #Get tag list for selection
        xapi.get(xpath)
        xm = xapi.element_root.find('result')
        if len(xm):
            for app in xm[0]:
                applications.append(app.get('name'))
        # Application Groups
        xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/application-group'.format(devicegroup) if panorama else '/config/devices/entry/vsys/entry/application-group'
        #Get tag list for selection
        xapi.get(xpath)
        xm = xapi.element_root.find('result')
        if len(xm):
            for app in xm[0]:
                applications.append(app.get('name'))
    
    #xpath = '/config/predefined/application'
    #xapi.get(xpath)
    xapi.op(cmd="<show><predefined><xpath>/predefined/application</xpath></predefined></show>")
    xm = xapi.element_root.find('result')
    if len(xm):
        for app in xm[0]:
            applications.append(app.get('name'))
    
    return applications