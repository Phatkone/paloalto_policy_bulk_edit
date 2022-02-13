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

from pan.xapi import PanXapi

device_xpath_base = '/config/devices/entry/vsys/entry/'
panorama_xpath_objects_base = '/config/devices/entry[@name=\'localhost.localdomain\']/device-group/entry[@name=\'{}\']/'
panorama_xpath_templates_base = '/config/devices/entry/template/entry[@name=\'{}\']/config/devices/entry[@name=\'localhost.localdomain\']/'

def list_to_dict(l: list, start: int = 1):
    return dict(zip(range(start, len(l) + start), l))


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


def verify_selection(d: dict, s: str, is_range: bool = False, return_values: bool = False, continue_on_fail: bool = False) -> (dict | list | str):
    valid_option = False
    if len(d) < 1:
        print("{}\n Oops. No options found.".format(s))
        if not continue_on_fail:
            exit(-1)
        return
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


def commit(panx: PanXapi, panorama: bool = False, devicegroup: str = "") -> None:
    from time import sleep

    commit_description = input("\n\nCommit description?: \n ")
    print("Committing...")
    # Commit to Firewall / Panorama
    panx.commit(cmd='<commit>{}</commit>'.format("<description>{}</description>".format(commit_description) if len(commit_description) > 0 else ""), sync=True, interval=2)
    
    # Push policies down to firewalls in chosen device group.
    if panorama:
        if panx.status == 'success':
            print("Commit Successful, Pushing to devices...")
            panx.commit(cmd='<commit-all><shared-policy>{}<device-group><entry name="{}"/></device-group></shared-policy></commit-all>'.format("<description>{}</description>".format(commit_description) if len(commit_description) > 0 else "", devicegroup), action='all')

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
    
    #xpath = '/config/predefined/url-categories'  # returns wrong names
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
    
    #xpath = '/config/predefined/application' # returns wrong names
    #xapi.get(xpath)
    xapi.op(cmd="<show><predefined><xpath>/predefined/application</xpath></predefined></show>")
    xm = xapi.element_root.find('result')
    if len(xm):
        for app in xm[0]:
            applications.append(app.get('name'))
    
    return applications


def get_profiles(xapi: PanXapi, panorama: bool = False, devicegroup: str = "", profile_type: str = "") -> (list | dict):
    types = [
        'groups',
        'virus',
        'vulnerability',
        'spyware',
        'url-filtering',
        'file-blocking',
        'data-filtering',
        'wildfire-analysis',
        'all-profiles'
    ]
    if profile_type not in types:
        raise Exception("Invalid profile type provided: {}\n Profile type must be one of the following: \n- {}".format(profile_type, "\n- ".join(types)))

    dg_stack = get_device_group_stack(xapi) if panorama else {}
    dg_list = get_parent_dgs(xapi, devicegroup, dg_stack)
    profiles = {} if profile_type == 'all-profiles' else []

    sub_xpath = 'profile-group' if profile_type == 'groups' else 'profiles/{}'.format(profile_type)
    if profile_type == 'all-profiles':
        sub_xpath = 'profiles'
        types.remove('groups')
        types.remove('all-profiles')
        for t in types:
            profiles[t] = []
    
    if len(dg_list) > 0 and devicegroup != "":
        for dg in dg_list:
            xpath = '/config/devices/entry[@name="localhost.localdomain"]/device-group/entry[@name="{}"]/{}'.format(dg, sub_xpath) if panorama else '/config/devices/entry/vsys/entry/{}'.format(sub_xpath)
            xapi.get(xpath)
            xm = xapi.element_root.find('result')
            if len(xm):
                if profile_type == 'all-profiles':
                    for t in types:
                        element = xm[0].find(t)
                        if element is not None and len(element):
                            for e in element:
                                if e.get('name') not in profiles[t]:
                                    profiles[t].append(e.get('name'))
                else:
                    for p in xm[0]:
                        if (p.get('name') not in profiles and profile_type in ['groups','data-filtering']) or (p.text not in profiles and profile_type != 'groups'):
                            profiles.append(p.text if profile_type not in ['groups','data-filtering'] else p.get('name'))
    
    if devicegroup not in dg_list or not panorama:
        xpath = '/config/devices/entry[@name="localhost.localdomain"]/device-group/entry[@name="{}"]/{}'.format(dg, sub_xpath) if panorama else '/config/devices/entry/vsys/entry/{}'.format(sub_xpath)
        xapi.get(xpath)
        xm = xapi.element_root.find('result')
        if len(xm):
            if profile_type == 'all-profiles':
                for t in types:
                    element = xm[0].find(t)
                    if element is not None and len(element):
                        for e in element:
                            if e.get('name') not in profiles[t]:
                                profiles[t].append(e.get('name'))
            else:
                for p in xm[0]:
                    if (p.get('name') not in profiles and profile_type in ['groups','data-filtering']) or (p.text not in profiles and profile_type != 'groups'):
                        profiles.append(p.text if profile_type not in ['groups','data-filtering'] else p.get('name'))

    xpath = '/config/predefined/{}'.format(sub_xpath)
    xapi.get(xpath)
    xm = xapi.element_root.find('result')
    if len(xm):
        if profile_type == 'all-profiles':
            for t in types:
                element = xm[0].find(t)
                if element is not None and len(element):
                    for e in element:
                        if e.get('name') not in profiles[t]:
                            profiles[t].append(e.get('name'))
        else:
            for p in xm[0]:
                if p.get('name') not in profiles:
                    profiles.append(p.get('name'))

    return profiles


def get_interfaces(panx: PanXapi, panorama: bool = False, template: str = "") -> dict:
    if template == "" and panorama:
        raise Exception("Invalid template '{}'".format(template))
    
    interfaces = {}
    # Get template if Panorama
    if panorama: 
        xpath =  panorama_xpath_templates_base.format(template) + 'network/interface'
    else:
        xpath = device_xpath_base + 'network/interface'

    panx.get(xpath)
    xm = panx.element_root.find('result')

    for interface_type in xm[0]:
        for interface in interface_type:
            interfaces[interface.get('name')] = {}
            interfaces[interface.get('name')]['type'] = interface[1].tag
            if interface.find('layer3') is not None and interface.find('layer3').find('ip') is not None:
                interfaces[interface.get('name')]['ip'] = []
                for ip in interface.find('layer3').find('ip'):
                    interfaces[interface.get('name')]['ip'].append(ip.get('name'))

    return interfaces


def get_services(panx: PanXapi, panorama: bool, devicegroup: str) -> dict:
    services = {}
    dg_stack = get_device_group_stack(panx) if panorama else {}
    dg_list = get_parent_dgs(panx, devicegroup, dg_stack)
    count = 1
    
    if len(dg_list) > 0 and devicegroup != "":
        for dg in dg_list:
            #Get service list for selection
            xpath = panorama_xpath_objects_base.format(devicegroup) + 'service'.format(dg)
            panx.get(xpath)
            xm = panx.element_root.find('result')
            if len(xm):
                for service in xm[0]:
                    services[count] = service.get('name')
                    count+=1
            #Get service groups list for selection
            xpath = panorama_xpath_objects_base.format(devicegroup) + 'service-group'.format(dg)
            panx.get(xpath)
            xm = panx.element_root.find('result')
            if len(xm):
                for service_group in xm[0]:
                    services[count] = service_group.get('name')
                    count+=1
    
    if devicegroup not in dg_list or not panorama:
        #Get service list for selection
        xpath = panorama_xpath_objects_base.format(devicegroup) + 'service'.format(devicegroup) if panorama else device_xpath_base + 'service'
        panx.get(xpath)
        xm = panx.element_root.find('result')
        if len(xm):
            for service in xm[0]:
                services[count] = service.get('name')
                count+=1
        #Get service groups list for selection
        xpath = panorama_xpath_objects_base.format(devicegroup) + 'service-group'.format(devicegroup) if panorama else device_xpath_base + 'service-group'
        panx.get(xpath)
        xm = panx.element_root.find('result')
        if len(xm):
            for service_group in xm[0]:
                services[count] = service_group.get('name')
                count+=1
            
    if panorama: 
        #get services from 'Shared'
        xpath = '/config/shared/service'
        panx.get(xpath)
        xm = panx.element_root.find('result')
        if len(xm):
            for service in xm[0]:
                services[count] = service.get('name')
                count+=1
        #get services from 'predefined'
        xpath = '/config/predefined/service'
        panx.get(xpath)
        xm = panx.element_root.find('result')
        if len(xm):
            for service in xm[0]:
                services[count] = service.get('name')
                count+=1
    return services


def get_address_objects(panx: PanXapi, panorama: bool, devicegroup: str, include_groups: bool = False) -> dict:
    address_objects = {}
    dg_stack = get_device_group_stack(panx) if panorama else {}
    dg_list = get_parent_dgs(panx, devicegroup, dg_stack)
    count = 1
    
    if len(dg_list) > 0 and devicegroup != "":
        for dg in dg_list:
            #Get address list for selection
            xpath = panorama_xpath_objects_base.format(devicegroup) + 'address'.format(dg)
            panx.get(xpath)
            xm = panx.element_root.find('result')
            if len(xm):
                for address in xm[0]:
                    address_objects[count] = address.get('name')
                    count+=1
            #Get address groups list for selection
            if include_groups:
                xpath = panorama_xpath_objects_base.format(devicegroup) + 'address-group'.format(dg)
                panx.get(xpath)
                xm = panx.element_root.find('result')
                if len(xm):
                    for address_group in xm[0]:
                        address_objects[count] = address_group.get('name')
                        count+=1
    
    if devicegroup not in dg_list or not panorama:
        #Get address list for selection
        xpath = panorama_xpath_objects_base.format(devicegroup) + 'address'.format(devicegroup) if panorama else device_xpath_base + 'address'
        panx.get(xpath)
        xm = panx.element_root.find('result')
        if len(xm):
            for address in xm[0]:
                address_objects[count] = address.get('name')
                count+=1
        if include_groups:
            #Get address groups list for selection
            xpath = panorama_xpath_objects_base.format(devicegroup) + 'address-group'.format(devicegroup) if panorama else device_xpath_base + 'address-group'
            panx.get(xpath)
            xm = panx.element_root.find('result')
            if len(xm):
                for address_group in xm[0]:
                    address_objects[count] = address_group.get('name')
                    count+=1
            
    if panorama: 
        #get address from 'Shared'
        xpath = '/config/shared/address'
        panx.get(xpath)
        xm = panx.element_root.find('result')
        if len(xm):
            for address in xm[0]:
                address_objects[count] = address.get('name')
                count+=1
        
        if include_groups:
            #get address groups from 'Shared'
            xpath = '/config/shared/address-group'
            panx.get(xpath)
            xm = panx.element_root.find('result')
            if len(xm):
                for address in xm[0]:
                    address_objects[count] = address.get('name')
                    count+=1
                    
        #get address from 'predefined'
        xpath = '/config/predefined/address'
        panx.get(xpath)
        xm = panx.element_root.find('result')
        if len(xm):
            for address in xm[0]:
                address_objects[count] = address.get('name')
                count+=1
    return address_objects
