# Bulk Update tool for Palo Alto Firewall and Panorama policies

## Purpose
With this tool you can update multiple security or NAT policies at once. For Panorama usage, it will only work on all rules within one device group.
Only one change can be made per run (I.E. add source zone to all at once).
Work is still in progress, once I have all functionality 100% then I will refactor the code to make it cleaner and more logical.


## Requirements
This script has been built for python3. No testing has been performed on python2 and as such is not supported.  
The following pip packages are included for operation:
 - pan-python


## Usage
Call pan_bulk_update.py to execute.  
Positional argument for the host device is also accepted in hostname or IP address format (I.E. `python3 pan_bulk_update.py firewall.local.domain`).
The script will prompt through the steps.
The script will prompt for username and password, from which, it will generate the API key and provide an opportunity to save the key for future use.
The key is stored in a named file (i.e. `.192-168-0-1` or `.firewall.local.domain`). 
The key is not stored in plain text but I have made **no** effort to provide adequate encryption so store the key at your own risk, use some logic about where it is running from.
After all changes have been made, the script will prompt for a commit/commit&push. 
Ensure you validate the changes before committing as I take no responsibility for someone taking their firewalls down.


## License
[GNU GPL 3.0](LICENSE) License applies.

## Author
Craig B. [Phatkone](https://github.com/Phatkone)
```
           ,,,
          (. .)
-------ooO-(_)-Ooo-------
```