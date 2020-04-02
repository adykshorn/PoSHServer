PoSH Server on PowerShell Core!

Just trying to get this to run in non-Windows at this point. I'm working in Ubuntu 18.04 with
Powershell 7. Once all features are functional, then I might look at making improvements.

So far have done the following to make the script work with PowerShell core:
  - Replaced backslashes in paths to forward slashes
    * Windows recognizes paths with forward slashes but, backslashes do not work in linux
  - Replaced a reference to $env:APPDATA to just use the current directory (saving logs, etc)...
  - Removed function to check if running as local admin as it is windows specific
    * Still requires running as admin, just doesn't check first.
  - Set the function that checks if the -SSLIP is an actual IP on the system to always return 
  validated for now. It relies on cmdlets that are not available in linux.
  
ISSUES

I haven't tested everything yet, but so far it's working but I haven't managed to get SSL to work.

USAGE

Edit the last line of the script to run as desired. Something along the lines of:

Start-StandalonePoSHServer -Port 80 -HomeDirectory "$HOME/www"

Looks for index.ps1 by default. HTML should be in @""@ tags. See example.ps1 for example.

For further documentation, check out the documentation from the original here:
https://github.com/yusufozturk/PoSHServer/blob/master/Documentation.pdf
