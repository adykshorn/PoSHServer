# Copyright (C) 2014 Yusuf Ozturk
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

function Start-StandalonePoSHServer {

<#
    .SYNOPSIS
     
        Powershell Web Server to serve HTML and Powershell web contents.
 
    .DESCRIPTION
     
        Listens a port to serve web content. Supports HTML and Powershell.
    
    .PARAMETER  WhatIf
     
        Display what would happen if you would run the function with given parameters.
    
    .PARAMETER  Confirm
     
        Prompts for confirmation for each operation. Allow user to specify Yes/No to all option to stop prompting.
    
    .EXAMPLE
     
        Start-PoSHServer -IP 127.0.0.1 -Port 8080
		
    .EXAMPLE
     
        Start-PoSHServer -Hostname "poshserver.net" -Port 8080
		
    .EXAMPLE
     
        Start-PoSHServer -Hostname "poshserver.net" -Port 8080 -asJob
		
    .EXAMPLE
     
        Start-PoSHServer -Hostname "poshserver.net" -Port 8080 -SSL -SSLPort 8443 -asJob
		
    .EXAMPLE
     
        Start-PoSHServer -Hostname "poshserver.net" -Port 8080 -SSL -SSLIP "127.0.0.1" -SSLPort 8443 -asJob
		
    .EXAMPLE
     
        Start-PoSHServer -Hostname "poshserver.net" -Port 8080 -DebugMode
		
    .EXAMPLE
     
        Start-PoSHServer -Hostname "poshserver.net,www.poshserver.net" -Port 8080
		
    .EXAMPLE
     
        Start-PoSHServer -Hostname "poshserver.net,www.poshserver.net" -Port 8080 -HomeDirectory "C:/inetpub/wwwroot"
		
    .EXAMPLE
     
        Start-PoSHServer -Hostname "poshserver.net,www.poshserver.net" -Port 8080 -HomeDirectory "C:/inetpub/wwwroot" -LogDirectory "C:/inetpub/wwwroot"
		
    .EXAMPLE
     
        Start-PoSHServer -Hostname "poshserver.net" -Port 8080 -CustomConfig "C:/inetpub/config.ps1" -CustomJob "C:/inetpub/job.ps1"

    .INPUTS
    
        None
 
    .OUTPUTS
 
        None
	
    .NOTES
    
        Author: Yusuf Ozturk
        Website: http://www.yusufozturk.info
        Email: yusuf.ozturk@outlook.com
        Date created: 09-Oct-2011
        Last modified: 07-Apr-2014
        Version: 3.7
 
    .LINK
    
        http://www.poshserver.net
		
#>
 
[CmdletBinding(SupportsShouldProcess = $true)]
param (

    # Hostname
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'IP Address or Hostname')]
	[Alias('IP')]
    [string]$Hostname,
	
    # Port Number
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Port Number')]
    [string]$Port,
	
    # SSL IP Address
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'SSL IP Address')]
    [string]$SSLIP,
	
    # SSL Port Number
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'SSL Port Number')]
    [string]$SSLPort,
	
    # SSL Port Number
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'SSL Friendly Name. Example: poshserver.net')]
    [string]$SSLName,
	
    # Home Directory
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Home Directory. Example: C:/inetpub/wwwroot')]
    [string]$HomeDirectory,
	
    # Log Directory
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Log Directory. Example: C:/inetpub/wwwroot')]
    [string]$LogDirectory,

    # Custom Config Path    
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Custom Config Path. Example: C:/inetpub/config.ps1')]
    [string]$CustomConfig,

    # Custom Child Config Path
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Custom Child Config Path. Example: C:/inetpub/childconfig.ps1')]
    [string]$CustomChildConfig,

    # Custom Job Path    
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Custom Job Path. Example: C:/inetpub/jobs.ps1')]
    [string]$CustomJob,
	
    # Custom Job Schedule
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Custom Job Schedule. Example: 1, 5, 10, 20, 30, 60')]
		[ValidateSet("1","5","10","20","30","60")] 
    [string]$CustomJobSchedule = "5",
	
    # Background Job ID
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Background Job ID. Example: 52341')]
    [string]$JobID,

    # Background Job Username
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Background Job Username. Example: CONTOSO\Administrator')]
    [string]$JobUsername,
	
    # Background Job User Password
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Background Job User Password. Example: P@ssw0rd1')]
    [string]$JobPassword,
	
    # Background Job Credentials
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Run Background Job as Different User')]
    [switch]$JobCredentials = $false,
	
    # Enable SSL
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Enable SSL')]
    [switch]$SSL = $false,

    # Debug Mode
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Debug Mode')]
    [switch]$DebugMode = $false,
	
    # Background Job
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Run As Background Job')]
    [switch]$asJob = $false
)
	
	# Enable Debug Mode
	if ($DebugMode)
	{
		$DebugPreference = "Continue"
	}
	else
	{
		$ErrorActionPreference = "silentlycontinue"
	}
	
	# PoSH Server Configuration
	$PoSHConfigPath = [System.IO.Directory]::GetCurrentDirectory() + "/config.ps1"
	
	# Test Config Path
	$TestPoSHConfigPath = Test-Path $PoSHConfigPath
	
	if (!$TestPoSHConfigPath)
	{
		# Default Document
		$DefaultDocument = "index.ps1"

		# Log Schedule
		# Options: Hourly, Daily
		$LogSchedule = "Daily"

		# Basic Authentication
		# Options: On, Off
		$BasicAuthentication = "Off"

		# Windows Authentication
		# Options: On, Off
		$WindowsAuthentication = "Off"

		# DirectoryBrowsing
		# Options: On, Off
		$DirectoryBrowsing = "Off"

		# IP Restriction
		# Options: On, Off
		$IPRestriction = "Off"
		$IPWhiteList = "::1 127.0.0.1"

		# Content Filtering
		# Options: On, Off
		$ContentFiltering = "Off"
		$ContentFilterBlackList = "audio/mpeg video/mpeg"

		# PHP Cgi Path
		$PHPCgiPath = ($env:PATH).Split(";") | Select-String "PHP"
		$PHPCgiPath = [string]$PHPCgiPath + "/php-cgi.exe"
	}
	else
	{
		. $PoSHConfigPath
	}
			
	# Get PoSH Server Module Path
	$ModulePath = [System.IO.Directory]::GetCurrentDirectory() + "/PoSHServer"
	
	# Test Default Module Path
	$ModulePathTest = Test-Path $ModulePath
	
	if ($ModulePathTest)
	{
		$PoSHModulePath = $ModulePath
	}
	else
	{	
		if ($ModulePath -ne $Null)
		{
			# Create Module Folder
			$NewModuleFolder = New-Item -Path "$ModulePath" -ItemType Directory
			
			# Create Job Folder
			$NewJobFolder = New-Item -Path "$ModulePath/jobs" -ItemType Directory
			
			# Create Log Folder
			$NewLogFolder = New-Item -Path "$ModulePath/logs" -ItemType Directory
			
			# Set Module Folder
			$PoSHModulePath = $ModulePath
		}
	}
	
	if (!$PoSHModulePath)
	{
		Write-Warning "Could not create PoSH Server Module Path."
		Write-Warning "Aborting.."
		
		$ResultCode = "-1"
		$ResultMessage = "Could not create PoSH Server Module Path."
	}
	
	# Background Job ID
	if ($JobID -and $ResultCode -ne "-1")
	{
		$JobIDPath = "$PoSHModulePath/jobs/job-$JobID.txt"
		$TestJobID = Test-Path $JobIDPath
		if ($JobIDPath)
		{
			$JobIDContent = Get-Content $JobIDPath
			$Hostname = $JobIDContent.Split(";")[0]
			$Port = $JobIDContent.Split(";")[1]
			$SSLIP = $JobIDContent.Split(";")[2]
			$SSLPort = $JobIDContent.Split(";")[3]
			$SSLName = $JobIDContent.Split(";")[4]
			$HomeDirectory = $JobIDContent.Split(";")[5]
			$LogDirectory = $JobIDContent.Split(";")[6]
			$CustomConfig = $JobIDContent.Split(";")[7]
			$CustomChildConfig = $JobIDContent.Split(";")[8]
			$CustomJob = $JobIDContent.Split(";")[9]
		}
		else
		{
			Write-Warning "Job ID is not exist."
			Write-Warning "Aborting.."

			$ResultCode = "-1"
			$ResultMessage = "Job ID is not exist."
		}
	}
	
	# Get Home and Log Directories
	if (!$HomeDirectory) 
	{ 
		$HomeDirectory = [System.IO.Directory]::GetCurrentDirectory() + "/http"
		
		# Test Home Directory Path
		$TestHomeDirectory = Test-Path $HomeDirectory
	
		if (!$TestHomeDirectory)
		{
			$HomeDirectory = [System.IO.Directory]::GetCurrentDirectory()
		}
	}
	
	if (!$LogDirectory) 
	{ 
		$LogDirectory = [System.IO.Directory]::GetCurrentDirectory() + "/logs"
		
		# Test Log Directory Path
		$TestLogDirectory = Test-Path $LogDirectory
	
		if (!$TestLogDirectory)
		{
			$LogDirectory = $PoSHModulePath + "/logs"
		}
	}
	
	# Import PoSH Server Functions

	function Confirm-PoSHServerIP {

	<#
		.SYNOPSIS
		 
			Function to verify IP address on server

		.EXAMPLE
		 
			Confirm-PoSHServerIP -IP "192.168.2.1"
			
	#>
	
	# Commenting out the below because it relies on WMI. That ain't going to work in non-windows.
	# For now just setting the result to always be "Validated"

	<#[CmdletBinding(SupportsShouldProcess = $true)]
	param (

		[Parameter(
			Mandatory = $true,
			HelpMessage = 'IP address')]
		[string]$IP
	)

		# Get Networking Adapter Configuration 
		$IPConfigs = Get-WmiObject Win32_NetworkAdapterConfiguration
	   
		# Get All IP Addresses 
		foreach ($IPConfig in $IPConfigs) 
		{ 
			if ($IPConfig.IPaddress) 
			{ 
				foreach ($IPAddress in $IPConfig.IPaddress) 
				{ 
					if ("$IP" -eq "$IPAddress")
					{
						$Result = "Validated"
					}
				}
			}
		}
		#>

		$Result = "Validated"
		$Result
	}

	function Get-DirectoryContent {

	<#
		.SYNOPSIS
		 
			Function to get directory content

		.EXAMPLE
		 
			Get-DirectoryContent -Path "C:/" -HeaderName "poshserver.net" -RequestURL "http://poshserver.net" -SubfolderName "/"
			
	#>

	[CmdletBinding(SupportsShouldProcess = $true)]
	param (

		[Parameter(
			Mandatory = $true,
			HelpMessage = 'Directory Path')]
		[string]$Path,

		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Header Name')]
		[string]$HeaderName,

		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Request URL')]
		[string]$RequestURL,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Subfolder Name')]
		[string]$SubfolderName
	)
		
		$NotSupported = "Sorry, Directory Browsing is not supported in Standalone Mode"
		$NotSupported
	}

	function New-PoSHLogHash {

	<#
		.SYNOPSIS
		 
			Function to hash PoSHServer log file

		.EXAMPLE
		 
			New-PoSHLogHash -LogSchedule "Hourly" -LogDirectory "C:/inetpub/logs"
			
	#>

	[CmdletBinding(SupportsShouldProcess = $true)]
	param (

		[Parameter(
			Mandatory = $true,
			HelpMessage = 'Log Schedule')]
		[string]$LogSchedule,

		[Parameter(
			Mandatory = $true,
			HelpMessage = 'Log Directory Path')]
		[string]$LogDirectory,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Debug Mode')]
		$DebugMode = $false
	)

		if ($LogSchedule -eq "Hourly")
		{
			$LogNameFormatLastHour = (Get-Date).AddHours(-1).ToString("yyMMddHH")
			$LogFileNameLastHour = "u_ex" + $LogNameFormatLastHour + ".log"
			$LogFilePathLastHour = $LogDirectory + "/" + $LogFileNameLastHour
			$SigFileName = "u_ex" + $LogNameFormatLastHour + ".sign"
			$SigFilePath = $LogDirectory + "/" + $SigFileName
			$DateFileName = "u_ex" + $LogNameFormatLastHour + ".date"
			$DateFilePath = $LogDirectory + "/" + $DateFileName
			$LastLogFilePath = $LogFilePathLastHour
		}
		else
		{
			$LogNameFormatYesterday = (Get-Date).AddDays(-1).ToString("yyMMdd")
			$LogFileNameYesterday = "u_ex" + $LogNameFormatYesterday + ".log"
			$LogFilePathYesterday = $LogDirectory + "/" + $LogFileNameYesterday
			$SigFileName = "u_ex" + $LogNameFormatYesterday + ".sign"
			$SigFilePath = $LogDirectory + "/" + $SigFileName
			$DateFileName = "u_ex" + $LogNameFormatYesterday + ".date"
			$DateFilePath = $LogDirectory + "/" + $DateFileName
			$LastLogFilePath = $LogFilePathYesterday
		}

		if ([System.IO.File]::Exists($LastLogFilePath))  
		{
			if (![System.IO.File]::Exists($SigFilePath))
			{
				$LogHashJobArgs = @($LastLogFilePath,$SigFilePath,$DateFilePath)
				
				try
				{
					$LogHashJob = Start-Job -ScriptBlock {
						param ($LastLogFilePath, $SigFilePath, $DateFilePath)
						if (![System.IO.File]::Exists($DateFilePath))  
						{
							$HashAlgorithm = "MD5"
							$HashType = [Type] "System.Security.Cryptography.$HashAlgorithm"
							$Hasher = $HashType::Create()
							$DateString = Get-Date -uformat "%d.%m.%Y"
							$TimeString = (w32tm /stripchart /computer:time.ume.tubitak.gov.tr /samples:1)[-1].split("")[0]
							$DateString = $DateString + " " + $TimeString
							$InputStream = New-Object IO.StreamReader $LastLogFilePath
							$HashBytes = $Hasher.ComputeHash($InputStream.BaseStream)
							$InputStream.Close()
							$Builder = New-Object System.Text.StringBuilder
							$HashBytes | Foreach-Object { [void] $Builder.Append($_.ToString("X2")) }
							$HashString = $Builder.ToString()
							$HashString = $HashString + " " + $DateString
							$Stream = [System.IO.StreamWriter]$SigFilePath
							$Stream.Write($HashString)
							$Stream.Close()
							$Stream = [System.IO.StreamWriter]$DateFilePath
							$Stream.Write($DateString)
							$Stream.Close()
							$InputStream = New-Object IO.StreamReader $SigFilePath
							$HashBytes = $Hasher.ComputeHash($InputStream.BaseStream)
							$InputStream.Close()
							$Builder = New-Object System.Text.StringBuilder
							$HashBytes | Foreach-Object { [void] $Builder.Append($_.ToString("X2")) }
							$HashString = $Builder.ToString()
							$Stream = [System.IO.StreamWriter]$SigFilePath
							$Stream.Write($HashString)
							$Stream.Close()
						}
					} -ArgumentList $LogHashJobArgs	
				}
				catch
				{
					Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
				}
			}
		}
		else
		{
			Add-Content -Value "Could not find log file." -Path "$LogDirectory/debug.txt"
		}
	}

	function Start-PoSHLogParser {

	<#
		.SYNOPSIS
		 
			Function to parse PoSHServer log files

		.EXAMPLE
		 
			Start-PoSHLogParser -LogPath "C:/inetpub/logs/hourly.log"
			
	#>

	[CmdletBinding(SupportsShouldProcess = $true)]
	param (

		[Parameter(
			Mandatory = $true,
			HelpMessage = 'Log Path')]
		[string]$LogPath
	)

		$File = $LogPath
		$Log = Get-Content $File | where {$_ -notLike "#[D,S-V]*" }
		$Columns = (($Log[0].TrimEnd()) -replace "#Fields: ", "" -replace "-","" -replace "/(","" -replace "/)","").Split(" ")
		$Count = $Columns.Length
		$Rows = $Log | where {$_ -notLike "#Fields"}
		$IISLog = New-Object System.Data.DataTable "IISLog"
		foreach ($Column in $Columns) 
		{
			$NewColumn = New-Object System.Data.DataColumn $Column, ([string])
			$IISLog.Columns.Add($NewColumn)
		}
		foreach ($Row in $Rows) 
		{
			$Row = $Row.Split(" ")
			$AddRow = $IISLog.newrow()
			for($i=0;$i -lt $Count; $i++) 
			{
				$ColumnName = $Columns[$i]
				$AddRow.$ColumnName = $Row[$i]
			}
			$IISLog.Rows.Add($AddRow)
		}
		$IISLog
	}

	function Get-MimeType {

	<#
		.SYNOPSIS
		 
			Function to get mime types

		.EXAMPLE
		 
			Get-MimeType -Extension ".jpg"
			
	#>

	[CmdletBinding(SupportsShouldProcess = $true)]
	param (

		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Extension')]
		[string]$Extension
	)
		
		switch ($Extension) 
		{ 
			.ps1 {"text/ps1"}
			.psxml {"text/psxml"}
			.psapi {"text/psxml"}
			.posh {"text/psxml"}
			.html {"text/html"} 
			.htm {"text/html"} 
			.php {"text/php"} 
			.css {"text/css"} 
			.jpeg {"image/jpeg"} 
			.jpg {"image/jpeg"}
			.gif {"image/gif"}
			.ico {"image/x-icon"}
			.flv {"video/x-flv"}
			.swf {"application/x-shockwave-flash"}
			.js {"text/javascript"}
			.txt {"text/plain"}
			.rar {"application/octet-stream"}
			.zip {"application/x-zip-compressed"}
			.rss {"application/rss+xml"}
			.xml {"text/xml"}
			.pdf {"application/pdf"}
			.png {"image/png"}
			.mpg {"video/mpeg"}
			.mpeg {"video/mpeg"}
			.mp3 {"audio/mpeg"}
			.oga {"audio/ogg"}
			.spx {"audio/ogg"}
			.mp4 {"video/mp4"}
			.m4v {"video/m4v"}
			.ogg {"video/ogg"}
			.ogv {"video/ogg"}
			.webm {"video/webm"}
			.wmv {"video/x-ms-wmv"}
			.woff {"application/x-font-woff"}
			.eot {"application/vnd.ms-fontobject"}
			.svg {"image/svg+xml"}
			.svgz {"image/svg+xml"}
			.otf {"font/otf"}
			.ttf {"application/x-font-ttf"}
			.xht {"application/xhtml+xml"}
			.xhtml {"application/xhtml+xml"}
			default {"text/html"}
		}	
	}

	function Get-PoSHPHPContent {

	<#
		.SYNOPSIS
		 
			Function to get php content

		.EXAMPLE
		 
			Get-PoSHPHPContent -PHPCgiPath "C:/php.exe" -File "C:/test.php" -PoSHPHPGET "test=value"
			
		.EXAMPLE
		 
			Get-PoSHPHPContent -PHPCgiPath "C:/php.exe" -File "C:/test.php" -PoSHPHPPOST "test=value"
			
	#>

	[CmdletBinding(SupportsShouldProcess = $true)]
	param (

		[Parameter(
			Mandatory = $true,
			HelpMessage = 'PHP-Cgi Path')]
		[string]$PHPCgiPath,

		[Parameter(
			Mandatory = $true,
			HelpMessage = 'File Path')]
		[string]$File,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'PHP GET String')]
		[string]$PoSHPHPGET,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'PHP POST String')]
		[string]$PoSHPHPPOST
	)

		# Set PHP Environment
		$env:GATEWAY_INTERFACE="CGI/1.1"
		$env:SCRIPT_FILENAME="$File"
		$env:REDIRECT_STATUS="200"
		$env:SERVER_PROTOCOL="HTTP/1.1"
		$env:HTTP_ACCEPT="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$env:CONTENT_TYPE="application/x-www-form-urlencoded"
		
		if ($PoSHPHPPOST)
		{
			# Set PHP POST Environment
			$env:REQUEST_METHOD="POST"
			$PHP_CONTENT_LENGTH = $PoSHPHPPOST.Length
			$env:CONTENT_LENGTH="$PHP_CONTENT_LENGTH"
			
			# Get PHP Content
			$PHPOutput = "$PoSHPHPPOST" | &$PHPCgiPath
		}
		else
		{
			# Set PHP GET Environment
			$env:REQUEST_METHOD="GET"
			$env:QUERY_STRING="$PoSHPHPGET"
			
			# Get PHP Content
			$PHPOutput = &$PHPCgiPath
		}
		
		# Get PHP Header Line Number
		$PHPHeaderLineNumber = ($PHPOutput | Select-String -Pattern "^$")[0].LineNumber
		
		# Get PHP Header
		$PHPHeader = $PHPOutput | Select -First $PHPHeaderLineNumber
		
		# Get Redirection Location
		$GetPHPLocation = $PHPHeader | Select-String "Location:"
		
		# Check Redirection Location
		if ($GetPHPLocation)
		{
			$GetPHPLocation = $GetPHPLocation -match 'Location: (.*)/?'
			if ($GetPHPLocation -eq $True) { $PHPRedirectionURL = $Matches[1] } else { $PHPRedirectionURL = $Null; }
		}
		
		# Redirect to Location
		if ($PHPRedirectionURL)
		{
			# Redirection Output
			$PHPRedirection = '<html>'
			$PHPRedirection += '<script type="text/javascript">'
			$PHPRedirection += 'window.location = "' + $PHPRedirectionURL + '"'
			$PHPRedirection += '</script>'
			$PHPRedirection += '</html>'
			$PHPRedirection
		}
		else
		{	
			# Output PHP Content
			$PHPOutput = $PHPOutput | Select -Skip $PHPHeaderLineNumber
			$PHPOutput
		}
	}

	function Get-PoSHPostStream {

	<#
		.SYNOPSIS
		 
			Function to get php post stream

		.EXAMPLE
		 
			Get-PoSHPostStream -InputStream $InputStream -ContentEncoding $ContentEncoding
			
	#>

	[CmdletBinding(SupportsShouldProcess = $true)]
	param (

		[Parameter(
			Mandatory = $true,
			HelpMessage = 'Input Stream')]
		$InputStream,
		
		[Parameter(
			Mandatory = $true,
			HelpMessage = 'Content Encoding')]
		$ContentEncoding
	)

		$PoSHCommand = New-Object IO.StreamReader ($InputStream,$ContentEncoding)
		$PoSHCommand = $PoSHCommand.ReadToEnd()
		$PoSHCommand = $PoSHCommand.ToString()
		
		if ($PoSHCommand)
		{
			$PoSHCommand = $PoSHCommand.Replace("+"," ")
			$PoSHCommand = $PoSHCommand.Replace("%20"," ")
			$PoSHCommand = $PoSHCommand.Replace("%21","!")
			$PoSHCommand = $PoSHCommand.Replace('%22','"')
			$PoSHCommand = $PoSHCommand.Replace("%23","#")
			$PoSHCommand = $PoSHCommand.Replace("%24","$")
			$PoSHCommand = $PoSHCommand.Replace("%25","%")
			$PoSHCommand = $PoSHCommand.Replace("%27","'")
			$PoSHCommand = $PoSHCommand.Replace("%28","(")
			$PoSHCommand = $PoSHCommand.Replace("%29",")")
			$PoSHCommand = $PoSHCommand.Replace("%2A","*")
			$PoSHCommand = $PoSHCommand.Replace("%2B","+")
			$PoSHCommand = $PoSHCommand.Replace("%2C",",")
			$PoSHCommand = $PoSHCommand.Replace("%2D","-")
			$PoSHCommand = $PoSHCommand.Replace("%2E",".")
			$PoSHCommand = $PoSHCommand.Replace("%2F","/")
			$PoSHCommand = $PoSHCommand.Replace("%3A",":")
			$PoSHCommand = $PoSHCommand.Replace("%3B",";")
			$PoSHCommand = $PoSHCommand.Replace("%3C","<")
			$PoSHCommand = $PoSHCommand.Replace("%3E",">")
			$PoSHCommand = $PoSHCommand.Replace("%3F","?")
			$PoSHCommand = $PoSHCommand.Replace("%5B","[")
			$PoSHCommand = $PoSHCommand.Replace("%5C","\")
			$PoSHCommand = $PoSHCommand.Replace("%5D","]")
			$PoSHCommand = $PoSHCommand.Replace("%5E","^")
			$PoSHCommand = $PoSHCommand.Replace("%5F","_")
			$PoSHCommand = $PoSHCommand.Replace("%7B","{")
			$PoSHCommand = $PoSHCommand.Replace("%7C","|")
			$PoSHCommand = $PoSHCommand.Replace("%7D","}")
			$PoSHCommand = $PoSHCommand.Replace("%7E","~")
			$PoSHCommand = $PoSHCommand.Replace("%7F","_")
			$PoSHCommand = $PoSHCommand.Replace("%7F%25","%")
			$PoSHPostStream = $PoSHCommand
			$PoSHCommand = $PoSHCommand.Split("&")

			$Properties = New-Object Psobject
			$Properties | Add-Member Noteproperty PoSHPostStream $PoSHPostStream
			foreach ($Post in $PoSHCommand)
			{
				$PostValue = $Post.Replace("%26","&")
				$PostContent = $PostValue.Split("=")
				$PostName = $PostContent[0].Replace("%3D","=")
				$PostValue = $PostContent[1].Replace("%3D","=")

				if ($PostName.EndsWith("[]"))
				{
					$PostName = $PostName.Substring(0,$PostName.Length-2)

					if (!(New-Object PSObject -Property @{PostName=@()}).PostName)
					{
						$Properties | Add-Member NoteProperty $Postname (@())
						$Properties."$PostName" += $PostValue
					}
					else
					{
						$Properties."$PostName" += $PostValue
					}
				} 
				else
				{
					$Properties | Add-Member NoteProperty $PostName $PostValue
				}
			}
			Write-Output $Properties
		}
	}

	function Get-PoSHQueryString {

	<#
		.SYNOPSIS
		 
			Function to get query string

		.EXAMPLE
		 
			Get-PoSHQueryString -Request $Request
			
	#>

	[CmdletBinding(SupportsShouldProcess = $true)]
	param (

		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Request')]
		$Request
	)

		if ($Request)
		{
			$PoSHQueryString = $Request.RawUrl.Split("?")[1]		
			$QueryStrings = $Request.QueryString
			
			$Properties = New-Object Psobject
			$Properties | Add-Member Noteproperty PoSHQueryString $PoSHQueryString
			foreach ($Query in $QueryStrings)
			{
				$QueryString = $Request.QueryString["$Query"]
				if ($QueryString -and $Query)
				{
					$Properties | Add-Member Noteproperty $Query $QueryString
				}
			}
			Write-Output $Properties
		}
	}

	function Get-PoSHWelcomeBanner {

	<#
		.SYNOPSIS
		 
			Function to get welcome banner

		.EXAMPLE
		 
			Get-PoSHWelcomeBanner -Hostname "localhost" -Port "8080" -SSL $True -SSLIP "10.10.10.2" -SSLPort "8443"
			
	#>

	[CmdletBinding(SupportsShouldProcess = $true)]
	param (

		[Parameter(
			Mandatory = $false,
			HelpMessage = 'IP Address or Hostname')]
		[Alias('IP')]
		[string]$Hostname,

		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Port Number')]
		[string]$Port,

		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Enable SSL')]
		$SSL = $false,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'SSL IP Address')]
		[string]$SSLIP,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'SSL Port Number')]
		[string]$SSLPort,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Debug Mode')]
		$DebugMode = $false
	)
		
		# Get Hostname
		if (!$Hostname -or $Hostname -eq "+") 
		{
			$Hostname = "localhost"
		}
		else
		{
			$Hostname = @($Hostname.Split(","))[0]
		}
		
		# Get Port
		if ($Port -ne "80")
		{
			$Port = ":$Port"
		}
		else
		{
			$Port = $null
		}
		
		if ($SSL)
		{
			# Get SSL Hostname
			if (!$SSLIP -or $SSLIP -eq "+") 
			{
				$SSLIP = "localhost"
			}
			else
			{
				$SSLIP = @($SSLIP.Split(","))[0]
			}
			
			# Get SSL Port
			if ($SSLPort -eq "443")
			{
				$SSLPort = "/"
			}
			else
			{
				$SSLPort = ":$SSLPort"
			}
		}
	}

	function New-PoSHAPIXML {

	<#
		.SYNOPSIS
		 
			Function to create PoSHAPI XML

		.EXAMPLE
		 
			New-PoSHAPIXML -ResultCode "1" -ResultMessage "Service unavailable" -RootTag "Result" -ItemTag "OperationResult" -Details
			
	#>

	[CmdletBinding(SupportsShouldProcess = $true)]
	param (

		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Result Code')]
		$ResultCode = "-1",

		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Result Message')]
		$ResultMessage = "The operation failed",
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Root Tag')]
		$RootTag = "Result",

		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Item Tag')]
		$ItemTag = "OperationResult",
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Child Items')]
		$ChildItems = "*",
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Attributes')]
		$Attributes = $Null,

		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Details')]
		$Details = $false
	)

	Begin {
		
		$xml = "<?xml version=""1.0"" encoding=""utf-8""?>`n"
		$xml += "<$RootTag>`n"
		$xml += " <Code>$ResultCode</Code>`n"
		$xml += " <Message>$ResultMessage</Message>`n"
	}

	Process {

		if ($Details)
		{
			$xml += " <$ItemTag"
			if ($Attributes)
			{
				foreach ($attr in $_ | Get-Member -type *Property $attributes)
				{ 
					$name = $attr.Name
					$xml += " $Name=`"$($_.$Name)`""
				}
			}
			$xml += ">`n"
			foreach ($child in $_ | Get-Member -Type *Property $childItems)
			{
				$name = $child.Name
				$xml += " <$Name>$($_.$Name)</$Name>`n"
			}
			$xml += " </$ItemTag>`n"
		}
	}

	End {

		$xml += "</$RootTag>`n"
		$xml
	}
	}

	function Request-PoSHCertificate {

	<#
		.SYNOPSIS
		 
			Function to create PoSH Certificate request

		.EXAMPLE
		 
			Request-PoSHCertificate
			
	#>

		$SSLSubject = "PoSHServer"
		$SSLName = New-Object -com "X509Enrollment.CX500DistinguishedName.1"
		$SSLName.Encode("CN=$SSLSubject", 0)
		$SSLKey = New-Object -com "X509Enrollment.CX509PrivateKey.1"
		$SSLKey.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
		$SSLKey.KeySpec = 1
		$SSLKey.Length = 2048
		$SSLKey.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
		$SSLKey.MachineContext = 1
		$SSLKey.ExportPolicy = 1
		$SSLKey.Create()
		$SSLObjectId = New-Object -com "X509Enrollment.CObjectIds.1"
		$SSLServerId = New-Object -com "X509Enrollment.CObjectId.1"
		$SSLServerId.InitializeFromValue("1.3.6.1.5.5.7.3.1")
		$SSLObjectId.add($SSLServerId)
		$SSLExtensions = New-Object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
		$SSLExtensions.InitializeEncode($SSLObjectId)
		$SSLCert = New-Object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
		$SSLCert.InitializeFromPrivateKey(2, $SSLKey, "")
		$SSLCert.Subject = $SSLName
		$SSLCert.Issuer = $SSLCert.Subject
		$SSLCert.NotBefore = Get-Date
		$SSLCert.NotAfter = $SSLCert.NotBefore.AddDays(1825)
		$SSLCert.X509Extensions.Add($SSLExtensions)
		$SSLCert.Encode()
		$SSLEnrollment = New-Object -com "X509Enrollment.CX509Enrollment.1"
		$SSLEnrollment.InitializeFromRequest($SSLCert)
		$SSLEnrollment.CertificateFriendlyName = 'PoSHServer SSL Certificate'
		$SSLCertdata = $SSLEnrollment.CreateRequest(0)
		$SSLEnrollment.InstallResponse(2, $SSLCertdata, 0, "")
	}

	function Register-PoSHCertificate {

	<#
		.SYNOPSIS
		 
			Function to register PoSH Certificate

		.EXAMPLE
		 
			Register-PoSHCertificate -SSLIP "10.10.10.2" -SSLPort "8443" -Thumbprint "45F53D35AB630198F19A27931283"
			
	#>

	[CmdletBinding(SupportsShouldProcess = $true)]
	param (

		[Parameter(
			Mandatory = $false,
			HelpMessage = 'SSL IP Address')]
		[string]$SSLIP,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'SSL Port Number')]
		[string]$SSLPort,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'SSL Thumbprint')]
		$Thumbprint,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Debug Mode')]
		$DebugMode = $false
	)

		$SSLIPAddresses = @($SSLIP.Split(","))
						
		foreach ($SSLIPAddress in $SSLIPAddresses)
		{
			$IPPort = $SSLIPAddress + ":" + $SSLPort
			
			if ($DebugMode)
			{
				# Remove Previous SSL Bindings
				netsh http delete sslcert ipport="$IPPort"
				
				# Add SSL Certificate
				netsh http add sslcert ipport="$IPPort" certhash="$Thumbprint" appid="{00112233-4455-6677-8899-AABBCCDDEEFF}"
			}
			else
			{		
				# Remove Previous SSL Bindings
				netsh http delete sslcert ipport="$IPPort" | Out-Null
				
				# Add SSL Certificate
				netsh http add sslcert ipport="$IPPort" certhash="$Thumbprint" appid="{00112233-4455-6677-8899-AABBCCDDEEFF}" | Out-Null
			}
		}
	}

	function New-PoSHTimeStamp {

	<#
		.SYNOPSIS
		 
			Function to generate time stamp

		.EXAMPLE
		 
			New-PoSHTimeStamp
			
	#>

		$now = Get-Date
		$hr = $now.Hour.ToString()
		$mi = $now.Minute.ToString()
		$sd = $now.Second.ToString()
		$ms = $now.Millisecond.ToString()
		Write-Output $hr$mi$sd$ms
	}

	function Invoke-AsyncHTTPRequest {

	<#
		.SYNOPSIS
		 
			Function to invoke async HTTP request

		.EXAMPLE
		 
			Invoke-AsyncHTTPRequest
			
	#>

	[CmdletBinding(SupportsShouldProcess = $true)]
	param (

		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Script Block')]
		$ScriptBlock,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Listener')]
		$Listener,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Hostname')]
		$Hostname,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Hostnames')]
		$Hostnames,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Home Directory. Example: C:/inetpub/wwwroot')]
		[string]$HomeDirectory,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'PoSHServer Config Path. Example: C:/inetpub/config.ps1')]
		[string]$PoSHConfigPath,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Log Directory. Example: C:/inetpub/wwwroot')]
		[string]$LogDirectory,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'PoSHServer Module Path')]
		[string]$PoSHModulePath,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Custom Child Config Path')]
		[string]$CustomChildConfig,
		
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Debug Mode')]
		[switch]$DebugMode = $false
	)

		$Pipeline = [System.Management.Automation.PowerShell]::Create()
		$Pipeline.AddScript($ScriptBlock)
		$Pipeline.AddArgument($Listener)
		$Pipeline.AddArgument($Hostname)
		$Pipeline.AddArgument($Hostnames)
		$Pipeline.AddArgument($HomeDirectory)
		$Pipeline.AddArgument($PoSHConfigPath)
		$Pipeline.AddArgument($LogDirectory)
		$Pipeline.AddArgument($PoSHModulePath)
		$Pipeline.AddArgument($CustomChildConfig)
		$Pipeline.AddArgument($DebugMode)
		$Pipeline.BeginInvoke()
	}
	
	# PoSH Server IP Address Verification
	if ($Hostname)
	{
		$IPAddresses = @($Hostname.Split(","))
		foreach ($IPAddress in $IPAddresses)
		{
			if ($IPAddress -ne "127.0.0.1" -and $IPAddress -ne "::1")
			{
				if ($IPAddress -as [ipaddress])
				{
					$IPValidation = Confirm-PoSHServerIP -IP $IPAddress
					if ($IPValidation -ne "Validated")
					{
						Write-Warning "$IPAddress is not exist on your current network configuration."
						Write-Warning "Aborting.."
						$ShouldProcess = $false
					}
				}
			}
		}
	}

	# PoSH Server SSL IP Address Verification	
	if ($SSLIP)
	{
		if ($ShouldProcess -ne $false)
		{
			$SSLIPAddresses = @($SSLIP.Split(","))
			foreach ($SSLIPAddress in $SSLIPAddresses)
			{
				if ($SSLIPAddress -ne "127.0.0.1" -and $SSLIPAddress -ne "::1")
				{
					if ($SSLIPAddress -as [ipaddress])
					{
						$IPValidation = Confirm-PoSHServerIP -IP $SSLIPAddress
						if ($IPValidation -ne "Validated")
						{
							Write-Warning "$SSLIPAddress is not exist on your current network configuration."
							Write-Warning "Aborting.."
							$ShouldProcess = $false
						}
					}
				}
			}
		}
	}
	
	function Set-PHPEncoding
	{
	param ($PHPOutput)
		
		$EncodingFix = [string]$PHPOutput
		$EncodingFix = $EncodingFix.Replace("─▒","ı")
		$EncodingFix = $EncodingFix.Replace("─░","İ")
		$EncodingFix = $EncodingFix.Replace("┼ş","ş")
		$EncodingFix = $EncodingFix.Replace("┼Ş","Ş")
		$EncodingFix = $EncodingFix.Replace("─ş","ğ")
		$EncodingFix = $EncodingFix.Replace("─Ş","Ğ")
		$EncodingFix = $EncodingFix.Replace("├ğ","ç")
		$EncodingFix = $EncodingFix.Replace("├ç","Ç")
		$EncodingFix = $EncodingFix.Replace("├╝","ü")
		$EncodingFix = $EncodingFix.Replace("├£","Ü")
		$EncodingFix = $EncodingFix.Replace("├Â","ö")
		$EncodingFix = $EncodingFix.Replace("├û","Ö")
		$EncodingFix = $EncodingFix.Replace("ÔÇô","'")
		$EncodingFix
	}
	
	# Break Script If Something's Wrong
	if ($ShouldProcess -eq $false)
	{
		$ResultCode = "-1"
		$ResultMessage = "Please check module output."
	}
	
	if ($ResultCode -ne "-1")
	{	
		# Enable Background Job
		if ($asJob)
		{	
			if (!$Hostname)
			{
				$Hostname = "+"
				$TaskHostname = "localhost"
			}
			else
			{
				$TaskHostname = $Hostname.Split(",")[0]
			}
			
			if (!$Port)
			{
				$Port = "8080"
				$TaskPort = "8080"
			}
			else
			{
				$TaskPort = $Port.Split(",")[0]
			}
			
			if ($SSL)
			{
				if (!$SSLIP) 
				{
					$SSLIP = "127.0.0.1"
					
					if (!$SSLPort)
					{
						$SSLPort = "8443"
					}
				}
			}
			
			$CheckTask = schtasks.exe | where {$_ -like "PoSHServer-$TaskHostname-$TaskPort*"}
			if ($CheckTask)
			{
				Write-Warning "This job is already exist. You should run it from Scheduled Jobs."
				Write-Warning "Aborting.."
				
				$ResultCode = "-1"
				$ResultMessage = "This job is already exist. You should run it from Scheduled Jobs."
			}
			else
			{
				# Prepare Job Information
				$TaskID = Get-Random -Maximum 10000
				$TaskName = "PoSHServer-$TaskHostname-$TaskPort-$TaskID"
				$CreateJobIDPath = $PoSHModulePath + "/jobs/job-" + $TaskID + ".txt"
				$CreateJobIDValue = $Hostname + ";" + $Port + ";" + $SSLIP + ";" + $SSLPort + ";" + $SSLName + ";" + $HomeDirectory + ";" + $LogDirectory + ";" + $CustomConfig + ";" + $CustomChildConfig + ";" + $CustomJob
				$CreateJobID = Add-Content -Path $CreateJobIDPath -Value $CreateJobIDValue
				
				# Create Scheduled Jobs
				$CreateTask = schtasks /create /tn "$TaskName" /xml "$PoSHModulePath/jobs/template.xml" /ru SYSTEM
				$ChangeTaskProcess = $true
				while ($ChangeTaskProcess)
				{
					if ($SSL)
					{
						$ChangeTask = schtasks /change /tn "$TaskName" /tr "Powershell -Command &{Import-Module PoSHServer; Start-PoSHServer -SSL -JobID $TaskID}" /rl highest
					}
					else
					{
						$ChangeTask = schtasks /change /tn "$TaskName" /tr "Powershell -Command &{Import-Module PoSHServer; Start-PoSHServer -JobID $TaskID}" /rl highest
					}
					
					if ($ChangeTask)
					{
						$ChangeTaskProcess = $false
					}
				}
				
				if ($JobUsername -and $JobPassword)
				{
					$ChangeTaskProcess = $true
					while ($ChangeTaskProcess)
					{
						$ChangeTask = schtasks /tn "$TaskName" /Change /RU "$JobUsername" /RP "$JobPassword"
						
						if ($ChangeTask)
						{
							$ChangeTaskProcess = $false
						}
					}
				}
				
				# Start Background Job
				$RunTask = schtasks /run /tn "$TaskName"
				
				# PoSH Server Welcome Banner
				Get-PoSHWelcomeBanner -Hostname $Hostname -Port $Port -SSL $SSL -SSLIP $SSLIP -SSLPort $SSLPort -DebugMode $DebugMode
			}
		}
		else
		{
			# PoSH Server Scheduled Background Jobs
			$PoSHJobArgs = @($Hostname,$Port,$HomeDirectory,$PoSHConfigPath,$LogDirectory,$PoSHModulePath,$asJob)
			$PoSHJob = Start-Job -scriptblock {
			param ($Hostname, $Port, $HomeDirectory, $PoSHConfigPath, $LogDirectory, $PoSHModulePath, $asJob)
			
				# Import PoSH Server Functions
				function Confirm-PoSHServerIP {

				<#
					.SYNOPSIS
					 
						Function to verify IP address on server

					.EXAMPLE
					 
						Confirm-PoSHServerIP -IP "192.168.2.1"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'IP address')]
					[string]$IP
				)

					# Get Networking Adapter Configuration 
					$IPConfigs = Get-WmiObject Win32_NetworkAdapterConfiguration
				   
					# Get All IP Addresses 
					foreach ($IPConfig in $IPConfigs) 
					{ 
						if ($IPConfig.IPaddress) 
						{ 
							foreach ($IPAddress in $IPConfig.IPaddress) 
							{ 
								if ("$IP" -eq "$IPAddress")
								{
									$Result = "Validated"
								}
							}
						}
					}
					
					$Result
				}

				function Get-DirectoryContent {

				<#
					.SYNOPSIS
					 
						Function to get directory content

					.EXAMPLE
					 
						Get-DirectoryContent -Path "C:/" -HeaderName "poshserver.net" -RequestURL "http://poshserver.net" -SubfolderName "/"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Directory Path')]
					[string]$Path,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Header Name')]
					[string]$HeaderName,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Request URL')]
					[string]$RequestURL,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Subfolder Name')]
					[string]$SubfolderName
				)
					
					$NotSupported = "Sorry, Directory Browsing is not supported in Standalone Mode"
					$NotSupported
				}

				function New-PoSHLogHash {

				<#
					.SYNOPSIS
					 
						Function to hash PoSHServer log file

					.EXAMPLE
					 
						New-PoSHLogHash -LogSchedule "Hourly" -LogDirectory "C:/inetpub/logs"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Log Schedule')]
					[string]$LogSchedule,

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Log Directory Path')]
					[string]$LogDirectory,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Debug Mode')]
					$DebugMode = $false
				)

					if ($LogSchedule -eq "Hourly")
					{
						$LogNameFormatLastHour = (Get-Date).AddHours(-1).ToString("yyMMddHH")
						$LogFileNameLastHour = "u_ex" + $LogNameFormatLastHour + ".log"
						$LogFilePathLastHour = $LogDirectory + "/" + $LogFileNameLastHour
						$SigFileName = "u_ex" + $LogNameFormatLastHour + ".sign"
						$SigFilePath = $LogDirectory + "/" + $SigFileName
						$DateFileName = "u_ex" + $LogNameFormatLastHour + ".date"
						$DateFilePath = $LogDirectory + "/" + $DateFileName
						$LastLogFilePath = $LogFilePathLastHour
					}
					else
					{
						$LogNameFormatYesterday = (Get-Date).AddDays(-1).ToString("yyMMdd")
						$LogFileNameYesterday = "u_ex" + $LogNameFormatYesterday + ".log"
						$LogFilePathYesterday = $LogDirectory + "/" + $LogFileNameYesterday
						$SigFileName = "u_ex" + $LogNameFormatYesterday + ".sign"
						$SigFilePath = $LogDirectory + "/" + $SigFileName
						$DateFileName = "u_ex" + $LogNameFormatYesterday + ".date"
						$DateFilePath = $LogDirectory + "/" + $DateFileName
						$LastLogFilePath = $LogFilePathYesterday
					}

					if ([System.IO.File]::Exists($LastLogFilePath))  
					{
						if (![System.IO.File]::Exists($SigFilePath))
						{
							$LogHashJobArgs = @($LastLogFilePath,$SigFilePath,$DateFilePath)
							
							try
							{
								$LogHashJob = Start-Job -ScriptBlock {
									param ($LastLogFilePath, $SigFilePath, $DateFilePath)
									if (![System.IO.File]::Exists($DateFilePath))  
									{
										$HashAlgorithm = "MD5"
										$HashType = [Type] "System.Security.Cryptography.$HashAlgorithm"
										$Hasher = $HashType::Create()
										$DateString = Get-Date -uformat "%d.%m.%Y"
										$TimeString = (w32tm /stripchart /computer:time.ume.tubitak.gov.tr /samples:1)[-1].split("")[0]
										$DateString = $DateString + " " + $TimeString
										$InputStream = New-Object IO.StreamReader $LastLogFilePath
										$HashBytes = $Hasher.ComputeHash($InputStream.BaseStream)
										$InputStream.Close()
										$Builder = New-Object System.Text.StringBuilder
										$HashBytes | Foreach-Object { [void] $Builder.Append($_.ToString("X2")) }
										$HashString = $Builder.ToString()
										$HashString = $HashString + " " + $DateString
										$Stream = [System.IO.StreamWriter]$SigFilePath
										$Stream.Write($HashString)
										$Stream.Close()
										$Stream = [System.IO.StreamWriter]$DateFilePath
										$Stream.Write($DateString)
										$Stream.Close()
										$InputStream = New-Object IO.StreamReader $SigFilePath
										$HashBytes = $Hasher.ComputeHash($InputStream.BaseStream)
										$InputStream.Close()
										$Builder = New-Object System.Text.StringBuilder
										$HashBytes | Foreach-Object { [void] $Builder.Append($_.ToString("X2")) }
										$HashString = $Builder.ToString()
										$Stream = [System.IO.StreamWriter]$SigFilePath
										$Stream.Write($HashString)
										$Stream.Close()
									}
								} -ArgumentList $LogHashJobArgs	
							}
							catch
							{
								Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
							}
						}
					}
					else
					{
						Add-Content -Value "Could not find log file." -Path "$LogDirectory/debug.txt"
					}
				}

				function Start-PoSHLogParser {

				<#
					.SYNOPSIS
					 
						Function to parse PoSHServer log files

					.EXAMPLE
					 
						Start-PoSHLogParser -LogPath "C:/inetpub/logs/hourly.log"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Log Path')]
					[string]$LogPath
				)

					$File = $LogPath
					$Log = Get-Content $File | where {$_ -notLike "#[D,S-V]*" }
					$Columns = (($Log[0].TrimEnd()) -replace "#Fields: ", "" -replace "-","" -replace "\(","" -replace "\)","").Split(" ")
					$Count = $Columns.Length
					$Rows = $Log | where {$_ -notLike "#Fields"}
					$IISLog = New-Object System.Data.DataTable "IISLog"
					foreach ($Column in $Columns) 
					{
						$NewColumn = New-Object System.Data.DataColumn $Column, ([string])
						$IISLog.Columns.Add($NewColumn)
					}
					foreach ($Row in $Rows) 
					{
						$Row = $Row.Split(" ")
						$AddRow = $IISLog.newrow()
						for($i=0;$i -lt $Count; $i++) 
						{
							$ColumnName = $Columns[$i]
							$AddRow.$ColumnName = $Row[$i]
						}
						$IISLog.Rows.Add($AddRow)
					}
					$IISLog
				}

				function Get-MimeType {

				<#
					.SYNOPSIS
					 
						Function to get mime types

					.EXAMPLE
					 
						Get-MimeType -Extension ".jpg"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Extension')]
					[string]$Extension
				)
					
					switch ($Extension) 
					{ 
						.ps1 {"text/ps1"}
						.psxml {"text/psxml"}
						.psapi {"text/psxml"}
						.posh {"text/psxml"}
						.html {"text/html"} 
						.htm {"text/html"} 
						.php {"text/php"} 
						.css {"text/css"} 
						.jpeg {"image/jpeg"} 
						.jpg {"image/jpeg"}
						.gif {"image/gif"}
						.ico {"image/x-icon"}
						.flv {"video/x-flv"}
						.swf {"application/x-shockwave-flash"}
						.js {"text/javascript"}
						.txt {"text/plain"}
						.rar {"application/octet-stream"}
						.zip {"application/x-zip-compressed"}
						.rss {"application/rss+xml"}
						.xml {"text/xml"}
						.pdf {"application/pdf"}
						.png {"image/png"}
						.mpg {"video/mpeg"}
						.mpeg {"video/mpeg"}
						.mp3 {"audio/mpeg"}
						.oga {"audio/ogg"}
						.spx {"audio/ogg"}
						.mp4 {"video/mp4"}
						.m4v {"video/m4v"}
						.ogg {"video/ogg"}
						.ogv {"video/ogg"}
						.webm {"video/webm"}
						.wmv {"video/x-ms-wmv"}
						.woff {"application/x-font-woff"}
						.eot {"application/vnd.ms-fontobject"}
						.svg {"image/svg+xml"}
						.svgz {"image/svg+xml"}
						.otf {"font/otf"}
						.ttf {"application/x-font-ttf"}
						.xht {"application/xhtml+xml"}
						.xhtml {"application/xhtml+xml"}
						default {"text/html"}
					}	
				}

				function Get-PoSHPHPContent {

				<#
					.SYNOPSIS
					 
						Function to get php content

					.EXAMPLE
					 
						Get-PoSHPHPContent -PHPCgiPath "C:/php.exe" -File "C:/test.php" -PoSHPHPGET "test=value"
						
					.EXAMPLE
					 
						Get-PoSHPHPContent -PHPCgiPath "C:/php.exe" -File "C:/test.php" -PoSHPHPPOST "test=value"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'PHP-Cgi Path')]
					[string]$PHPCgiPath,

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'File Path')]
					[string]$File,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'PHP GET String')]
					[string]$PoSHPHPGET,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'PHP POST String')]
					[string]$PoSHPHPPOST
				)

					# Set PHP Environment
					$env:GATEWAY_INTERFACE="CGI/1.1"
					$env:SCRIPT_FILENAME="$File"
					$env:REDIRECT_STATUS="200"
					$env:SERVER_PROTOCOL="HTTP/1.1"
					$env:HTTP_ACCEPT="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
					$env:CONTENT_TYPE="application/x-www-form-urlencoded"
					
					if ($PoSHPHPPOST)
					{
						# Set PHP POST Environment
						$env:REQUEST_METHOD="POST"
						$PHP_CONTENT_LENGTH = $PoSHPHPPOST.Length
						$env:CONTENT_LENGTH="$PHP_CONTENT_LENGTH"
						
						# Get PHP Content
						$PHPOutput = "$PoSHPHPPOST" | &$PHPCgiPath
					}
					else
					{
						# Set PHP GET Environment
						$env:REQUEST_METHOD="GET"
						$env:QUERY_STRING="$PoSHPHPGET"
						
						# Get PHP Content
						$PHPOutput = &$PHPCgiPath
					}
					
					# Get PHP Header Line Number
					$PHPHeaderLineNumber = ($PHPOutput | Select-String -Pattern "^$")[0].LineNumber
					
					# Get PHP Header
					$PHPHeader = $PHPOutput | Select -First $PHPHeaderLineNumber
					
					# Get Redirection Location
					$GetPHPLocation = $PHPHeader | Select-String "Location:"
					
					# Check Redirection Location
					if ($GetPHPLocation)
					{
						$GetPHPLocation = $GetPHPLocation -match 'Location: (.*)/?'
						if ($GetPHPLocation -eq $True) { $PHPRedirectionURL = $Matches[1] } else { $PHPRedirectionURL = $Null; }
					}
					
					# Redirect to Location
					if ($PHPRedirectionURL)
					{
						# Redirection Output
						$PHPRedirection = '<html>'
						$PHPRedirection += '<script type="text/javascript">'
						$PHPRedirection += 'window.location = "' + $PHPRedirectionURL + '"'
						$PHPRedirection += '</script>'
						$PHPRedirection += '</html>'
						$PHPRedirection
					}
					else
					{	
						# Output PHP Content
						$PHPOutput = $PHPOutput | Select -Skip $PHPHeaderLineNumber
						$PHPOutput
					}
				}

				function Get-PoSHPostStream {

				<#
					.SYNOPSIS
					 
						Function to get php post stream

					.EXAMPLE
					 
						Get-PoSHPostStream -InputStream $InputStream -ContentEncoding $ContentEncoding
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Input Stream')]
					$InputStream,
					
					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Content Encoding')]
					$ContentEncoding
				)

					$PoSHCommand = New-Object IO.StreamReader ($InputStream,$ContentEncoding)
					$PoSHCommand = $PoSHCommand.ReadToEnd()
					$PoSHCommand = $PoSHCommand.ToString()
					
					if ($PoSHCommand)
					{
						$PoSHCommand = $PoSHCommand.Replace("+"," ")
						$PoSHCommand = $PoSHCommand.Replace("%20"," ")
						$PoSHCommand = $PoSHCommand.Replace("%21","!")
						$PoSHCommand = $PoSHCommand.Replace('%22','"')
						$PoSHCommand = $PoSHCommand.Replace("%23","#")
						$PoSHCommand = $PoSHCommand.Replace("%24","$")
						$PoSHCommand = $PoSHCommand.Replace("%25","%")
						$PoSHCommand = $PoSHCommand.Replace("%27","'")
						$PoSHCommand = $PoSHCommand.Replace("%28","(")
						$PoSHCommand = $PoSHCommand.Replace("%29",")")
						$PoSHCommand = $PoSHCommand.Replace("%2A","*")
						$PoSHCommand = $PoSHCommand.Replace("%2B","+")
						$PoSHCommand = $PoSHCommand.Replace("%2C",",")
						$PoSHCommand = $PoSHCommand.Replace("%2D","-")
						$PoSHCommand = $PoSHCommand.Replace("%2E",".")
						$PoSHCommand = $PoSHCommand.Replace("%2F","/")
						$PoSHCommand = $PoSHCommand.Replace("%3A",":")
						$PoSHCommand = $PoSHCommand.Replace("%3B",";")
						$PoSHCommand = $PoSHCommand.Replace("%3C","<")
						$PoSHCommand = $PoSHCommand.Replace("%3E",">")
						$PoSHCommand = $PoSHCommand.Replace("%3F","?")
						$PoSHCommand = $PoSHCommand.Replace("%5B","[")
						$PoSHCommand = $PoSHCommand.Replace("%5C","\")
						$PoSHCommand = $PoSHCommand.Replace("%5D","]")
						$PoSHCommand = $PoSHCommand.Replace("%5E","^")
						$PoSHCommand = $PoSHCommand.Replace("%5F","_")
						$PoSHCommand = $PoSHCommand.Replace("%7B","{")
						$PoSHCommand = $PoSHCommand.Replace("%7C","|")
						$PoSHCommand = $PoSHCommand.Replace("%7D","}")
						$PoSHCommand = $PoSHCommand.Replace("%7E","~")
						$PoSHCommand = $PoSHCommand.Replace("%7F","_")
						$PoSHCommand = $PoSHCommand.Replace("%7F%25","%")
						$PoSHPostStream = $PoSHCommand
						$PoSHCommand = $PoSHCommand.Split("&")

						$Properties = New-Object Psobject
						$Properties | Add-Member Noteproperty PoSHPostStream $PoSHPostStream
						foreach ($Post in $PoSHCommand)
						{
							$PostValue = $Post.Replace("%26","&")
							$PostContent = $PostValue.Split("=")
							$PostName = $PostContent[0].Replace("%3D","=")
							$PostValue = $PostContent[1].Replace("%3D","=")

							if ($PostName.EndsWith("[]"))
							{
								$PostName = $PostName.Substring(0,$PostName.Length-2)

								if (!(New-Object PSObject -Property @{PostName=@()}).PostName)
								{
									$Properties | Add-Member NoteProperty $Postname (@())
									$Properties."$PostName" += $PostValue
								}
								else
								{
									$Properties."$PostName" += $PostValue
								}
							} 
							else
							{
								$Properties | Add-Member NoteProperty $PostName $PostValue
							}
						}
						Write-Output $Properties
					}
				}

				function Get-PoSHQueryString {

				<#
					.SYNOPSIS
					 
						Function to get query string

					.EXAMPLE
					 
						Get-PoSHQueryString -Request $Request
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Request')]
					$Request
				)

					if ($Request)
					{
						$PoSHQueryString = $Request.RawUrl.Split("?")[1]		
						$QueryStrings = $Request.QueryString
						
						$Properties = New-Object Psobject
						$Properties | Add-Member Noteproperty PoSHQueryString $PoSHQueryString
						foreach ($Query in $QueryStrings)
						{
							$QueryString = $Request.QueryString["$Query"]
							if ($QueryString -and $Query)
							{
								$Properties | Add-Member Noteproperty $Query $QueryString
							}
						}
						Write-Output $Properties
					}
				}

				function Get-PoSHWelcomeBanner {

				<#
					.SYNOPSIS
					 
						Function to get welcome banner

					.EXAMPLE
					 
						Get-PoSHWelcomeBanner -Hostname "localhost" -Port "8080" -SSL $True -SSLIP "10.10.10.2" -SSLPort "8443"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'IP Address or Hostname')]
					[Alias('IP')]
					[string]$Hostname,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Port Number')]
					[string]$Port,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Enable SSL')]
					$SSL = $false,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL IP Address')]
					[string]$SSLIP,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL Port Number')]
					[string]$SSLPort,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Debug Mode')]
					$DebugMode = $false
				)
					
					# Get Hostname
					if (!$Hostname -or $Hostname -eq "+") 
					{
						$Hostname = "localhost"
					}
					else
					{
						$Hostname = @($Hostname.Split(","))[0]
					}
					
					# Get Port
					if ($Port -ne "80")
					{
						$Port = ":$Port"
					}
					else
					{
						$Port = $null
					}
					
					if ($SSL)
					{
						# Get SSL Hostname
						if (!$SSLIP -or $SSLIP -eq "+") 
						{
							$SSLIP = "localhost"
						}
						else
						{
							$SSLIP = @($SSLIP.Split(","))[0]
						}
						
						# Get SSL Port
						if ($SSLPort -eq "443")
						{
							$SSLPort = "/"
						}
						else
						{
							$SSLPort = ":$SSLPort"
						}
					}
				}

				function New-PoSHAPIXML {

				<#
					.SYNOPSIS
					 
						Function to create PoSHAPI XML

					.EXAMPLE
					 
						New-PoSHAPIXML -ResultCode "1" -ResultMessage "Service unavailable" -RootTag "Result" -ItemTag "OperationResult" -Details
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Result Code')]
					$ResultCode = "-1",

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Result Message')]
					$ResultMessage = "The operation failed",
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Root Tag')]
					$RootTag = "Result",

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Item Tag')]
					$ItemTag = "OperationResult",
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Child Items')]
					$ChildItems = "*",
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Attributes')]
					$Attributes = $Null,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Details')]
					$Details = $false
				)

				Begin {
					
					$xml = "<?xml version=""1.0"" encoding=""utf-8""?>`n"
					$xml += "<$RootTag>`n"
					$xml += " <Code>$ResultCode</Code>`n"
					$xml += " <Message>$ResultMessage</Message>`n"
				}

				Process {

					if ($Details)
					{
						$xml += " <$ItemTag"
						if ($Attributes)
						{
							foreach ($attr in $_ | Get-Member -type *Property $attributes)
							{ 
								$name = $attr.Name
								$xml += " $Name=`"$($_.$Name)`""
							}
						}
						$xml += ">`n"
						foreach ($child in $_ | Get-Member -Type *Property $childItems)
						{
							$name = $child.Name
							$xml += " <$Name>$($_.$Name)</$Name>`n"
						}
						$xml += " </$ItemTag>`n"
					}
				}

				End {

					$xml += "</$RootTag>`n"
					$xml
				}
				}

				function Request-PoSHCertificate {

				<#
					.SYNOPSIS
					 
						Function to create PoSH Certificate request

					.EXAMPLE
					 
						Request-PoSHCertificate
						
				#>

					$SSLSubject = "PoSHServer"
					$SSLName = New-Object -com "X509Enrollment.CX500DistinguishedName.1"
					$SSLName.Encode("CN=$SSLSubject", 0)
					$SSLKey = New-Object -com "X509Enrollment.CX509PrivateKey.1"
					$SSLKey.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
					$SSLKey.KeySpec = 1
					$SSLKey.Length = 2048
					$SSLKey.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
					$SSLKey.MachineContext = 1
					$SSLKey.ExportPolicy = 1
					$SSLKey.Create()
					$SSLObjectId = New-Object -com "X509Enrollment.CObjectIds.1"
					$SSLServerId = New-Object -com "X509Enrollment.CObjectId.1"
					$SSLServerId.InitializeFromValue("1.3.6.1.5.5.7.3.1")
					$SSLObjectId.add($SSLServerId)
					$SSLExtensions = New-Object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
					$SSLExtensions.InitializeEncode($SSLObjectId)
					$SSLCert = New-Object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
					$SSLCert.InitializeFromPrivateKey(2, $SSLKey, "")
					$SSLCert.Subject = $SSLName
					$SSLCert.Issuer = $SSLCert.Subject
					$SSLCert.NotBefore = Get-Date
					$SSLCert.NotAfter = $SSLCert.NotBefore.AddDays(1825)
					$SSLCert.X509Extensions.Add($SSLExtensions)
					$SSLCert.Encode()
					$SSLEnrollment = New-Object -com "X509Enrollment.CX509Enrollment.1"
					$SSLEnrollment.InitializeFromRequest($SSLCert)
					$SSLEnrollment.CertificateFriendlyName = 'PoSHServer SSL Certificate'
					$SSLCertdata = $SSLEnrollment.CreateRequest(0)
					$SSLEnrollment.InstallResponse(2, $SSLCertdata, 0, "")
				}

				function Register-PoSHCertificate {

				<#
					.SYNOPSIS
					 
						Function to register PoSH Certificate

					.EXAMPLE
					 
						Register-PoSHCertificate -SSLIP "10.10.10.2" -SSLPort "8443" -Thumbprint "45F53D35AB630198F19A27931283"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL IP Address')]
					[string]$SSLIP,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL Port Number')]
					[string]$SSLPort,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL Thumbprint')]
					$Thumbprint,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Debug Mode')]
					$DebugMode = $false
				)

					$SSLIPAddresses = @($SSLIP.Split(","))
									
					foreach ($SSLIPAddress in $SSLIPAddresses)
					{
						$IPPort = $SSLIPAddress + ":" + $SSLPort
						
						if ($DebugMode)
						{
							# Remove Previous SSL Bindings
							netsh http delete sslcert ipport="$IPPort"
							
							# Add SSL Certificate
							netsh http add sslcert ipport="$IPPort" certhash="$Thumbprint" appid="{00112233-4455-6677-8899-AABBCCDDEEFF}"
						}
						else
						{		
							# Remove Previous SSL Bindings
							netsh http delete sslcert ipport="$IPPort" | Out-Null
							
							# Add SSL Certificate
							netsh http add sslcert ipport="$IPPort" certhash="$Thumbprint" appid="{00112233-4455-6677-8899-AABBCCDDEEFF}" | Out-Null
						}
					}
				}

				function New-PoSHTimeStamp {

				<#
					.SYNOPSIS
					 
						Function to generate time stamp

					.EXAMPLE
					 
						New-PoSHTimeStamp
						
				#>

					$now = Get-Date
					$hr = $now.Hour.ToString()
					$mi = $now.Minute.ToString()
					$sd = $now.Second.ToString()
					$ms = $now.Millisecond.ToString()
					Write-Output $hr$mi$sd$ms
				}

				function Invoke-AsyncHTTPRequest {

				<#
					.SYNOPSIS
					 
						Function to invoke async HTTP request

					.EXAMPLE
					 
						Invoke-AsyncHTTPRequest
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Script Block')]
					$ScriptBlock,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Listener')]
					$Listener,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Hostname')]
					$Hostname,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Hostnames')]
					$Hostnames,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Home Directory. Example: C:/inetpub/wwwroot')]
					[string]$HomeDirectory,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'PoSHServer Config Path. Example: C:/inetpub/config.ps1')]
					[string]$PoSHConfigPath,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Log Directory. Example: C:/inetpub/wwwroot')]
					[string]$LogDirectory,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'PoSHServer Module Path')]
					[string]$PoSHModulePath,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Custom Child Config Path')]
					[string]$CustomChildConfig,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Debug Mode')]
					[switch]$DebugMode = $false
				)

					$Pipeline = [System.Management.Automation.PowerShell]::Create()
					$Pipeline.AddScript($ScriptBlock)
					$Pipeline.AddArgument($Listener)
					$Pipeline.AddArgument($Hostname)
					$Pipeline.AddArgument($Hostnames)
					$Pipeline.AddArgument($HomeDirectory)
					$Pipeline.AddArgument($PoSHConfigPath)
					$Pipeline.AddArgument($LogDirectory)
					$Pipeline.AddArgument($PoSHModulePath)
					$Pipeline.AddArgument($CustomChildConfig)
					$Pipeline.AddArgument($DebugMode)
					$Pipeline.BeginInvoke()
				}
				
				# Test Config Path
				$TestPoSHConfigPath = Test-Path $PoSHConfigPath
				
				if (!$TestPoSHConfigPath)
				{
					# Default Document
					$DefaultDocument = "index.ps1"

					# Log Schedule
					# Options: Hourly, Daily
					$LogSchedule = "Daily"

					# Basic Authentication
					# Options: On, Off
					$BasicAuthentication = "Off"

					# Windows Authentication
					# Options: On, Off
					$WindowsAuthentication = "Off"

					# DirectoryBrowsing
					# Options: On, Off
					$DirectoryBrowsing = "Off"

					# IP Restriction
					# Options: On, Off
					$IPRestriction = "Off"
					$IPWhiteList = "::1 127.0.0.1"

					# Content Filtering
					# Options: On, Off
					$ContentFiltering = "Off"
					$ContentFilterBlackList = "audio/mpeg video/mpeg"

					# PHP Cgi Path
					$PHPCgiPath = ($env:PATH).Split(";") | Select-String "PHP"
					$PHPCgiPath = [string]$PHPCgiPath + "/php-cgi.exe"
				}
				else
				{
					. $PoSHConfigPath
				}
				
				while ($true)
				{
					Start-Sleep -s 60			
					
					# Get Job Time
					$JobTime = Get-Date -format HHmm
					
					if ($LogSchedule -eq "Hourly")
					{
						# PoSH Server Log Hashing (at *:30 hourly)
						if ($JobTime -eq "*30")
						{
							New-PoSHLogHash -LogSchedule $LogSchedule -LogDirectory $LogDirectory
						}
					}
					else
					{
						# PoSH Server Log Hashing (at 02:30 daily)
						if ($JobTime -eq "0230")
						{
							New-PoSHLogHash -LogSchedule $LogSchedule -LogDirectory $LogDirectory
						}
					}
				}
			} -ArgumentList $PoSHJobArgs
			
			# PoSH Server Custom Background Jobs
			$PoSHCustomJobArgs = @($Hostname,$Port,$HomeDirectory,$PoSHConfigPath,$LogDirectory,$PoSHModulePath,$CustomJob,$CustomJobSchedule,$asJob)
			$PoSHCustomJob = Start-Job -scriptblock {
			param ($Hostname, $Port, $HomeDirectory, $PoSHConfigPath, $LogDirectory, $PoSHModulePath, $CustomJob, $CustomJobSchedule, $asJob)
			
				# Import PoSH Server Functions
				function Confirm-PoSHServerIP {

				<#
					.SYNOPSIS
					 
						Function to verify IP address on server

					.EXAMPLE
					 
						Confirm-PoSHServerIP -IP "192.168.2.1"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'IP address')]
					[string]$IP
				)

					# Get Networking Adapter Configuration 
					$IPConfigs = Get-WmiObject Win32_NetworkAdapterConfiguration
				   
					# Get All IP Addresses 
					foreach ($IPConfig in $IPConfigs) 
					{ 
						if ($IPConfig.IPaddress) 
						{ 
							foreach ($IPAddress in $IPConfig.IPaddress) 
							{ 
								if ("$IP" -eq "$IPAddress")
								{
									$Result = "Validated"
								}
							}
						}
					}
					
					$Result
				}

				function Get-DirectoryContent {

				<#
					.SYNOPSIS
					 
						Function to get directory content

					.EXAMPLE
					 
						Get-DirectoryContent -Path "C:/" -HeaderName "poshserver.net" -RequestURL "http://poshserver.net" -SubfolderName "/"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Directory Path')]
					[string]$Path,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Header Name')]
					[string]$HeaderName,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Request URL')]
					[string]$RequestURL,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Subfolder Name')]
					[string]$SubfolderName
				)
					
					$NotSupported = "Sorry, Directory Browsing is not supported in Standalone Mode"
					$NotSupported
				}

				function New-PoSHLogHash {

				<#
					.SYNOPSIS
					 
						Function to hash PoSHServer log file

					.EXAMPLE
					 
						New-PoSHLogHash -LogSchedule "Hourly" -LogDirectory "C:/inetpub/logs"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Log Schedule')]
					[string]$LogSchedule,

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Log Directory Path')]
					[string]$LogDirectory,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Debug Mode')]
					$DebugMode = $false
				)

					if ($LogSchedule -eq "Hourly")
					{
						$LogNameFormatLastHour = (Get-Date).AddHours(-1).ToString("yyMMddHH")
						$LogFileNameLastHour = "u_ex" + $LogNameFormatLastHour + ".log"
						$LogFilePathLastHour = $LogDirectory + "/" + $LogFileNameLastHour
						$SigFileName = "u_ex" + $LogNameFormatLastHour + ".sign"
						$SigFilePath = $LogDirectory + "/" + $SigFileName
						$DateFileName = "u_ex" + $LogNameFormatLastHour + ".date"
						$DateFilePath = $LogDirectory + "/" + $DateFileName
						$LastLogFilePath = $LogFilePathLastHour
					}
					else
					{
						$LogNameFormatYesterday = (Get-Date).AddDays(-1).ToString("yyMMdd")
						$LogFileNameYesterday = "u_ex" + $LogNameFormatYesterday + ".log"
						$LogFilePathYesterday = $LogDirectory + "/" + $LogFileNameYesterday
						$SigFileName = "u_ex" + $LogNameFormatYesterday + ".sign"
						$SigFilePath = $LogDirectory + "/" + $SigFileName
						$DateFileName = "u_ex" + $LogNameFormatYesterday + ".date"
						$DateFilePath = $LogDirectory + "/" + $DateFileName
						$LastLogFilePath = $LogFilePathYesterday
					}

					if ([System.IO.File]::Exists($LastLogFilePath))  
					{
						if (![System.IO.File]::Exists($SigFilePath))
						{
							$LogHashJobArgs = @($LastLogFilePath,$SigFilePath,$DateFilePath)
							
							try
							{
								$LogHashJob = Start-Job -ScriptBlock {
									param ($LastLogFilePath, $SigFilePath, $DateFilePath)
									if (![System.IO.File]::Exists($DateFilePath))  
									{
										$HashAlgorithm = "MD5"
										$HashType = [Type] "System.Security.Cryptography.$HashAlgorithm"
										$Hasher = $HashType::Create()
										$DateString = Get-Date -uformat "%d.%m.%Y"
										$TimeString = (w32tm /stripchart /computer:time.ume.tubitak.gov.tr /samples:1)[-1].split("")[0]
										$DateString = $DateString + " " + $TimeString
										$InputStream = New-Object IO.StreamReader $LastLogFilePath
										$HashBytes = $Hasher.ComputeHash($InputStream.BaseStream)
										$InputStream.Close()
										$Builder = New-Object System.Text.StringBuilder
										$HashBytes | Foreach-Object { [void] $Builder.Append($_.ToString("X2")) }
										$HashString = $Builder.ToString()
										$HashString = $HashString + " " + $DateString
										$Stream = [System.IO.StreamWriter]$SigFilePath
										$Stream.Write($HashString)
										$Stream.Close()
										$Stream = [System.IO.StreamWriter]$DateFilePath
										$Stream.Write($DateString)
										$Stream.Close()
										$InputStream = New-Object IO.StreamReader $SigFilePath
										$HashBytes = $Hasher.ComputeHash($InputStream.BaseStream)
										$InputStream.Close()
										$Builder = New-Object System.Text.StringBuilder
										$HashBytes | Foreach-Object { [void] $Builder.Append($_.ToString("X2")) }
										$HashString = $Builder.ToString()
										$Stream = [System.IO.StreamWriter]$SigFilePath
										$Stream.Write($HashString)
										$Stream.Close()
									}
								} -ArgumentList $LogHashJobArgs	
							}
							catch
							{
								Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
							}
						}
					}
					else
					{
						Add-Content -Value "Could not find log file." -Path "$LogDirectory/debug.txt"
					}
				}

				function Start-PoSHLogParser {

				<#
					.SYNOPSIS
					 
						Function to parse PoSHServer log files

					.EXAMPLE
					 
						Start-PoSHLogParser -LogPath "C:/inetpub/logs/hourly.log"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Log Path')]
					[string]$LogPath
				)

					$File = $LogPath
					$Log = Get-Content $File | where {$_ -notLike "#[D,S-V]*" }
					$Columns = (($Log[0].TrimEnd()) -replace "#Fields: ", "" -replace "-","" -replace "\(","" -replace "\)","").Split(" ")
					$Count = $Columns.Length
					$Rows = $Log | where {$_ -notLike "#Fields"}
					$IISLog = New-Object System.Data.DataTable "IISLog"
					foreach ($Column in $Columns) 
					{
						$NewColumn = New-Object System.Data.DataColumn $Column, ([string])
						$IISLog.Columns.Add($NewColumn)
					}
					foreach ($Row in $Rows) 
					{
						$Row = $Row.Split(" ")
						$AddRow = $IISLog.newrow()
						for($i=0;$i -lt $Count; $i++) 
						{
							$ColumnName = $Columns[$i]
							$AddRow.$ColumnName = $Row[$i]
						}
						$IISLog.Rows.Add($AddRow)
					}
					$IISLog
				}

				function Get-MimeType {

				<#
					.SYNOPSIS
					 
						Function to get mime types

					.EXAMPLE
					 
						Get-MimeType -Extension ".jpg"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Extension')]
					[string]$Extension
				)
					
					switch ($Extension) 
					{ 
						.ps1 {"text/ps1"}
						.psxml {"text/psxml"}
						.psapi {"text/psxml"}
						.posh {"text/psxml"}
						.html {"text/html"} 
						.htm {"text/html"} 
						.php {"text/php"} 
						.css {"text/css"} 
						.jpeg {"image/jpeg"} 
						.jpg {"image/jpeg"}
						.gif {"image/gif"}
						.ico {"image/x-icon"}
						.flv {"video/x-flv"}
						.swf {"application/x-shockwave-flash"}
						.js {"text/javascript"}
						.txt {"text/plain"}
						.rar {"application/octet-stream"}
						.zip {"application/x-zip-compressed"}
						.rss {"application/rss+xml"}
						.xml {"text/xml"}
						.pdf {"application/pdf"}
						.png {"image/png"}
						.mpg {"video/mpeg"}
						.mpeg {"video/mpeg"}
						.mp3 {"audio/mpeg"}
						.oga {"audio/ogg"}
						.spx {"audio/ogg"}
						.mp4 {"video/mp4"}
						.m4v {"video/m4v"}
						.ogg {"video/ogg"}
						.ogv {"video/ogg"}
						.webm {"video/webm"}
						.wmv {"video/x-ms-wmv"}
						.woff {"application/x-font-woff"}
						.eot {"application/vnd.ms-fontobject"}
						.svg {"image/svg+xml"}
						.svgz {"image/svg+xml"}
						.otf {"font/otf"}
						.ttf {"application/x-font-ttf"}
						.xht {"application/xhtml+xml"}
						.xhtml {"application/xhtml+xml"}
						default {"text/html"}
					}	
				}

				function Get-PoSHPHPContent {

				<#
					.SYNOPSIS
					 
						Function to get php content

					.EXAMPLE
					 
						Get-PoSHPHPContent -PHPCgiPath "C:/php.exe" -File "C:/test.php" -PoSHPHPGET "test=value"
						
					.EXAMPLE
					 
						Get-PoSHPHPContent -PHPCgiPath "C:/php.exe" -File "C:/test.php" -PoSHPHPPOST "test=value"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'PHP-Cgi Path')]
					[string]$PHPCgiPath,

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'File Path')]
					[string]$File,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'PHP GET String')]
					[string]$PoSHPHPGET,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'PHP POST String')]
					[string]$PoSHPHPPOST
				)

					# Set PHP Environment
					$env:GATEWAY_INTERFACE="CGI/1.1"
					$env:SCRIPT_FILENAME="$File"
					$env:REDIRECT_STATUS="200"
					$env:SERVER_PROTOCOL="HTTP/1.1"
					$env:HTTP_ACCEPT="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
					$env:CONTENT_TYPE="application/x-www-form-urlencoded"
					
					if ($PoSHPHPPOST)
					{
						# Set PHP POST Environment
						$env:REQUEST_METHOD="POST"
						$PHP_CONTENT_LENGTH = $PoSHPHPPOST.Length
						$env:CONTENT_LENGTH="$PHP_CONTENT_LENGTH"
						
						# Get PHP Content
						$PHPOutput = "$PoSHPHPPOST" | &$PHPCgiPath
					}
					else
					{
						# Set PHP GET Environment
						$env:REQUEST_METHOD="GET"
						$env:QUERY_STRING="$PoSHPHPGET"
						
						# Get PHP Content
						$PHPOutput = &$PHPCgiPath
					}
					
					# Get PHP Header Line Number
					$PHPHeaderLineNumber = ($PHPOutput | Select-String -Pattern "^$")[0].LineNumber
					
					# Get PHP Header
					$PHPHeader = $PHPOutput | Select -First $PHPHeaderLineNumber
					
					# Get Redirection Location
					$GetPHPLocation = $PHPHeader | Select-String "Location:"
					
					# Check Redirection Location
					if ($GetPHPLocation)
					{
						$GetPHPLocation = $GetPHPLocation -match 'Location: (.*)/?'
						if ($GetPHPLocation -eq $True) { $PHPRedirectionURL = $Matches[1] } else { $PHPRedirectionURL = $Null; }
					}
					
					# Redirect to Location
					if ($PHPRedirectionURL)
					{
						# Redirection Output
						$PHPRedirection = '<html>'
						$PHPRedirection += '<script type="text/javascript">'
						$PHPRedirection += 'window.location = "' + $PHPRedirectionURL + '"'
						$PHPRedirection += '</script>'
						$PHPRedirection += '</html>'
						$PHPRedirection
					}
					else
					{	
						# Output PHP Content
						$PHPOutput = $PHPOutput | Select -Skip $PHPHeaderLineNumber
						$PHPOutput
					}
				}

				function Get-PoSHPostStream {

				<#
					.SYNOPSIS
					 
						Function to get php post stream

					.EXAMPLE
					 
						Get-PoSHPostStream -InputStream $InputStream -ContentEncoding $ContentEncoding
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Input Stream')]
					$InputStream,
					
					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Content Encoding')]
					$ContentEncoding
				)

					$PoSHCommand = New-Object IO.StreamReader ($InputStream,$ContentEncoding)
					$PoSHCommand = $PoSHCommand.ReadToEnd()
					$PoSHCommand = $PoSHCommand.ToString()
					
					if ($PoSHCommand)
					{
						$PoSHCommand = $PoSHCommand.Replace("+"," ")
						$PoSHCommand = $PoSHCommand.Replace("%20"," ")
						$PoSHCommand = $PoSHCommand.Replace("%21","!")
						$PoSHCommand = $PoSHCommand.Replace('%22','"')
						$PoSHCommand = $PoSHCommand.Replace("%23","#")
						$PoSHCommand = $PoSHCommand.Replace("%24","$")
						$PoSHCommand = $PoSHCommand.Replace("%25","%")
						$PoSHCommand = $PoSHCommand.Replace("%27","'")
						$PoSHCommand = $PoSHCommand.Replace("%28","(")
						$PoSHCommand = $PoSHCommand.Replace("%29",")")
						$PoSHCommand = $PoSHCommand.Replace("%2A","*")
						$PoSHCommand = $PoSHCommand.Replace("%2B","+")
						$PoSHCommand = $PoSHCommand.Replace("%2C",",")
						$PoSHCommand = $PoSHCommand.Replace("%2D","-")
						$PoSHCommand = $PoSHCommand.Replace("%2E",".")
						$PoSHCommand = $PoSHCommand.Replace("%2F","/")
						$PoSHCommand = $PoSHCommand.Replace("%3A",":")
						$PoSHCommand = $PoSHCommand.Replace("%3B",";")
						$PoSHCommand = $PoSHCommand.Replace("%3C","<")
						$PoSHCommand = $PoSHCommand.Replace("%3E",">")
						$PoSHCommand = $PoSHCommand.Replace("%3F","?")
						$PoSHCommand = $PoSHCommand.Replace("%5B","[")
						$PoSHCommand = $PoSHCommand.Replace("%5C","\")
						$PoSHCommand = $PoSHCommand.Replace("%5D","]")
						$PoSHCommand = $PoSHCommand.Replace("%5E","^")
						$PoSHCommand = $PoSHCommand.Replace("%5F","_")
						$PoSHCommand = $PoSHCommand.Replace("%7B","{")
						$PoSHCommand = $PoSHCommand.Replace("%7C","|")
						$PoSHCommand = $PoSHCommand.Replace("%7D","}")
						$PoSHCommand = $PoSHCommand.Replace("%7E","~")
						$PoSHCommand = $PoSHCommand.Replace("%7F","_")
						$PoSHCommand = $PoSHCommand.Replace("%7F%25","%")
						$PoSHPostStream = $PoSHCommand
						$PoSHCommand = $PoSHCommand.Split("&")

						$Properties = New-Object Psobject
						$Properties | Add-Member Noteproperty PoSHPostStream $PoSHPostStream
						foreach ($Post in $PoSHCommand)
						{
							$PostValue = $Post.Replace("%26","&")
							$PostContent = $PostValue.Split("=")
							$PostName = $PostContent[0].Replace("%3D","=")
							$PostValue = $PostContent[1].Replace("%3D","=")

							if ($PostName.EndsWith("[]"))
							{
								$PostName = $PostName.Substring(0,$PostName.Length-2)

								if (!(New-Object PSObject -Property @{PostName=@()}).PostName)
								{
									$Properties | Add-Member NoteProperty $Postname (@())
									$Properties."$PostName" += $PostValue
								}
								else
								{
									$Properties."$PostName" += $PostValue
								}
							} 
							else
							{
								$Properties | Add-Member NoteProperty $PostName $PostValue
							}
						}
						Write-Output $Properties
					}
				}

				function Get-PoSHQueryString {

				<#
					.SYNOPSIS
					 
						Function to get query string

					.EXAMPLE
					 
						Get-PoSHQueryString -Request $Request
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Request')]
					$Request
				)

					if ($Request)
					{
						$PoSHQueryString = $Request.RawUrl.Split("?")[1]		
						$QueryStrings = $Request.QueryString
						
						$Properties = New-Object Psobject
						$Properties | Add-Member Noteproperty PoSHQueryString $PoSHQueryString
						foreach ($Query in $QueryStrings)
						{
							$QueryString = $Request.QueryString["$Query"]
							if ($QueryString -and $Query)
							{
								$Properties | Add-Member Noteproperty $Query $QueryString
							}
						}
						Write-Output $Properties
					}
				}

				function Get-PoSHWelcomeBanner {

				<#
					.SYNOPSIS
					 
						Function to get welcome banner

					.EXAMPLE
					 
						Get-PoSHWelcomeBanner -Hostname "localhost" -Port "8080" -SSL $True -SSLIP "10.10.10.2" -SSLPort "8443"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'IP Address or Hostname')]
					[Alias('IP')]
					[string]$Hostname,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Port Number')]
					[string]$Port,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Enable SSL')]
					$SSL = $false,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL IP Address')]
					[string]$SSLIP,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL Port Number')]
					[string]$SSLPort,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Debug Mode')]
					$DebugMode = $false
				)
					
					# Get Hostname
					if (!$Hostname -or $Hostname -eq "+") 
					{
						$Hostname = "localhost"
					}
					else
					{
						$Hostname = @($Hostname.Split(","))[0]
					}
					
					# Get Port
					if ($Port -ne "80")
					{
						$Port = ":$Port"
					}
					else
					{
						$Port = $null
					}
					
					if ($SSL)
					{
						# Get SSL Hostname
						if (!$SSLIP -or $SSLIP -eq "+") 
						{
							$SSLIP = "localhost"
						}
						else
						{
							$SSLIP = @($SSLIP.Split(","))[0]
						}
						
						# Get SSL Port
						if ($SSLPort -eq "443")
						{
							$SSLPort = "/"
						}
						else
						{
							$SSLPort = ":$SSLPort"
						}
					}
				}

				function New-PoSHAPIXML {

				<#
					.SYNOPSIS
					 
						Function to create PoSHAPI XML

					.EXAMPLE
					 
						New-PoSHAPIXML -ResultCode "1" -ResultMessage "Service unavailable" -RootTag "Result" -ItemTag "OperationResult" -Details
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Result Code')]
					$ResultCode = "-1",

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Result Message')]
					$ResultMessage = "The operation failed",
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Root Tag')]
					$RootTag = "Result",

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Item Tag')]
					$ItemTag = "OperationResult",
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Child Items')]
					$ChildItems = "*",
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Attributes')]
					$Attributes = $Null,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Details')]
					$Details = $false
				)

				Begin {
					
					$xml = "<?xml version=""1.0"" encoding=""utf-8""?>`n"
					$xml += "<$RootTag>`n"
					$xml += " <Code>$ResultCode</Code>`n"
					$xml += " <Message>$ResultMessage</Message>`n"
				}

				Process {

					if ($Details)
					{
						$xml += " <$ItemTag"
						if ($Attributes)
						{
							foreach ($attr in $_ | Get-Member -type *Property $attributes)
							{ 
								$name = $attr.Name
								$xml += " $Name=`"$($_.$Name)`""
							}
						}
						$xml += ">`n"
						foreach ($child in $_ | Get-Member -Type *Property $childItems)
						{
							$name = $child.Name
							$xml += " <$Name>$($_.$Name)</$Name>`n"
						}
						$xml += " </$ItemTag>`n"
					}
				}

				End {

					$xml += "</$RootTag>`n"
					$xml
				}
				}

				function Request-PoSHCertificate {

				<#
					.SYNOPSIS
					 
						Function to create PoSH Certificate request

					.EXAMPLE
					 
						Request-PoSHCertificate
						
				#>

					$SSLSubject = "PoSHServer"
					$SSLName = New-Object -com "X509Enrollment.CX500DistinguishedName.1"
					$SSLName.Encode("CN=$SSLSubject", 0)
					$SSLKey = New-Object -com "X509Enrollment.CX509PrivateKey.1"
					$SSLKey.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
					$SSLKey.KeySpec = 1
					$SSLKey.Length = 2048
					$SSLKey.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
					$SSLKey.MachineContext = 1
					$SSLKey.ExportPolicy = 1
					$SSLKey.Create()
					$SSLObjectId = New-Object -com "X509Enrollment.CObjectIds.1"
					$SSLServerId = New-Object -com "X509Enrollment.CObjectId.1"
					$SSLServerId.InitializeFromValue("1.3.6.1.5.5.7.3.1")
					$SSLObjectId.add($SSLServerId)
					$SSLExtensions = New-Object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
					$SSLExtensions.InitializeEncode($SSLObjectId)
					$SSLCert = New-Object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
					$SSLCert.InitializeFromPrivateKey(2, $SSLKey, "")
					$SSLCert.Subject = $SSLName
					$SSLCert.Issuer = $SSLCert.Subject
					$SSLCert.NotBefore = Get-Date
					$SSLCert.NotAfter = $SSLCert.NotBefore.AddDays(1825)
					$SSLCert.X509Extensions.Add($SSLExtensions)
					$SSLCert.Encode()
					$SSLEnrollment = New-Object -com "X509Enrollment.CX509Enrollment.1"
					$SSLEnrollment.InitializeFromRequest($SSLCert)
					$SSLEnrollment.CertificateFriendlyName = 'PoSHServer SSL Certificate'
					$SSLCertdata = $SSLEnrollment.CreateRequest(0)
					$SSLEnrollment.InstallResponse(2, $SSLCertdata, 0, "")
				}

				function Register-PoSHCertificate {

				<#
					.SYNOPSIS
					 
						Function to register PoSH Certificate

					.EXAMPLE
					 
						Register-PoSHCertificate -SSLIP "10.10.10.2" -SSLPort "8443" -Thumbprint "45F53D35AB630198F19A27931283"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL IP Address')]
					[string]$SSLIP,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL Port Number')]
					[string]$SSLPort,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL Thumbprint')]
					$Thumbprint,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Debug Mode')]
					$DebugMode = $false
				)

					$SSLIPAddresses = @($SSLIP.Split(","))
									
					foreach ($SSLIPAddress in $SSLIPAddresses)
					{
						$IPPort = $SSLIPAddress + ":" + $SSLPort
						
						if ($DebugMode)
						{
							# Remove Previous SSL Bindings
							netsh http delete sslcert ipport="$IPPort"
							
							# Add SSL Certificate
							netsh http add sslcert ipport="$IPPort" certhash="$Thumbprint" appid="{00112233-4455-6677-8899-AABBCCDDEEFF}"
						}
						else
						{		
							# Remove Previous SSL Bindings
							netsh http delete sslcert ipport="$IPPort" | Out-Null
							
							# Add SSL Certificate
							netsh http add sslcert ipport="$IPPort" certhash="$Thumbprint" appid="{00112233-4455-6677-8899-AABBCCDDEEFF}" | Out-Null
						}
					}
				}

				function New-PoSHTimeStamp {

				<#
					.SYNOPSIS
					 
						Function to generate time stamp

					.EXAMPLE
					 
						New-PoSHTimeStamp
						
				#>

					$now = Get-Date
					$hr = $now.Hour.ToString()
					$mi = $now.Minute.ToString()
					$sd = $now.Second.ToString()
					$ms = $now.Millisecond.ToString()
					Write-Output $hr$mi$sd$ms
				}

				function Invoke-AsyncHTTPRequest {

				<#
					.SYNOPSIS
					 
						Function to invoke async HTTP request

					.EXAMPLE
					 
						Invoke-AsyncHTTPRequest
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Script Block')]
					$ScriptBlock,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Listener')]
					$Listener,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Hostname')]
					$Hostname,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Hostnames')]
					$Hostnames,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Home Directory. Example: C:/inetpub/wwwroot')]
					[string]$HomeDirectory,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'PoSHServer Config Path. Example: C:/inetpub/config.ps1')]
					[string]$PoSHConfigPath,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Log Directory. Example: C:/inetpub/wwwroot')]
					[string]$LogDirectory,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'PoSHServer Module Path')]
					[string]$PoSHModulePath,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Custom Child Config Path')]
					[string]$CustomChildConfig,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Debug Mode')]
					[switch]$DebugMode = $false
				)

					$Pipeline = [System.Management.Automation.PowerShell]::Create()
					$Pipeline.AddScript($ScriptBlock)
					$Pipeline.AddArgument($Listener)
					$Pipeline.AddArgument($Hostname)
					$Pipeline.AddArgument($Hostnames)
					$Pipeline.AddArgument($HomeDirectory)
					$Pipeline.AddArgument($PoSHConfigPath)
					$Pipeline.AddArgument($LogDirectory)
					$Pipeline.AddArgument($PoSHModulePath)
					$Pipeline.AddArgument($CustomChildConfig)
					$Pipeline.AddArgument($DebugMode)
					$Pipeline.BeginInvoke()
				}
				
				# Test Config Path
				$TestPoSHConfigPath = Test-Path $PoSHConfigPath
				
				if (!$TestPoSHConfigPath)
				{
					# Default Document
					$DefaultDocument = "index.ps1"

					# Log Schedule
					# Options: Hourly, Daily
					$LogSchedule = "Daily"

					# Basic Authentication
					# Options: On, Off
					$BasicAuthentication = "Off"

					# Windows Authentication
					# Options: On, Off
					$WindowsAuthentication = "Off"

					# DirectoryBrowsing
					# Options: On, Off
					$DirectoryBrowsing = "Off"

					# IP Restriction
					# Options: On, Off
					$IPRestriction = "Off"
					$IPWhiteList = "::1 127.0.0.1"

					# Content Filtering
					# Options: On, Off
					$ContentFiltering = "Off"
					$ContentFilterBlackList = "audio/mpeg video/mpeg"

					# PHP Cgi Path
					$PHPCgiPath = ($env:PATH).Split(";") | Select-String "PHP"
					$PHPCgiPath = [string]$PHPCgiPath + "/php-cgi.exe"
				}
				else
				{
					. $PoSHConfigPath
				}
				
				while ($true)
				{
					Start-Sleep -s 60			
					
					# Get Job Time
					$JobTime = Get-Date -format HHmm
					
					if ($CustomJobSchedule -eq "1")
					{
						# PoSH Server Custom Jobs (at every 1 minute)
						if ($CustomJob)
						{
							. $CustomJob
						}
					}					
					elseif ($CustomJobSchedule -eq "5")
					{
						# PoSH Server Custom Jobs (at every 5 minutes)
						if ($JobTime -like "*5" -or $JobTime -like "*0")
						{
							if ($CustomJob)
							{
								. $CustomJob
							}
						}
					}
					elseif ($CustomJobSchedule -eq "10")
					{
						# PoSH Server Custom Jobs (at every 10 minutes)
						if ($JobTime -like "*00" -or $JobTime -like "*10" -or $JobTime -like "*20" -or $JobTime -like "*30" -or $JobTime -like "*40" -or $JobTime -like "*50")
						{
							if ($CustomJob)
							{
								. $CustomJob
							}
						}
					}
					elseif ($CustomJobSchedule -eq "20")
					{
						# PoSH Server Custom Jobs (at every 20 minutes)
						if ($JobTime -like "*00" -or $JobTime -like "*20" -or $JobTime -like "*40")
						{
							if ($CustomJob)
							{
								. $CustomJob
							}
						}
					}
					elseif ($CustomJobSchedule -eq "30")
					{
						# PoSH Server Custom Jobs (at every 30 minutes)
						if ($JobTime -like "*00" -or $JobTime -like "*30")
						{
							if ($CustomJob)
							{
								. $CustomJob
							}
						}
					}
					elseif ($CustomJobSchedule -eq "60")
					{
						# PoSH Server Custom Jobs (at every hour)
						if ($JobTime -like "*00")
						{
							if ($CustomJob)
							{
								. $CustomJob
							}
						}
					}					
					else
					{
						# PoSH Server Custom Jobs (at every 5 minutes)
						if ($JobTime -like "*5" -or $JobTime -like "*0")
						{
							if ($CustomJob)
							{
								. $CustomJob
							}
						}
					}
				}
			} -ArgumentList $PoSHCustomJobArgs
			
			# PoSH Server Custom Config
			if ($CustomConfig)
			{
				. $CustomConfig
			}
			
			# Create an HTTPListener
			try
			{
				$Listener = New-Object Net.HttpListener
			}
			catch
			{
				Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
			}
			
			# Add Prefix Urls
			try
			{
				if (!$Hostname) 
				{
					$Hostname = "+"
					
					if (!$Port)
					{
						$Port = "8080"
					}
					
					$Prefix = "http://" + $Hostname + ":" + $Port + "/"
					$Listener.Prefixes.Add($Prefix)
				}
				else
				{
					$Hostnames = @($Hostname.Split(","))
					
					if (!$Port)
					{
						$Port = "8080"
					}
							
					foreach ($Hostname in $Hostnames)
					{
						$Prefix = "http://" + $Hostname + ":" + $Port + "/"
						$Listener.Prefixes.Add($Prefix)
					}
				}
				
				if ($SSL)
				{
					if (!$SSLIP) 
					{
						$SSLIP = "127.0.0.1"
						
						if (!$SSLPort)
						{
							$SSLPort = "8443"
						}
						
						$Prefix = "https://" + $SSLIP + ":" + $SSLPort + "/"
						$Listener.Prefixes.Add($Prefix)
					}
					else
					{
						$SSLIPAddresses = @($SSLIP.Split(","))
						
						if (!$SSLPort)
						{
							$SSLPort = "8443"
						}
								
						foreach ($SSLIPAddress in $SSLIPAddresses)
						{
							$Prefix = "https://" + $SSLIPAddress + ":" + $SSLPort + "/"
							$Listener.Prefixes.Add($Prefix)
						}
					}
				}		
			}
			catch
			{
				Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
			}
			
			# Start Listener
			try
			{
				$Listener.Start()
			}
			catch
			{
				Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
			}
			
			# Configure SSL
			try
			{
				if ($SSL)
				{
					if ($SSLName)
					{
						$PoSHCert = Get-ChildItem -Recurse Cert: | Where-Object { $_.FriendlyName -eq $SSLName }
						
						if (!$PoSHCert)
						{
							$PoSHCert = Get-ChildItem -Recurse Cert: | Where-Object { $_.FriendlyName -eq "PoSHServer SSL Certificate" }
						}
					}
					else
					{
						$PoSHCert = Get-ChildItem -Recurse Cert: | Where-Object { $_.FriendlyName -eq "PoSHServer SSL Certificate" }
					}
					
					if (!$PoSHCert)
					{
						if ($DebugMode)
						{
							Add-Content -Value "Sorry, I couldn't find your SSL certificate." -Path "$LogDirectory/debug.txt"
							Add-Content -Value "Creating Self-Signed SSL certificate.." -Path "$LogDirectory/debug.txt"
						}
						Request-PoSHCertificate
						$PoSHCert = Get-ChildItem -Recurse Cert: | Where-Object { $_.FriendlyName -eq "PoSHServer SSL Certificate" }
					}
					
					# Register SSL Certificate
					$CertThumbprint = $PoSHCert[0].Thumbprint
					Register-PoSHCertificate -SSLIP $SSLIP -SSLPort $SSLPort -Thumbprint $CertThumbprint -DebugMode $DebugMode
				}
			}
			catch
			{
				Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
			}
			
			# PoSH Server Welcome Banner
			try
			{
				Get-PoSHWelcomeBanner -Hostname $Hostname -Port $Port -SSL $SSL -SSLIP $SSLIP -SSLPort $SSLPort -DebugMode $DebugMode
			}
			catch
			{
				Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
			}
			
			# PoSH Server Async Process Script
			$ScriptBlock = `
			{
			Param($Listener, $Hostname, $Hostnames, $HomeDirectory, $PoSHConfigPath, $LogDirectory, $PoSHModulePath, $CustomChildConfig, $DebugMode)
			
				# Import PoSH Server Functions
				function Confirm-PoSHServerIP {

				<#
					.SYNOPSIS
					 
						Function to verify IP address on server

					.EXAMPLE
					 
						Confirm-PoSHServerIP -IP "192.168.2.1"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'IP address')]
					[string]$IP
				)

					# Get Networking Adapter Configuration 
					$IPConfigs = Get-WmiObject Win32_NetworkAdapterConfiguration
				   
					# Get All IP Addresses 
					foreach ($IPConfig in $IPConfigs) 
					{ 
						if ($IPConfig.IPaddress) 
						{ 
							foreach ($IPAddress in $IPConfig.IPaddress) 
							{ 
								if ("$IP" -eq "$IPAddress")
								{
									$Result = "Validated"
								}
							}
						}
					}
					
					$Result
				}

				function Get-DirectoryContent {

				<#
					.SYNOPSIS
					 
						Function to get directory content

					.EXAMPLE
					 
						Get-DirectoryContent -Path "C:/" -HeaderName "poshserver.net" -RequestURL "http://poshserver.net" -SubfolderName "/"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Directory Path')]
					[string]$Path,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Header Name')]
					[string]$HeaderName,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Request URL')]
					[string]$RequestURL,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Subfolder Name')]
					[string]$SubfolderName
				)
					
					$NotSupported = "Sorry, Directory Browsing is not supported in Standalone Mode"
					$NotSupported
				}

				function New-PoSHLogHash {

				<#
					.SYNOPSIS
					 
						Function to hash PoSHServer log file

					.EXAMPLE
					 
						New-PoSHLogHash -LogSchedule "Hourly" -LogDirectory "C:/inetpub/logs"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Log Schedule')]
					[string]$LogSchedule,

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Log Directory Path')]
					[string]$LogDirectory,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Debug Mode')]
					$DebugMode = $false
				)

					if ($LogSchedule -eq "Hourly")
					{
						$LogNameFormatLastHour = (Get-Date).AddHours(-1).ToString("yyMMddHH")
						$LogFileNameLastHour = "u_ex" + $LogNameFormatLastHour + ".log"
						$LogFilePathLastHour = $LogDirectory + "/" + $LogFileNameLastHour
						$SigFileName = "u_ex" + $LogNameFormatLastHour + ".sign"
						$SigFilePath = $LogDirectory + "/" + $SigFileName
						$DateFileName = "u_ex" + $LogNameFormatLastHour + ".date"
						$DateFilePath = $LogDirectory + "/" + $DateFileName
						$LastLogFilePath = $LogFilePathLastHour
					}
					else
					{
						$LogNameFormatYesterday = (Get-Date).AddDays(-1).ToString("yyMMdd")
						$LogFileNameYesterday = "u_ex" + $LogNameFormatYesterday + ".log"
						$LogFilePathYesterday = $LogDirectory + "/" + $LogFileNameYesterday
						$SigFileName = "u_ex" + $LogNameFormatYesterday + ".sign"
						$SigFilePath = $LogDirectory + "/" + $SigFileName
						$DateFileName = "u_ex" + $LogNameFormatYesterday + ".date"
						$DateFilePath = $LogDirectory + "/" + $DateFileName
						$LastLogFilePath = $LogFilePathYesterday
					}

					if ([System.IO.File]::Exists($LastLogFilePath))  
					{
						if (![System.IO.File]::Exists($SigFilePath))
						{
							$LogHashJobArgs = @($LastLogFilePath,$SigFilePath,$DateFilePath)
							
							try
							{
								$LogHashJob = Start-Job -ScriptBlock {
									param ($LastLogFilePath, $SigFilePath, $DateFilePath)
									if (![System.IO.File]::Exists($DateFilePath))  
									{
										$HashAlgorithm = "MD5"
										$HashType = [Type] "System.Security.Cryptography.$HashAlgorithm"
										$Hasher = $HashType::Create()
										$DateString = Get-Date -uformat "%d.%m.%Y"
										$TimeString = (w32tm /stripchart /computer:time.ume.tubitak.gov.tr /samples:1)[-1].split("")[0]
										$DateString = $DateString + " " + $TimeString
										$InputStream = New-Object IO.StreamReader $LastLogFilePath
										$HashBytes = $Hasher.ComputeHash($InputStream.BaseStream)
										$InputStream.Close()
										$Builder = New-Object System.Text.StringBuilder
										$HashBytes | Foreach-Object { [void] $Builder.Append($_.ToString("X2")) }
										$HashString = $Builder.ToString()
										$HashString = $HashString + " " + $DateString
										$Stream = [System.IO.StreamWriter]$SigFilePath
										$Stream.Write($HashString)
										$Stream.Close()
										$Stream = [System.IO.StreamWriter]$DateFilePath
										$Stream.Write($DateString)
										$Stream.Close()
										$InputStream = New-Object IO.StreamReader $SigFilePath
										$HashBytes = $Hasher.ComputeHash($InputStream.BaseStream)
										$InputStream.Close()
										$Builder = New-Object System.Text.StringBuilder
										$HashBytes | Foreach-Object { [void] $Builder.Append($_.ToString("X2")) }
										$HashString = $Builder.ToString()
										$Stream = [System.IO.StreamWriter]$SigFilePath
										$Stream.Write($HashString)
										$Stream.Close()
									}
								} -ArgumentList $LogHashJobArgs	
							}
							catch
							{
								Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
							}
						}
					}
					else
					{
						Add-Content -Value "Could not find log file." -Path "$LogDirectory/debug.txt"
					}
				}

				function Start-PoSHLogParser {

				<#
					.SYNOPSIS
					 
						Function to parse PoSHServer log files

					.EXAMPLE
					 
						Start-PoSHLogParser -LogPath "C:/inetpub/logs/hourly.log"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Log Path')]
					[string]$LogPath
				)

					$File = $LogPath
					$Log = Get-Content $File | where {$_ -notLike "#[D,S-V]*" }
					$Columns = (($Log[0].TrimEnd()) -replace "#Fields: ", "" -replace "-","" -replace "\(","" -replace "\)","").Split(" ")
					$Count = $Columns.Length
					$Rows = $Log | where {$_ -notLike "#Fields"}
					$IISLog = New-Object System.Data.DataTable "IISLog"
					foreach ($Column in $Columns) 
					{
						$NewColumn = New-Object System.Data.DataColumn $Column, ([string])
						$IISLog.Columns.Add($NewColumn)
					}
					foreach ($Row in $Rows) 
					{
						$Row = $Row.Split(" ")
						$AddRow = $IISLog.newrow()
						for($i=0;$i -lt $Count; $i++) 
						{
							$ColumnName = $Columns[$i]
							$AddRow.$ColumnName = $Row[$i]
						}
						$IISLog.Rows.Add($AddRow)
					}
					$IISLog
				}

				function Get-MimeType {

				<#
					.SYNOPSIS
					 
						Function to get mime types

					.EXAMPLE
					 
						Get-MimeType -Extension ".jpg"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Extension')]
					[string]$Extension
				)
					
					switch ($Extension) 
					{ 
						.ps1 {"text/ps1"}
						.psxml {"text/psxml"}
						.psapi {"text/psxml"}
						.posh {"text/psxml"}
						.html {"text/html"} 
						.htm {"text/html"} 
						.php {"text/php"} 
						.css {"text/css"} 
						.jpeg {"image/jpeg"} 
						.jpg {"image/jpeg"}
						.gif {"image/gif"}
						.ico {"image/x-icon"}
						.flv {"video/x-flv"}
						.swf {"application/x-shockwave-flash"}
						.js {"text/javascript"}
						.txt {"text/plain"}
						.rar {"application/octet-stream"}
						.zip {"application/x-zip-compressed"}
						.rss {"application/rss+xml"}
						.xml {"text/xml"}
						.pdf {"application/pdf"}
						.png {"image/png"}
						.mpg {"video/mpeg"}
						.mpeg {"video/mpeg"}
						.mp3 {"audio/mpeg"}
						.oga {"audio/ogg"}
						.spx {"audio/ogg"}
						.mp4 {"video/mp4"}
						.m4v {"video/m4v"}
						.ogg {"video/ogg"}
						.ogv {"video/ogg"}
						.webm {"video/webm"}
						.wmv {"video/x-ms-wmv"}
						.woff {"application/x-font-woff"}
						.eot {"application/vnd.ms-fontobject"}
						.svg {"image/svg+xml"}
						.svgz {"image/svg+xml"}
						.otf {"font/otf"}
						.ttf {"application/x-font-ttf"}
						.xht {"application/xhtml+xml"}
						.xhtml {"application/xhtml+xml"}
						default {"text/html"}
					}	
				}

				function Get-PoSHPHPContent {

				<#
					.SYNOPSIS
					 
						Function to get php content

					.EXAMPLE
					 
						Get-PoSHPHPContent -PHPCgiPath "C:/php.exe" -File "C:/test.php" -PoSHPHPGET "test=value"
						
					.EXAMPLE
					 
						Get-PoSHPHPContent -PHPCgiPath "C:/php.exe" -File "C:/test.php" -PoSHPHPPOST "test=value"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'PHP-Cgi Path')]
					[string]$PHPCgiPath,

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'File Path')]
					[string]$File,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'PHP GET String')]
					[string]$PoSHPHPGET,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'PHP POST String')]
					[string]$PoSHPHPPOST
				)

					# Set PHP Environment
					$env:GATEWAY_INTERFACE="CGI/1.1"
					$env:SCRIPT_FILENAME="$File"
					$env:REDIRECT_STATUS="200"
					$env:SERVER_PROTOCOL="HTTP/1.1"
					$env:HTTP_ACCEPT="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
					$env:CONTENT_TYPE="application/x-www-form-urlencoded"
					
					if ($PoSHPHPPOST)
					{
						# Set PHP POST Environment
						$env:REQUEST_METHOD="POST"
						$PHP_CONTENT_LENGTH = $PoSHPHPPOST.Length
						$env:CONTENT_LENGTH="$PHP_CONTENT_LENGTH"
						
						# Get PHP Content
						$PHPOutput = "$PoSHPHPPOST" | &$PHPCgiPath
					}
					else
					{
						# Set PHP GET Environment
						$env:REQUEST_METHOD="GET"
						$env:QUERY_STRING="$PoSHPHPGET"
						
						# Get PHP Content
						$PHPOutput = &$PHPCgiPath
					}
					
					# Get PHP Header Line Number
					$PHPHeaderLineNumber = ($PHPOutput | Select-String -Pattern "^$")[0].LineNumber
					
					# Get PHP Header
					$PHPHeader = $PHPOutput | Select -First $PHPHeaderLineNumber
					
					# Get Redirection Location
					$GetPHPLocation = $PHPHeader | Select-String "Location:"
					
					# Check Redirection Location
					if ($GetPHPLocation)
					{
						$GetPHPLocation = $GetPHPLocation -match 'Location: (.*)/?'
						if ($GetPHPLocation -eq $True) { $PHPRedirectionURL = $Matches[1] } else { $PHPRedirectionURL = $Null; }
					}
					
					# Redirect to Location
					if ($PHPRedirectionURL)
					{
						# Redirection Output
						$PHPRedirection = '<html>'
						$PHPRedirection += '<script type="text/javascript">'
						$PHPRedirection += 'window.location = "' + $PHPRedirectionURL + '"'
						$PHPRedirection += '</script>'
						$PHPRedirection += '</html>'
						$PHPRedirection
					}
					else
					{	
						# Output PHP Content
						$PHPOutput = $PHPOutput | Select -Skip $PHPHeaderLineNumber
						$PHPOutput
					}
				}

				function Get-PoSHPostStream {

				<#
					.SYNOPSIS
					 
						Function to get php post stream

					.EXAMPLE
					 
						Get-PoSHPostStream -InputStream $InputStream -ContentEncoding $ContentEncoding
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Input Stream')]
					$InputStream,
					
					[Parameter(
						Mandatory = $true,
						HelpMessage = 'Content Encoding')]
					$ContentEncoding
				)

					$PoSHCommand = New-Object IO.StreamReader ($InputStream,$ContentEncoding)
					$PoSHCommand = $PoSHCommand.ReadToEnd()
					$PoSHCommand = $PoSHCommand.ToString()
					
					if ($PoSHCommand)
					{
						$PoSHCommand = $PoSHCommand.Replace("+"," ")
						$PoSHCommand = $PoSHCommand.Replace("%20"," ")
						$PoSHCommand = $PoSHCommand.Replace("%21","!")
						$PoSHCommand = $PoSHCommand.Replace('%22','"')
						$PoSHCommand = $PoSHCommand.Replace("%23","#")
						$PoSHCommand = $PoSHCommand.Replace("%24","$")
						$PoSHCommand = $PoSHCommand.Replace("%25","%")
						$PoSHCommand = $PoSHCommand.Replace("%27","'")
						$PoSHCommand = $PoSHCommand.Replace("%28","(")
						$PoSHCommand = $PoSHCommand.Replace("%29",")")
						$PoSHCommand = $PoSHCommand.Replace("%2A","*")
						$PoSHCommand = $PoSHCommand.Replace("%2B","+")
						$PoSHCommand = $PoSHCommand.Replace("%2C",",")
						$PoSHCommand = $PoSHCommand.Replace("%2D","-")
						$PoSHCommand = $PoSHCommand.Replace("%2E",".")
						$PoSHCommand = $PoSHCommand.Replace("%2F","/")
						$PoSHCommand = $PoSHCommand.Replace("%3A",":")
						$PoSHCommand = $PoSHCommand.Replace("%3B",";")
						$PoSHCommand = $PoSHCommand.Replace("%3C","<")
						$PoSHCommand = $PoSHCommand.Replace("%3E",">")
						$PoSHCommand = $PoSHCommand.Replace("%3F","?")
						$PoSHCommand = $PoSHCommand.Replace("%5B","[")
						$PoSHCommand = $PoSHCommand.Replace("%5C","\")
						$PoSHCommand = $PoSHCommand.Replace("%5D","]")
						$PoSHCommand = $PoSHCommand.Replace("%5E","^")
						$PoSHCommand = $PoSHCommand.Replace("%5F","_")
						$PoSHCommand = $PoSHCommand.Replace("%7B","{")
						$PoSHCommand = $PoSHCommand.Replace("%7C","|")
						$PoSHCommand = $PoSHCommand.Replace("%7D","}")
						$PoSHCommand = $PoSHCommand.Replace("%7E","~")
						$PoSHCommand = $PoSHCommand.Replace("%7F","_")
						$PoSHCommand = $PoSHCommand.Replace("%7F%25","%")
						$PoSHPostStream = $PoSHCommand
						$PoSHCommand = $PoSHCommand.Split("&")

						$Properties = New-Object Psobject
						$Properties | Add-Member Noteproperty PoSHPostStream $PoSHPostStream
						foreach ($Post in $PoSHCommand)
						{
							$PostValue = $Post.Replace("%26","&")
							$PostContent = $PostValue.Split("=")
							$PostName = $PostContent[0].Replace("%3D","=")
							$PostValue = $PostContent[1].Replace("%3D","=")

							if ($PostName.EndsWith("[]"))
							{
								$PostName = $PostName.Substring(0,$PostName.Length-2)

								if (!(New-Object PSObject -Property @{PostName=@()}).PostName)
								{
									$Properties | Add-Member NoteProperty $Postname (@())
									$Properties."$PostName" += $PostValue
								}
								else
								{
									$Properties."$PostName" += $PostValue
								}
							} 
							else
							{
								$Properties | Add-Member NoteProperty $PostName $PostValue
							}
						}
						Write-Output $Properties
					}
				}

				function Get-PoSHQueryString {

				<#
					.SYNOPSIS
					 
						Function to get query string

					.EXAMPLE
					 
						Get-PoSHQueryString -Request $Request
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Request')]
					$Request
				)

					if ($Request)
					{
						$PoSHQueryString = $Request.RawUrl.Split("?")[1]		
						$QueryStrings = $Request.QueryString
						
						$Properties = New-Object Psobject
						$Properties | Add-Member Noteproperty PoSHQueryString $PoSHQueryString
						foreach ($Query in $QueryStrings)
						{
							$QueryString = $Request.QueryString["$Query"]
							if ($QueryString -and $Query)
							{
								$Properties | Add-Member Noteproperty $Query $QueryString
							}
						}
						Write-Output $Properties
					}
				}

				function Get-PoSHWelcomeBanner {

				<#
					.SYNOPSIS
					 
						Function to get welcome banner

					.EXAMPLE
					 
						Get-PoSHWelcomeBanner -Hostname "localhost" -Port "8080" -SSL $True -SSLIP "10.10.10.2" -SSLPort "8443"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'IP Address or Hostname')]
					[Alias('IP')]
					[string]$Hostname,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Port Number')]
					[string]$Port,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Enable SSL')]
					$SSL = $false,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL IP Address')]
					[string]$SSLIP,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL Port Number')]
					[string]$SSLPort,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Debug Mode')]
					$DebugMode = $false
				)
					
					# Get Hostname
					if (!$Hostname -or $Hostname -eq "+") 
					{
						$Hostname = "localhost"
					}
					else
					{
						$Hostname = @($Hostname.Split(","))[0]
					}
					
					# Get Port
					if ($Port -ne "80")
					{
						$Port = ":$Port"
					}
					else
					{
						$Port = $null
					}
					
					if ($SSL)
					{
						# Get SSL Hostname
						if (!$SSLIP -or $SSLIP -eq "+") 
						{
							$SSLIP = "localhost"
						}
						else
						{
							$SSLIP = @($SSLIP.Split(","))[0]
						}
						
						# Get SSL Port
						if ($SSLPort -eq "443")
						{
							$SSLPort = "/"
						}
						else
						{
							$SSLPort = ":$SSLPort"
						}
					}
				}

				function New-PoSHAPIXML {

				<#
					.SYNOPSIS
					 
						Function to create PoSHAPI XML

					.EXAMPLE
					 
						New-PoSHAPIXML -ResultCode "1" -ResultMessage "Service unavailable" -RootTag "Result" -ItemTag "OperationResult" -Details
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Result Code')]
					$ResultCode = "-1",

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Result Message')]
					$ResultMessage = "The operation failed",
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Root Tag')]
					$RootTag = "Result",

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Item Tag')]
					$ItemTag = "OperationResult",
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Child Items')]
					$ChildItems = "*",
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Attributes')]
					$Attributes = $Null,

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Details')]
					$Details = $false
				)

				Begin {
					
					$xml = "<?xml version=""1.0"" encoding=""utf-8""?>`n"
					$xml += "<$RootTag>`n"
					$xml += " <Code>$ResultCode</Code>`n"
					$xml += " <Message>$ResultMessage</Message>`n"
				}

				Process {

					if ($Details)
					{
						$xml += " <$ItemTag"
						if ($Attributes)
						{
							foreach ($attr in $_ | Get-Member -type *Property $attributes)
							{ 
								$name = $attr.Name
								$xml += " $Name=`"$($_.$Name)`""
							}
						}
						$xml += ">`n"
						foreach ($child in $_ | Get-Member -Type *Property $childItems)
						{
							$name = $child.Name
							$xml += " <$Name>$($_.$Name)</$Name>`n"
						}
						$xml += " </$ItemTag>`n"
					}
				}

				End {

					$xml += "</$RootTag>`n"
					$xml
				}
				}

				function Request-PoSHCertificate {

				<#
					.SYNOPSIS
					 
						Function to create PoSH Certificate request

					.EXAMPLE
					 
						Request-PoSHCertificate
						
				#>

					$SSLSubject = "PoSHServer"
					$SSLName = New-Object -com "X509Enrollment.CX500DistinguishedName.1"
					$SSLName.Encode("CN=$SSLSubject", 0)
					$SSLKey = New-Object -com "X509Enrollment.CX509PrivateKey.1"
					$SSLKey.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
					$SSLKey.KeySpec = 1
					$SSLKey.Length = 2048
					$SSLKey.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
					$SSLKey.MachineContext = 1
					$SSLKey.ExportPolicy = 1
					$SSLKey.Create()
					$SSLObjectId = New-Object -com "X509Enrollment.CObjectIds.1"
					$SSLServerId = New-Object -com "X509Enrollment.CObjectId.1"
					$SSLServerId.InitializeFromValue("1.3.6.1.5.5.7.3.1")
					$SSLObjectId.add($SSLServerId)
					$SSLExtensions = New-Object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
					$SSLExtensions.InitializeEncode($SSLObjectId)
					$SSLCert = New-Object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
					$SSLCert.InitializeFromPrivateKey(2, $SSLKey, "")
					$SSLCert.Subject = $SSLName
					$SSLCert.Issuer = $SSLCert.Subject
					$SSLCert.NotBefore = Get-Date
					$SSLCert.NotAfter = $SSLCert.NotBefore.AddDays(1825)
					$SSLCert.X509Extensions.Add($SSLExtensions)
					$SSLCert.Encode()
					$SSLEnrollment = New-Object -com "X509Enrollment.CX509Enrollment.1"
					$SSLEnrollment.InitializeFromRequest($SSLCert)
					$SSLEnrollment.CertificateFriendlyName = 'PoSHServer SSL Certificate'
					$SSLCertdata = $SSLEnrollment.CreateRequest(0)
					$SSLEnrollment.InstallResponse(2, $SSLCertdata, 0, "")
				}

				function Register-PoSHCertificate {

				<#
					.SYNOPSIS
					 
						Function to register PoSH Certificate

					.EXAMPLE
					 
						Register-PoSHCertificate -SSLIP "10.10.10.2" -SSLPort "8443" -Thumbprint "45F53D35AB630198F19A27931283"
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL IP Address')]
					[string]$SSLIP,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL Port Number')]
					[string]$SSLPort,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'SSL Thumbprint')]
					$Thumbprint,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Debug Mode')]
					$DebugMode = $false
				)

					$SSLIPAddresses = @($SSLIP.Split(","))
									
					foreach ($SSLIPAddress in $SSLIPAddresses)
					{
						$IPPort = $SSLIPAddress + ":" + $SSLPort
						
						if ($DebugMode)
						{
							# Remove Previous SSL Bindings
							netsh http delete sslcert ipport="$IPPort"
							
							# Add SSL Certificate
							netsh http add sslcert ipport="$IPPort" certhash="$Thumbprint" appid="{00112233-4455-6677-8899-AABBCCDDEEFF}"
						}
						else
						{		
							# Remove Previous SSL Bindings
							netsh http delete sslcert ipport="$IPPort" | Out-Null
							
							# Add SSL Certificate
							netsh http add sslcert ipport="$IPPort" certhash="$Thumbprint" appid="{00112233-4455-6677-8899-AABBCCDDEEFF}" | Out-Null
						}
					}
				}

				function New-PoSHTimeStamp {

				<#
					.SYNOPSIS
					 
						Function to generate time stamp

					.EXAMPLE
					 
						New-PoSHTimeStamp
						
				#>

					$now = Get-Date
					$hr = $now.Hour.ToString()
					$mi = $now.Minute.ToString()
					$sd = $now.Second.ToString()
					$ms = $now.Millisecond.ToString()
					Write-Output $hr$mi$sd$ms
				}

				function Invoke-AsyncHTTPRequest {

				<#
					.SYNOPSIS
					 
						Function to invoke async HTTP request

					.EXAMPLE
					 
						Invoke-AsyncHTTPRequest
						
				#>

				[CmdletBinding(SupportsShouldProcess = $true)]
				param (

					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Script Block')]
					$ScriptBlock,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Listener')]
					$Listener,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Hostname')]
					$Hostname,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Hostnames')]
					$Hostnames,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Home Directory. Example: C:/inetpub/wwwroot')]
					[string]$HomeDirectory,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'PoSHServer Config Path. Example: C:/inetpub/config.ps1')]
					[string]$PoSHConfigPath,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Log Directory. Example: C:/inetpub/wwwroot')]
					[string]$LogDirectory,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'PoSHServer Module Path')]
					[string]$PoSHModulePath,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Custom Child Config Path')]
					[string]$CustomChildConfig,
					
					[Parameter(
						Mandatory = $false,
						HelpMessage = 'Debug Mode')]
					[switch]$DebugMode = $false
				)

					$Pipeline = [System.Management.Automation.PowerShell]::Create()
					$Pipeline.AddScript($ScriptBlock)
					$Pipeline.AddArgument($Listener)
					$Pipeline.AddArgument($Hostname)
					$Pipeline.AddArgument($Hostnames)
					$Pipeline.AddArgument($HomeDirectory)
					$Pipeline.AddArgument($PoSHConfigPath)
					$Pipeline.AddArgument($LogDirectory)
					$Pipeline.AddArgument($PoSHModulePath)
					$Pipeline.AddArgument($CustomChildConfig)
					$Pipeline.AddArgument($DebugMode)
					$Pipeline.BeginInvoke()
				}
				
				# Enable Debug Mode
				if ($DebugMode)
				{
					$DebugPreference = "Continue"
				}
				else
				{
					$ErrorActionPreference = "silentlycontinue"
				}

				# PoSHServer PHP Encoding
				function Set-PHPEncoding
				{
				param ($PHPOutput)
					
					$EncodingFix = [string]$PHPOutput
					$EncodingFix = $EncodingFix.Replace("─▒","ı")
					$EncodingFix = $EncodingFix.Replace("─░","İ")
					$EncodingFix = $EncodingFix.Replace("┼ş","ş")
					$EncodingFix = $EncodingFix.Replace("┼Ş","Ş")
					$EncodingFix = $EncodingFix.Replace("─ş","ğ")
					$EncodingFix = $EncodingFix.Replace("─Ş","Ğ")
					$EncodingFix = $EncodingFix.Replace("├ğ","ç")
					$EncodingFix = $EncodingFix.Replace("├ç","Ç")
					$EncodingFix = $EncodingFix.Replace("├╝","ü")
					$EncodingFix = $EncodingFix.Replace("├£","Ü")
					$EncodingFix = $EncodingFix.Replace("├Â","ö")
					$EncodingFix = $EncodingFix.Replace("├û","Ö")
					$EncodingFix = $EncodingFix.Replace("ÔÇô","'")
					$EncodingFix
				}
				
				# PoSH Server Custom Child Config
				if ($CustomChildConfig)
				{
					. $CustomChildConfig
				}
				
				# Create loop
				$ShouldProcess = $true
				
				# Get Server Requests
				while ($ShouldProcess)
				{		
					# Test Config Path
					$TestPoSHConfigPath = Test-Path $PoSHConfigPath
					
					if (!$TestPoSHConfigPath)
					{
						# Default Document
						$DefaultDocument = "index.ps1"

						# Log Schedule
						# Options: Hourly, Daily
						$LogSchedule = "Daily"

						# Basic Authentication
						# Options: On, Off
						$BasicAuthentication = "Off"

						# Windows Authentication
						# Options: On, Off
						$WindowsAuthentication = "Off"

						# DirectoryBrowsing
						# Options: On, Off
						$DirectoryBrowsing = "Off"

						# IP Restriction
						# Options: On, Off
						$IPRestriction = "Off"
						$IPWhiteList = "::1 127.0.0.1"

						# Content Filtering
						# Options: On, Off
						$ContentFiltering = "Off"
						$ContentFilterBlackList = "audio/mpeg video/mpeg"

						# PHP Cgi Path
						$PHPCgiPath = ($env:PATH).Split(";") | Select-String "PHP"
						$PHPCgiPath = [string]$PHPCgiPath + "/php-cgi.exe"
					}
					else
					{
						. $PoSHConfigPath
					}
					
					# Reset Authentication
					$Listener.AuthenticationSchemes = "Anonymous";
						
					# Set Authentication
					if ($BasicAuthentication -eq "On") { $Listener.AuthenticationSchemes = "Basic"; }
					if ($NTLMAuthentication -eq "On") { $Listener.AuthenticationSchemes = "NTLM"; }
					if ($WindowsAuthentication -eq "On") { $Listener.AuthenticationSchemes = "IntegratedWindowsAuthentication"; }

					# Open Connection
					$Context = $Listener.GetContext()
					
					# PoSH Server Authentication Module

					# Basic Authentication
					if ($BasicAuthentication -eq "On")
					{
						$Identity = $Context.User.Identity;
						$PoSHUserName = $Identity.Name
						$PoSHUserPassword = $Identity.Password
					}

					# Windows Authentication
					if ($WindowsAuthentication -eq "On")
					{
						$Identity = $Context.User.Identity;
						$PoSHUserName = $Identity.Name
					}
					
					# Set Home Directory
					[IO.Directory]::SetCurrentDirectory("$HomeDirectory")
					$File = $Context.Request.Url.LocalPath
					$Response = $Context.Response
					$Response.Headers.Add("Accept-Encoding","gzip");
					$Response.Headers.Add("Server","PoSH Server");
					$Response.Headers.Add("X-Powered-By","Microsoft PowerShell");
					
					# Set Request Parameters
					$Request = $Context.Request
					$InputStream = $Request.InputStream
					$ContentEncoding = $Request.ContentEncoding
							
					# PoSH Server IP Restriction Module
					$ClientIPAddr = $Request.RemoteEndPoint.Address

					if ($IPRestriction -eq "On")
					{
						if (!($IPWhiteList -match $ClientIPAddr))
						{
							Write-Warning "$ClientIPAddr has no permission, dropping.."
							$IPSessionDrop = "1";
						}
						else
						{
							$IPSessionDrop = "0";
						}
					}
					else
					{
						$IPSessionDrop = "0";
					}
					
					# Get Query String
					$PoSHQuery = Get-PoSHQueryString -Request $Request
					
					# Get Post Stream
					$PoSHPost = Get-PoSHPostStream -InputStream $InputStream -ContentEncoding $ContentEncoding
					
					# Cookie Information
					$PoSHCookies = $Request.Cookies["PoSHSessionID"];
					if (!$PoSHCookies)
					{
						$PoSHCookie = New-Object Net.Cookie
						$PoSHCookie.Name = "PoSHSessionID"
						$PoSHCookie.Value = New-PoSHTimeStamp
						$Response.AppendCookie($PoSHCookie)
					}
					
					# Get Default Document
					if ($File -notlike "*.*" -and $File -like "*/")
					{
						$FolderPath = [System.IO.Directory]::GetCurrentDirectory() + $File
						$RequstURL = [string]$Request.Url
						$SubfolderName = $File
						$File = $File + $DefaultDocument
					}
					elseif ($File -notlike "*.*" -and $File -notlike "*/")
					{
						$FolderPath = [System.IO.Directory]::GetCurrentDirectory() + $File + "/"
						$RequstURL = [string]$Request.Url + "/"
						$SubfolderName = $File + "/"
						$File = $File + "/" + $DefaultDocument 
					}
					else
					{
						$FolderPath = $Null;
					}
					
					# PoSH API Support
					if ($File -like "*.psxml")
					{
						$File = $File.Replace(".psxml",".ps1")
						
						# Full File Path
						$File = [System.IO.Directory]::GetCurrentDirectory() + $File
						
						# Get Mime Type
						$MimeType = "text/psxml"
					}
					else
					{
						# Full File Path
						$File = [System.IO.Directory]::GetCurrentDirectory() + $File
						
						# Get Mime Type
						$FileExtension = (Get-ChildItem $File -EA SilentlyContinue).Extension
						$MimeType = Get-MimeType $FileExtension
					}
					
					# Content Filtering Module
					if ($ContentFiltering -eq "On")
					{
						if ($ContentFilterBlackList -match $MimeType)
						{
							Write-Debug "$MimeType is not allowed, dropping.."
							$ContentSessionDrop = "1";
						}
						else
						{
							$ContentSessionDrop = "0";
						}
					}
					else
					{
						$ContentSessionDrop = "0";
					}
					
					# Stream Content
					if ([System.IO.File]::Exists($File) -and $ContentSessionDrop -eq "0" -and $IPSessionDrop -eq "0")  
					{ 
						if ($MimeType -eq "text/ps1")
						{
							try
							{
								$Response.ContentType = "text/html"
								$Response.StatusCode = [System.Net.HttpStatusCode]::OK
								$LogResponseStatus = $Response.StatusCode
								$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
								$Response.WriteLine("$(. $File)")
							}
							catch
							{
								Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
							}
						}
						elseif ($MimeType -eq "text/psxml")
						{
							try
							{
								$Response.ContentType = "text/xml"
								$Response.StatusCode = [System.Net.HttpStatusCode]::OK
								$LogResponseStatus = $Response.StatusCode
								$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
								$Response.WriteLine("$(. $File)")
							}
							catch
							{
								Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
							}
						}
						elseif ($MimeType -eq "text/php")
						{
							try
							{
								if ($PHPCgiPath)
								{
									$TestPHPCgiPath = Test-Path -Path $PHPCgiPath
								}
								else
								{
									$TestPHPCgiPath = $false
								}
								
								if ($TestPHPCgiPath)
								{
									if ($File -like "C:/Windows/*")
									{
										$Response.ContentType = "text/html"
										$Response.StatusCode = [System.Net.HttpStatusCode]::NotFound
										$LogResponseStatus = $Response.StatusCode
										$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
										$Response.WriteLine("PHP Security Error!")
									}
									else
									{
										$Response.ContentType = "text/html"
										$PHPContentOutput = Get-PoSHPHPContent -PHPCgiPath "$PHPCgiPath" -File "$File" -PoSHPHPGET $PoSHQuery.PoSHQueryString -PoSHPHPPOST $PoSHPost.PoSHPostStream
										$PHPContentOutput = Set-PHPEncoding -PHPOutput $PHPContentOutput
										$Response.StatusCode = [System.Net.HttpStatusCode]::OK
										$LogResponseStatus = $Response.StatusCode
										$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
										$Response.WriteLine("$PHPContentOutput")
									}
								}
								else
								{
									$Response.ContentType = "text/html"
									$Response.StatusCode = [System.Net.HttpStatusCode]::NotFound
									$LogResponseStatus = $Response.StatusCode
									$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
									$Response.WriteLine("PHP Cgi Error!")						
								}
							}
							catch
							{
								Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
							}
						}				
						else
						{
							try
							{
								$Response.ContentType = "$MimeType"
								$FileContent = [System.IO.File]::ReadAllBytes($File)
								$Response.ContentLength64 = $FileContent.Length
								$Response.StatusCode = [System.Net.HttpStatusCode]::OK
								$LogResponseStatus = $Response.StatusCode
								$Response.OutputStream.Write($FileContent, 0, $FileContent.Length)
							}
							catch
							{
								Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
							}
						}
					}
					else
					{
						# Content Filtering and IP Restriction Control
						if ($ContentSessionDrop -eq "0" -and $IPSessionDrop -eq "0")
						{
							if ($FolderPath)
							{
								$TestFolderPath = Test-Path -Path $FolderPath
							}
							else
							{
								$TestFolderPath = $false
							}
						}
						else
						{
							$TestFolderPath = $false
						}
						
						if ($DirectoryBrowsing -eq "On" -and $TestFolderPath)
						{
							try
							{
								$Response.ContentType = "text/html"
								$Response.StatusCode = [System.Net.HttpStatusCode]::OK
								$LogResponseStatus = $Response.StatusCode
								$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
								if ($Hostname -eq "+") { $HeaderName = "localhost" } else { $HeaderName = $Hostnames[0] }
								$DirectoryContent = (Get-DirectoryContent -Path "$FolderPath" -HeaderName $HeaderName -RequestURL $RequestURL -SubfolderName $SubfolderName)
								$Response.WriteLine("$DirectoryContent")
							}
							catch
							{
								Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
							}
						}
						else
						{
							try
							{
								$Response.ContentType = "text/html"
								$Response.StatusCode = [System.Net.HttpStatusCode]::NotFound
								$LogResponseStatus = $Response.StatusCode
								$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
								$Response.WriteLine("File not found!")
							}
							catch
							{
								Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
							}
						}
					}
					
					# PoSH Server Logging Module
					# Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem s-port c-ip cs-version cs(User-Agent) cs(Cookie) cs(Referer) cs-host sc-status
					$LogDate = Get-Date -format yyyy-MM-dd
					$LogTime = Get-Date -format HH:mm:ss
					$LogSiteName = $Hostname
					if ($LogSiteName -eq "+") { $LogSiteName = "localhost" }
					$LogComputerName = Get-Content env:computername
					$LogServerIP = $Request.LocalEndPoint.Address
					$LogMethod = $Request.HttpMethod
					$LogUrlStem = $Request.RawUrl
					$LogServerPort = $Request.LocalEndPoint.Port
					$LogClientIP = $Request.RemoteEndPoint.Address
					$LogClientVersion = $Request.ProtocolVersion
					if (!$LogClientVersion) { $LogClientVersion = "-" } else { $LogClientVersion = "HTTP/" + $LogClientVersion }
					$LogClientAgent = [string]$Request.UserAgent
					if (!$LogClientAgent) { $LogClientAgent = "-" } else { $LogClientAgent = $LogClientAgent.Replace(" ","+") }
					$LogClientCookie = [string]$Response.Cookies.Value
					if (!$LogClientCookie) { $LogClientCookie = "-" } else { $LogClientCookie = $LogClientCookie.Replace(" ","+") }
					$LogClientReferrer = [string]$Request.UrlReferrer
					if (!$LogClientReferrer) { $LogClientReferrer = "-" } else { $LogClientReferrer = $LogClientReferrer.Replace(" ","+") }
					$LogHostInfo = [string]$LogServerIP + ":" + [string]$LogServerPort

					# Log Output
					$LogOutput = "$LogDate $LogTime $LogSiteName $LogComputerName $LogServerIP $LogMethod $LogUrlStem $LogServerPort $LogClientIP $LogClientVersion $LogClientAgent $LogClientCookie $LogClientReferrer $LogHostInfo $LogResponseStatus"

					# Logging to Log File
					if ($LogSchedule -eq "Hourly")
					{
						$LogNameFormat = Get-Date -format yyMMddHH
						$LogFileName = "u_ex" + $LogNameFormat + ".log"
						$LogFilePath = $LogDirectory + "/" + $LogFileName
					}
					else
					{
						$LogNameFormat = Get-Date -format yyMMdd
						$LogFileName = "u_ex" + $LogNameFormat + ".log"
						$LogFilePath = $LogDirectory + "/" + $LogFileName
					}

					if ($LastCheckDate -ne $LogNameFormat)
					{
						if (![System.IO.File]::Exists($LogFilePath))  
						{
							$LogHeader = "#Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem s-port c-ip cs-version cs(User-Agent) cs(Cookie) cs(Referer) cs-host sc-status"
							Add-Content -Path $LogFilePath -Value $LogHeader -EA SilentlyContinue
						}
						
						# Set Last Check Date
						$LastCheckDate = $LogNameFormat
					}

					try
					{
						Add-Content -Path $LogFilePath -Value $LogOutput -EA SilentlyContinue
					}
					catch
					{
						Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
					}
					
					# Close Connection
					try
					{
						$Response.Close()
					}
					catch
					{
						Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
					}
				}	
			}
			
			if ($DebugMode)
			{	
				# Invoke PoSH Server Multithread Process - Thread 1
				Invoke-AsyncHTTPRequest -ScriptBlock $ScriptBlock -Listener $Listener -Hostname $Hostname -Hostnames $Hostnames -HomeDirectory $HomeDirectory -PoSHConfigPath $PoSHConfigPath -LogDirectory $LogDirectory -PoSHModulePath $PoSHModulePath -CustomChildConfig $CustomChildConfig -DebugMode | Out-Null
				
				# Invoke PoSH Server Multithread Process - Thread 2
				Invoke-AsyncHTTPRequest -ScriptBlock $ScriptBlock -Listener $Listener -Hostname $Hostname -Hostnames $Hostnames -HomeDirectory $HomeDirectory -PoSHConfigPath $PoSHConfigPath -LogDirectory $LogDirectory -PoSHModulePath $PoSHModulePath -CustomChildConfig $CustomChildConfig -DebugMode | Out-Null
				
				# Invoke PoSH Server Multithread Process - Thread 3
				Invoke-AsyncHTTPRequest -ScriptBlock $ScriptBlock -Listener $Listener -Hostname $Hostname -Hostnames $Hostnames -HomeDirectory $HomeDirectory -PoSHConfigPath $PoSHConfigPath -LogDirectory $LogDirectory -PoSHModulePath $PoSHModulePath -CustomChildConfig $CustomChildConfig -DebugMode | Out-Null
			}
			else
			{
				# Invoke PoSH Server Multithread Process - Thread 1
				Invoke-AsyncHTTPRequest -ScriptBlock $ScriptBlock -Listener $Listener -Hostname $Hostname -Hostnames $Hostnames -HomeDirectory $HomeDirectory -PoSHConfigPath $PoSHConfigPath -LogDirectory $LogDirectory -PoSHModulePath $PoSHModulePath -CustomChildConfig $CustomChildConfig | Out-Null
				
				# Invoke PoSH Server Multithread Process - Thread 2
				Invoke-AsyncHTTPRequest -ScriptBlock $ScriptBlock -Listener $Listener -Hostname $Hostname -Hostnames $Hostnames -HomeDirectory $HomeDirectory -PoSHConfigPath $PoSHConfigPath -LogDirectory $LogDirectory -PoSHModulePath $PoSHModulePath -CustomChildConfig $CustomChildConfig | Out-Null
				
				# Invoke PoSH Server Multithread Process - Thread 3
				Invoke-AsyncHTTPRequest -ScriptBlock $ScriptBlock -Listener $Listener -Hostname $Hostname -Hostnames $Hostnames -HomeDirectory $HomeDirectory -PoSHConfigPath $PoSHConfigPath -LogDirectory $LogDirectory -PoSHModulePath $PoSHModulePath -CustomChildConfig $CustomChildConfig | Out-Null
			}
			
			# Create loop
			$ShouldProcess = $true
			
			# Get Server Requests
			while ($ShouldProcess)
			{
				# Test Config Path
				$TestPoSHConfigPath = Test-Path $PoSHConfigPath
				
				if (!$TestPoSHConfigPath)
				{
					# Default Document
					$DefaultDocument = "index.ps1"

					# Log Schedule
					# Options: Hourly, Daily
					$LogSchedule = "Daily"

					# Basic Authentication
					# Options: On, Off
					$BasicAuthentication = "Off"

					# Windows Authentication
					# Options: On, Off
					$WindowsAuthentication = "Off"

					# DirectoryBrowsing
					# Options: On, Off
					$DirectoryBrowsing = "Off"

					# IP Restriction
					# Options: On, Off
					$IPRestriction = "Off"
					$IPWhiteList = "::1 127.0.0.1"

					# Content Filtering
					# Options: On, Off
					$ContentFiltering = "Off"
					$ContentFilterBlackList = "audio/mpeg video/mpeg"

					# PHP Cgi Path
					$PHPCgiPath = ($env:PATH).Split(";") | Select-String "PHP"
					$PHPCgiPath = [string]$PHPCgiPath + "/php-cgi.exe"
				}
				else
				{
					. $PoSHConfigPath
				}
				
				# Reset Authentication
				$Listener.AuthenticationSchemes = "Anonymous";
					
				# Set Authentication
				if ($BasicAuthentication -eq "On") { $Listener.AuthenticationSchemes = "Basic"; }
				if ($NTLMAuthentication -eq "On") { $Listener.AuthenticationSchemes = "NTLM"; }
				if ($WindowsAuthentication -eq "On") { $Listener.AuthenticationSchemes = "IntegratedWindowsAuthentication"; }

				# Open Connection
				$Context = $Listener.GetContext()
				
				# PoSH Server Authentication Module

				# Basic Authentication
				if ($BasicAuthentication -eq "On")
				{
					$Identity = $Context.User.Identity;
					$PoSHUserName = $Identity.Name
					$PoSHUserPassword = $Identity.Password
				}

				# Windows Authentication
				if ($WindowsAuthentication -eq "On")
				{
					$Identity = $Context.User.Identity;
					$PoSHUserName = $Identity.Name
				}
							
				# Set Home Directory
				[IO.Directory]::SetCurrentDirectory("$HomeDirectory")
				$File = $Context.Request.Url.LocalPath
				$Response = $Context.Response
				$Response.Headers.Add("Accept-Encoding","gzip");
				$Response.Headers.Add("Server","PoSH Server");
				$Response.Headers.Add("X-Powered-By","Microsoft PowerShell");
				
				# Set Request Parameters
				$Request = $Context.Request
				$InputStream = $Request.InputStream
				$ContentEncoding = $Request.ContentEncoding
						
				# IP Restriction Module
				$ClientIPAddr = $Request.RemoteEndPoint.Address

				if ($IPRestriction -eq "On")
				{
					if (!($IPWhiteList -match $ClientIPAddr))
					{
						Write-Warning "$ClientIPAddr has no permission, dropping.."
						$IPSessionDrop = "1";
					}
					else
					{
						$IPSessionDrop = "0";
					}
				}
				else
				{
					$IPSessionDrop = "0";
				}
				
				# Get Query String
				$PoSHQuery = Get-PoSHQueryString -Request $Request
				
				# Get Post Stream
				$PoSHPost = Get-PoSHPostStream -InputStream $InputStream -ContentEncoding $ContentEncoding
				
				# Cookie Information
				$PoSHCookies = $Request.Cookies["PoSHSessionID"];
				if (!$PoSHCookies)
				{
					$PoSHCookie = New-Object Net.Cookie
					$PoSHCookie.Name = "PoSHSessionID"
					$PoSHCookie.Value = New-PoSHTimeStamp
					$Response.AppendCookie($PoSHCookie)
				}
				
				# Get Default Document
				if ($File -notlike "*.*" -and $File -like "*/")
				{
					$FolderPath = [System.IO.Directory]::GetCurrentDirectory() + $File
					$RequstURL = [string]$Request.Url
					$SubfolderName = $File
					$File = $File + $DefaultDocument
				}
				elseif ($File -notlike "*.*" -and $File -notlike "*/")
				{
					$FolderPath = [System.IO.Directory]::GetCurrentDirectory() + $File + "/"
					$RequstURL = [string]$Request.Url + "/"
					$SubfolderName = $File + "/"
					$File = $File + "/" + $DefaultDocument 
				}
				else
				{
					$FolderPath = $Null;
				}
				
				# PoSH API Support
				if ($File -like "*.psxml")
				{
					$File = $File.Replace(".psxml",".ps1")
					
					# Full File Path
					$File = [System.IO.Directory]::GetCurrentDirectory() + $File
					
					# Get Mime Type
					$MimeType = "text/psxml"
				}
				else
				{
					# Full File Path
					$File = [System.IO.Directory]::GetCurrentDirectory() + $File
					
					# Get Mime Type
					$FileExtension = (Get-ChildItem $File -EA SilentlyContinue).Extension
					$MimeType = Get-MimeType $FileExtension
				}
				
				# Content Filtering Module
				if ($ContentFiltering -eq "On")
				{
					if ($ContentFilterBlackList -match $MimeType)
					{
						Write-Debug "$MimeType is not allowed, dropping.."
						$ContentSessionDrop = "1";
					}
					else
					{
						$ContentSessionDrop = "0";
					}
				}
				else
				{
					$ContentSessionDrop = "0";
				}
				
				# Stream Content
				if ([System.IO.File]::Exists($File) -and $ContentSessionDrop -eq "0" -and $IPSessionDrop -eq "0")  
				{ 
					if ($MimeType -eq "text/ps1")
					{
						try
						{
							$Response.ContentType = "text/html"
							$Response.StatusCode = [System.Net.HttpStatusCode]::OK
							$LogResponseStatus = $Response.StatusCode
							$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
							$Response.WriteLine("$(. $File)")
						}
						catch
						{
							Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
						}
					}
					elseif ($MimeType -eq "text/psxml")
					{
						try
						{
							$Response.ContentType = "text/xml"
							$Response.StatusCode = [System.Net.HttpStatusCode]::OK
							$LogResponseStatus = $Response.StatusCode
							$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
							$Response.WriteLine("$(. $File)")
						}
						catch
						{
							Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
						}
					}
					elseif ($MimeType -eq "text/php")
					{
						try
						{
							if ($PHPCgiPath)
							{
								$TestPHPCgiPath = Test-Path -Path $PHPCgiPath
							}
							else
							{
								$TestPHPCgiPath = $false
							}
							
							if ($TestPHPCgiPath)
							{
								if ($File -like "C:/Windows/*")
								{
									$Response.ContentType = "text/html"
									$Response.StatusCode = [System.Net.HttpStatusCode]::NotFound
									$LogResponseStatus = $Response.StatusCode
									$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
									$Response.WriteLine("PHP Security Error!")
								}
								else
								{
									$Response.ContentType = "text/html"
									$PHPContentOutput = Get-PoSHPHPContent -PHPCgiPath "$PHPCgiPath" -File "$File" -PoSHPHPGET $PoSHQuery.PoSHQueryString -PoSHPHPPOST $PoSHPost.PoSHPostStream
									$PHPContentOutput = Set-PHPEncoding -PHPOutput $PHPContentOutput
									$Response.StatusCode = [System.Net.HttpStatusCode]::OK
									$LogResponseStatus = $Response.StatusCode
									$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
									$Response.WriteLine("$PHPContentOutput")
								}
							}
							else
							{
								$Response.ContentType = "text/html"
								$Response.StatusCode = [System.Net.HttpStatusCode]::NotFound
								$LogResponseStatus = $Response.StatusCode
								$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
								$Response.WriteLine("PHP Cgi Error!")						
							}
						}
						catch
						{
							Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
						}
					}				
					else
					{
						try
						{
							$Response.ContentType = "$MimeType"
							$FileContent = [System.IO.File]::ReadAllBytes($File)
							$Response.ContentLength64 = $FileContent.Length
							$Response.StatusCode = [System.Net.HttpStatusCode]::OK
							$LogResponseStatus = $Response.StatusCode
							$Response.OutputStream.Write($FileContent, 0, $FileContent.Length)
						}
						catch
						{
							Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
						}
					}
				}
				else
				{
					# Content Filtering and IP Restriction Control
					if ($ContentSessionDrop -eq "0" -and $IPSessionDrop -eq "0")
					{
						if ($FolderPath)
						{
							$TestFolderPath = Test-Path -Path $FolderPath
						}
						else
						{
							$TestFolderPath = $false
						}
					}
					else
					{
						$TestFolderPath = $false
					}
					
					if ($DirectoryBrowsing -eq "On" -and $TestFolderPath)
					{
						try
						{
							$Response.ContentType = "text/html"
							$Response.StatusCode = [System.Net.HttpStatusCode]::OK
							$LogResponseStatus = $Response.StatusCode
							$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
							if ($Hostname -eq "+") { $HeaderName = "localhost" } else { $HeaderName = $Hostnames[0] }
							$DirectoryContent = (Get-DirectoryContent -Path "$FolderPath" -HeaderName $HeaderName -RequestURL $RequestURL -SubfolderName $SubfolderName)
							$Response.WriteLine("$DirectoryContent")
						}
						catch
						{
							Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
						}
					}
					else
					{
						try
						{
							$Response.ContentType = "text/html"
							$Response.StatusCode = [System.Net.HttpStatusCode]::NotFound
							$LogResponseStatus = $Response.StatusCode
							$Response = New-Object IO.StreamWriter($Response.OutputStream,[Text.Encoding]::UTF8)
							$Response.WriteLine("File not found!")
						}
						catch
						{
							Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
						}
					}
				}
				
				# PoSH Server Logging Module
				# Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem s-port c-ip cs-version cs(User-Agent) cs(Cookie) cs(Referer) cs-host sc-status
				$LogDate = Get-Date -format yyyy-MM-dd
				$LogTime = Get-Date -format HH:mm:ss
				$LogSiteName = $Hostname
				if ($LogSiteName -eq "+") { $LogSiteName = "localhost" }
				$LogComputerName = Get-Content env:computername
				$LogServerIP = $Request.LocalEndPoint.Address
				$LogMethod = $Request.HttpMethod
				$LogUrlStem = $Request.RawUrl
				$LogServerPort = $Request.LocalEndPoint.Port
				$LogClientIP = $Request.RemoteEndPoint.Address
				$LogClientVersion = $Request.ProtocolVersion
				if (!$LogClientVersion) { $LogClientVersion = "-" } else { $LogClientVersion = "HTTP/" + $LogClientVersion }
				$LogClientAgent = [string]$Request.UserAgent
				if (!$LogClientAgent) { $LogClientAgent = "-" } else { $LogClientAgent = $LogClientAgent.Replace(" ","+") }
				$LogClientCookie = [string]$Response.Cookies.Value
				if (!$LogClientCookie) { $LogClientCookie = "-" } else { $LogClientCookie = $LogClientCookie.Replace(" ","+") }
				$LogClientReferrer = [string]$Request.UrlReferrer
				if (!$LogClientReferrer) { $LogClientReferrer = "-" } else { $LogClientReferrer = $LogClientReferrer.Replace(" ","+") }
				$LogHostInfo = [string]$LogServerIP + ":" + [string]$LogServerPort

				# Log Output
				$LogOutput = "$LogDate $LogTime $LogSiteName $LogComputerName $LogServerIP $LogMethod $LogUrlStem $LogServerPort $LogClientIP $LogClientVersion $LogClientAgent $LogClientCookie $LogClientReferrer $LogHostInfo $LogResponseStatus"

				# Logging to Log File
				if ($LogSchedule -eq "Hourly")
				{
					$LogNameFormat = Get-Date -format yyMMddHH
					$LogFileName = "u_ex" + $LogNameFormat + ".log"
					$LogFilePath = $LogDirectory + "/" + $LogFileName
				}
				else
				{
					$LogNameFormat = Get-Date -format yyMMdd
					$LogFileName = "u_ex" + $LogNameFormat + ".log"
					$LogFilePath = $LogDirectory + "/" + $LogFileName
				}

				if ($LastCheckDate -ne $LogNameFormat)
				{
					if (![System.IO.File]::Exists($LogFilePath))  
					{
						$LogHeader = "#Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem s-port c-ip cs-version cs(User-Agent) cs(Cookie) cs(Referer) cs-host sc-status"
						Add-Content -Path $LogFilePath -Value $LogHeader -EA SilentlyContinue
					}
					
					# Set Last Check Date
					$LastCheckDate = $LogNameFormat
				}

				try
				{
					Add-Content -Path $LogFilePath -Value $LogOutput -EA SilentlyContinue
				}
				catch
				{
					Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
				}
				
				# Close Connection
				try
				{
					$Response.Close()
				}
				catch
				{
					Add-Content -Value $_ -Path "$LogDirectory/debug.txt"
				}
			}
			
			# Stop Listener
			$Listener.Stop()
		}
	}
}

# Set Silent Mode
$ErrorActionPreference = "silentlycontinue"

# Confirm Administrative Priviliges
# Welcome Banner
Write-Host " "
Write-Host "  Welcome to PoSH Server"
Write-Host " "
Write-Host " "
Write-Host "  You can start browsing your webpage from:"
Write-Host "  http://localhost:8080"
Write-Host " "
Write-Host " "
Write-Host "  Thanks for using PoSH Server.."
Write-Host " "
Write-Host " "
Write-Host " "

Start-StandalonePoSHServer -Port 80 -HomeDirectory "$HOME/www"