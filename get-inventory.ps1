## Nate Caprioli
## Inventory Script that output to a csv (later a nice report) 
## Requirements:  Must be run from a PC with RSAT installed. 
## Pre-Requisites: Must have a local account/domain account with WinRM configured
## Out-HTMLView - needed for data output, **Requires Admin rights to install.  
## Some code involving some math as a ref: | Select DeviceID,@{n='FreeSpace';e={$_.FreeSpace / 1GB -as [int]}},@{n='RemainingSpace';e={($_.Size / 1GB -as [int]) - ($_.FreeSpace / 1GB) -as [int]}}

## Out-HTMLView - needed for data output, **Requires Admin rights to install.
Install-Module PSWriteHTML -Force


## Overall goals of this script:
## Collect ALL PC Names on the network, their IP addresses, hostname, mac address, OSVersion, Manufacturer, Model, SerialNumber of Board,
## Bios Version, Processor, Sockets/Cores, Memory, GPU, LastReboot, LastPatchDate, Hard Drive info, Network Adapter info, Share info
## 

## Error Action 
$ErrorActionPreference = "silentlyContinue"

## Selects PDC 

$PDC1 = Get-dhcpserverindc | select-object -ExpandProperty DnsName

## Get's subnet from DHCP server

$DHCPsubnet = Get-DhcpServerv4Scope -computername $PDC1 | select-object -ExpandProperty SubnetMask | Select-Object -ExpandProperty IPAddressToString

## Gets first three o
### New Code first three octets  
## Credit to furmelade on irc.freenode.net/##sysadmin-casual
$BeginOctet = (((Get-NetIPConfiguration | select -expand ipv4defaultgateway).nexthop).split('.') | select -First 3) -join '.'

## Begin/End IP Address
$BeginIP = 1
$EndIP = 254

$OutputArray = @()

## If Subnet is /24 then run scan. 
if ($DHCPsubnet = '255.255.255.0') {
    
    
  while ($BeginIP -le $EndIP) {
    ## Tests if connection is alive for pulling data.
    if ((Test-Connection -ComputerName $BeginOctet'.'$beginIP -Quiet -Count 1)) {
      ## Gets Mac address of device via get-neighbor
      $getmac = Get-NetNeighbor | Where-Object { $_.IPAddress -eq "$beginOctet.$BeginIP" } | Select-Object -ExpandProperty LinkLayerAddress

      ## Gets hostname via .net PS
      $gethostname = Resolve-DnsName -QuickTimeout -Name "$BeginOctet.$BeginIP" -EA SilentlyContinue | Select-Object -ExpandProperty NameHost 
        
      ## Some logic to check if hostname is null, if not then continue
      if ($gethostname -notlike $null) {
        ## Enters PSSession
        $session = New-PSSession -ComputerName $gethostname
        if ($session) {

          ## Gets OS Version(windows only currently)
          $getOSver = invoke-command -Session $session -EA SilentlyContinue -scriptblock { (Get-WmiObject win32_operatingsystem).Caption }

          ## Gets IP Address Only
          $getIPAddress = invoke-command -Session $session -EA SilentlyContinue -ScriptBlock { get-wmiobject -class win32_networkadapterconfiguration -filter 'IPenabled = "true"' | select -expand IPAddress }
          Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { $wmiCompObject = Get-WmiObject -Class win32_ComputerSystem }
          Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { $wmiProcObject = Get-WmiObject -Class Win32_Processor }
          Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { $wmiBIOSObject = Get-WmiObject -Class Win32_BIOS }

          ## Gets Hardware Information
          $getMfg = invoke-command -Session $session -EA SilentlyContinue -scriptblock { $wmiCompObject.Manufacturer }
          $getModel = invoke-command -Session $session -EA SilentlyContinue -scriptblock { $wmiCompObject.Model }
          $getSerial = invoke-command -Session $session -EA SilentlyContinue -ScriptBlock { $wmiBIOSObject.SerialNumber }
          $getProc = invoke-command -Session $session -EA SilentlyContinue -ScriptBlock { $wmiProcObject.Name | select -first 1 }
          $getPCores = Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { $wmiCompObject.NumberOfProcessors }
          $getTCores = invoke-command -Session $session -EA SilentlyContinue -ScriptBlock { $wmiProcObject | select -expand NumberOfLogicalProcessors | select -first 1 }
          $getMem = invoke-command -Session $session -EA SilentlyContinue -scriptblock { [math]::round($wmiCompObject.TotalPhysicalMemory / 1024MB ) }
          $getGPU = invoke-command -Session $session -EA SilentlyContinue -scriptblock { (Get-WmiObject -class:Win32_VideoController).Name }
          $getLastReboot = Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { (Get-CimInstance -ClassName win32_operatingsystem).LastBootUpTime }
          $getLogicalDriveModel = Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { (Get-WmiObject -Class win32_diskdrive | Select-Object Model, SerialNumber, Caption, @{Name = "SizeinGB"; Expression = { [math]::Round($_.Size / 1GB) } }) }
          $getNetworkAdapters = invoke-command -Session $session -EA SilentlyContinue -ScriptBlock { get-wmiobject -class win32_networkadapterconfiguration -filter 'IPenabled = "true"' | Select-Object IPAddress, DefaultIPGateway, Description, DHCPEnabled }
          $getHDDSpace = Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { (Get-WmiObject -class win32_logicaldisk | where-object { $_.DeviceID -ne 'A:' -and $_.DeviceID -ne 'D:' }  ) }
          # | Select DeviceID,@{n='FreeSpace';e={$_.FreeSpace / 1GB -as [int]}},@{n='RemainingSpace';e={($_.Size / 1GB -as [int]) - ($_.FreeSpace / 1GB) -as [int]}}

          ## Gets Software Information
          $getLastUser = Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { $Path = 'HKLM:\Software\Microsoft\windows\currentVersion\Authentication\LogonUI' ; Get-ItemProperty -Path $Path -Name LastLoggedOnUser | Select -ExpandProperty LastLoggedOnUser }
          $getLastPatch = Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { (Get-WmiObject -Class win32_quickfixengineering).InstalledOn | Sort-Object | Select -last 1 }
          $getBiosVer = Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { $wmiBIOSObject.SMBIOSBIOSVERSION }
          $getShareInfo = Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { Get-WmiObject -Class win32_share }
          $getPendingUpdates = Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { if (-not(gci -Path C:\temp)) { mkdir C:\temp ; [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" ; (New-Object System.Net.WebClient).DownloadFile('https://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542/file/139923/3/Get-PendingReboot.ps1', 'C:\temp\Get-PendingReboot.ps1')  ; import-module C:\temp\Get-PendingReboot.ps1 ; Get-PendingReboot } else { [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" ; (New-Object System.Net.WebClient).DownloadFile('https://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542/file/139923/3/Get-PendingReboot.ps1', 'C:\temp\Get-PendingReboot.ps1') ; import-module 'C:\temp\Get-PendingReboot.ps1' ; Get-PendingReboot } }
          $getFireWallStatus = Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { (Get-NetFirewallProfile) }
          $getInstalledSoftware = Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*) }
          $getPSVersion = Invoke-Command -Session $session -EA SilentlyContinue -ScriptBlock { ($PSVersionTable.PSVersion).Major }

          ## Share stuff
          $Test = $getShareInfo.Name | Select-String -Pattern '$IPC' -NotMatch

          ## Creats an unnamed array for the HDD Information, selects the info, writes each to a string then removes commas and adds line breaks etc
          $HDDInfoArray = @()
          $HDDInfoArray += $getHDDspace | select DeviceID, FreeSpace, RemainingSpace -expand
          $FinalHDD = $HDDInfoArray -replace “\n\r”, ””

          ## Creates an unnamed array for the Installed Software, writes each to a string then removes the commas and adds line breaks etc.
          $SoftwareInfoArray = @()
          $SoftwareInfoArray += $getInstalledSoftware | select DisplayName, DisplayVersion, Publisher, InstallDate -expand | ft | Out-string
          $FinalSoftware = $SoftwareInfoArray -replace “\n\r”, ”” | Out-string
      
          ## Start writing for the actual reporting version
          $testOutput = 
          @([pscustomobject]@{
              Hostname          = $gethostname | Out-String;
              LastUser          = $getLastUser | Out-String;
              IPAddress         = $getNetworkAdapters.IPAddress | Out-String;
              MacAddress        = $getmac | Out-String;
              OSVersion         = $getOSver | Out-String;
              ShareName         = $getShareInfo.Name | Out-String;
              SharePath         = $getShareInfo | ForEach-Object { $_.Path + '.' } | Out-String;
              ShareDesc         = $getShareInfo | foreach-object { $_.Description + '.' } | Out-String;
              HDDLetter         = $getHDDSpace.DeviceID | Out-String;
              HDDUsedSpaceGB    = $getHDDSpace | ForEach-Object { ($_.Size / 1GB -as [int]) - ($_.FreeSpace / 1GB) -as [int] } | out-string;
              HDDFreeSpaceGB    = $getHDDSpace | ForEach-Object { ($_.FreeSpace / 1GB) -as [int] } | out-string ;
              Manufacturer      = $getMfg | Out-String;
              Model             = $getModel | Out-String;
              SerialNumber      = $getSerial | Out-String;
              BiosVersion       = $getBiosVer | Out-String;
              Processor         = $getProc | Out-String;
              Sockets           = $getPCores | Out-String;
              Cores             = $getTCores | Out-String;
              Memory            = $getMem | Out-String;
              GPU               = $getGPU | Out-String;
              LastReboot        = $getLastReboot | Out-String;
              LastPatchDate     = $getLastPatch | Out-String;
              PSVersion         = $getPSVersion | Out-String;
              HardDriveModel    = $getLogicalDriveModel.Model | Out-String;
              HardDriveSerial   = $getLogicalDriveModel.SerialNumber | Out-String;
              HardDriveSizeinGB = $getLogicalDriveModel.SizeInGB | Out-String;
              IPAddressForRef   = $getNetworkAdapters.IPAddress | Out-String;
              DefaultGateway    = $getNetworkAdapters.DefaultIPGateway | Out-String;
              NetAdapterDesc    = $getNetworkAdapters.Description | Out-String;
              DCHPEnabled       = $getNetworkAdapters.DHCPEnabled | Out-String;
              ComputerName      = $getNetworkAdapters.PSComputerName | Out-String;
              PendingUpdates    = $getPendingUpdates.WindowsUpdate | Out-String;
              PendingCompRen    = $getPendingUpdates.PendComputerRename | Out-String;
              PendingFileRen    = $getPendingUpdates.PendFileRename | Out-String;
              PendingReboot     = $getPendingUpdates.RebootPending | Out-String;
              WindowsFWprofile  = $getFireWallStatus.Name | Out-String;
              WindowsFWStatus   = $getFireWallStatus.enabled | ForEach-Object { if ($_ -eq '1') { Write-Output Enabled } } | Out-String;
            

            })


          ## This forces the output to not use elipsis and truncate our data
          $FormatEnumerationLimit = -1
          ## This outputs everything into one grid for single pane viewing pleasure
          $OutputArray += $testOutput
        
          ## After all code is ran, ups the integer number by 1
          $beginIP++
          Exit-PSSession
        }
        else {
          Write-Output "Hostname: $gethostname IPAddress: $beginOctet.$beginIP MacAddress: $getmac  OSVersion: N/A `n"
          $beginIP++
        }
      }
        
      ## Continuation of the if $gethostname is $null else statement)
      else {   

        Write-Output "Hostname: N/A $gethostname IPAddress: $beginOctet.$beginIP MacAddress: $getmac OSVersion: N/A `n"
        $beginIP++
        continue
      }
    }
        
        
        
    else {
      $BeginIP++
    }
  }
}

$OutputArray | Out-HtmlView -Style nowrap -ScrollX
