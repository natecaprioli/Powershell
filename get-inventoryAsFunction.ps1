function get-inventory {  
  Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
  


  $getmac = get-netadapter | Sort-Object number | select -First 1 | select -expand MacAddress

  ## Gets hostname via .net PS
  $gethostname = $env:COMPUTERNAME

  ## Gets OS Version(windows only currently)
  $getOSver = (Get-WmiObject win32_operatingsystem).Caption 

  ## Gets IP Address Only
  $getIPAddress = get-wmiobject -class win32_networkadapterconfiguration -filter 'IPenabled = "true"' | select -expand IPAddress 
  $wmiCompObject = Get-WmiObject -Class win32_ComputerSystem 
  $wmiProcObject = Get-WmiObject -Class Win32_Processor 
  $wmiBIOSObject = Get-WmiObject -Class Win32_BIOS 

  ## Gets Hardware Information
  $getMfg = $wmiCompObject.Manufacturer 
  $getModel = $wmiCompObject.Model 
  $getSerial = $wmiBIOSObject.SerialNumber 
  $getProc = $wmiProcObject.Name | select -first 1 
  $getPCores = $wmiCompObject.NumberOfProcessors 
  $getTCores = $wmiProcObject | select -expand NumberOfLogicalProcessors | select -first 1 
  $getMem = [math]::round($wmiCompObject.TotalPhysicalMemory / 1024MB ) 
  $getGPU = (Get-WmiObject -class:Win32_VideoController).Name 
  $getLastReboot = (Get-CimInstance -ClassName win32_operatingsystem).LastBootUpTime 
  $getLogicalDriveModel = (Get-WmiObject -Class win32_diskdrive | Select-Object Model, SerialNumber, Caption, @{Name = "SizeinGB"; Expression = { [math]::Round($_.Size / 1GB) } }) 
  $getNetworkAdapters = get-wmiobject -class win32_networkadapterconfiguration -filter 'IPenabled = "true"' | Select-Object IPAddress, DefaultIPGateway, Description, DHCPEnabled 
  $getHDDSpace = (Get-WmiObject -class win32_logicaldisk | where-object { $_.DeviceID -ne 'A:' -and $_.DeviceID -ne 'D:' }  ) 

  ## Gets Software Information
  $getLastUser = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedOnUser | select -ExpandProperty LastLoggedOnUser
  $getLastPatch = (Get-WmiObject -Class win32_quickfixengineering).InstalledOn | Sort-Object | Select -last 1 
  $getBiosVer = $wmiBIOSObject.SMBIOSBIOSVERSION 
  $getShareInfo = Get-WmiObject -Class win32_share 
  mkdir C:\temp -Force > out-null ; [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" ; (New-Object System.Net.WebClient).DownloadFile('https://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542/file/139923/3/Get-PendingReboot.ps1', 'C:\temp\Get-PendingReboot.ps1')  ; import-module C:\temp\Get-PendingReboot.ps1
  $getPendingUpdates = Get-PendingReboot
  $getFireWallStatus = (Get-NetFirewallProfile) 
  $getInstalledSoftware = (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*) 
  $getPSVersion = ($PSVersionTable.PSVersion).Major 
  $FinalOutput = 
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
    
  $FinalOutput
  
}

