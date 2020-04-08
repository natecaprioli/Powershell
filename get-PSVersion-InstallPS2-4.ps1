## Nate Caprioli


## Variables
$OSVer = (Get-WmiObject Win32_OperatingSystem).Caption

## Checks OS Version and runs appropriate code
if ($OSVer -like "Microsoft Windows 10*") 
    {
    # Runs PS 4.0 Code on Win10
    Write-Output "This is Windows 10 already, no need for PS4.0"
    $PSVersionTable
    }
    else 
    {
    if ($OSVer -like "Microsoft Windows 7*")
        {
        # Run the PS2.0 Code on Win7 to update Powershell
        # https://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows6.1-KB2819745-x64-MultiPkg.msu
        Write-Output "This is windows 7"
        mkdir C:\temp
        # Downloads .net 4.5.2 to use new powershell and installs w/ sleep
        Write-Output "Downloading .NET 4.5.2"
        (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe","C:\temp\NDP452-KB2901907-x86-x64-AllOS-ENU.exe")
        Write-Output "Installing .NET 4.5.2"
        Start-Process -FilePath "C:\temp\NDP452-KB2901907-x86-x64-AllOS-ENU.exe" -ArgumentList "/q /norestart" -Wait
        # Downloads WMF 4.0 to get new Powershell
        Write-Output "Download WMF 4.0"
        (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows6.1-KB2819745-x64-MultiPkg.msu","C:\temp\Windows6.1-KB2819745-x64-MultiPkg.msu")
        Write-Output "Install WMF 4.0"
        Start-Process -FilePath "wusa.exe" -ArgumentList "C:\temp\Windows6.1-KB2819745-x64-MultiPkg.msu /quiet /norestart" -Wait
        shutdown -r -t 300 -f -c "The device is rebooting for maintenance in 5 minutes. Please save your work and log out.  Run Shutdown.exe /A to cancel temporarily"
        $PSVersionTable
        }
        else 
        {
        Write-Output "Downloading WMF 2.0"
        (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/E/C/E/ECE99583-2003-455D-B681-68DB610B44A4/WindowsXP-KB968930-x86-ENG.exe","C:\temp\WindowsXP-KB968930-x86-ENG.exe")
        Write-Output "Run WMF 2.0"
        cmd /c "C:\temp\WindowsXP-KB968930-x86-ENG.exe /q /norestart"
        shutdown -r -t 300 -f -c "The device is rebooting for maintenance in 5 minutes. Please save your work and log out.  Run Shutdown.exe /A to cancel temporarily"
        }
    }