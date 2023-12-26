<#PSScriptInfo
.VERSION 1.1
.AUTHOR Yesua Menchón
.COPYRIGHT
.RELEASENOTES
Version 1.0: Initial version.
.PRIVATEDATA
#>

$error_aplicarACL = 0
$errorXPack = 0
Function Registrar-LogFinal ($text)
{
    if(!(Test-Path -Path 'C:\temp'))
    {
        #New-Item -Path 'C:\WorkArround' -ItemType Directory
        New-ItemProperty -Path 'C:\temp' -Name 'workarround_ResultClickShareApps.txt'
    }

    Add-Content -Path 'C:\temp\workarround_ResultClickShareApps.txt' -Value $text
}
Function Registrar-Log ($text)
{
    if(!(Test-Path -Path 'C:\temp'))
    {
        #New-Item -Path 'C:\temp' -ItemType Directory
        New-ItemProperty -Path 'C:\temp' -Name 'workarround_ResultClickShareApps_ext.txt'
    }

    Add-Content -Path 'C:\temp\workarround_ResultClickShareApps_ext.txt' -Value $text
}
Function Revisar-Admin
{
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
    { 
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit 
    }
    else
    {
    }
}

Function Parar-Serveis($nom)
{
    try
    {
        $Filtrat = -join("Name LIKE '",$nom,"'")
        $id = Get-WmiObject -Class Win32_Service -Filter $Filtrat | Select-Object -ExpandProperty ProcessId
        
        Stop-Process -Id $id -Force
    }
    catch
    {
        Registrar-Log -text "Process $nom stopped or not existing"
    }
}

Function Renombrar-Carpeta
{
    Parar-Serveis -nom "clickshare_native.exe"
    Parar-Serveis -nom "calendarreader64.exe"
    Parar-Serveis -nom "PresentSense.exe"
    try
    {
        if((Test-Path -Path "C:\ClickShareApp"))
        {
            Rename-Item -Path "C:\ClickShareApp" -NewName "ClickShareApp.Sav"
        }
    }
    catch
    {
        Registrar-Log -text "Error while edit folder ClickShareApp"
    }
}

Function Recuperar-Apps
{
    try
    {
        Get-AppXPackage -AllUsers |Where-Object {$_.InstallLocation -like "*SystemApps*"} | Foreach {Add-AppxPackage -DisableDevelopmentMode -ForceApplicationShutdown -Register "$($_.InstallLocation)\AppXManifest.xml"}
    }
    catch
    {
        $errorXPack = 1
        Registrar-Log -text "Error AppXPackage"
    }
}

Function Aplicar-ACL($ruta)
{
    $idRef = [System.Security.Principal.SecurityIdentifier]("AC")   
    $access = [System.Security.AccessControl.RegistryRights]"ReadKey"
    $inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $propagation = [System.Security.AccessControl.PropagationFlags]"None"
    $type = [System.Security.AccessControl.AccessControlType]"Allow"
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($idRef,$access,$inheritance,$propagation,$type)

    $acl = Get-Acl $ruta
    try {
        $acl.AddAccessRule($rule)
        $acl |Set-Acl
    } catch
    { 
        Registrar-Log -text "Error Aplicar-ACL"
        $error_aplicarACL = 1
    }
}


Function Recuperar-StartMenu
{
    Aplicar-ACL -ruta 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
    Aplicar-ACL -ruta 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
}

Function Repas-WorkArround
{
    if(!(Test-Path -Path 'C:\ClickShareApp') -or ($error_aplicarACL == 1) -or ($errorXPack == 1))
    {
        Registrar-LogFinal "ERROR PROCESS"
    }
    else
    {
       Registrar-LogFinal "SUCCESS PROCESS" 
    }
}

Function WorkArround-ClickShareApps
{
    Renombrar-Carpeta
    Recuperar-StartMenu
    Revisar-Admin
    Recuperar-Apps
    Repas-WorkArround
}

WorkArround-ClickShareApps
