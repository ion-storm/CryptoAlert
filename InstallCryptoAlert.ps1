<#
    .DESCRIPTION
        This is a full blown script for detecting CryptoWall in action. This script should be ready for deployment via an RMM platform or manually. The script uses FSRM to detect file drops and is capable of installing FSRM if it is not installed. Once detection occurs the user is locked out of all nonadministrative shares, an event is logged for each file dropped, and the user is sent an email to notify IT. The users account is not locked out as FSRM does not have that privilege level so you should still take action quickly to prevent other servers or their own machine from encryption.

        This script creates an additional script in C:\Windows called CryptoKicknBlock.ps1 this is what FSRM uses to block share access and kick the user off. You can modify this script to include administrative shares if desired. This helper script will also unblock the account once you are ready. Instructions are in the script. Get-Help works for both scripts.

        Please be aware this script will only work for 2012 and above due to the use of SMB commands.

        WARNING this script WILL NOT fully prevent CryptoWall it is simply a tool to use to limit the damage caused. You should always have good backups and other preventative measures in place.

    .NOTES
        Author: C. Mohr
        Version: 1.0 Release date: 8/20/2015
        Released under the GNU GPLv3

        This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
    .LINK
        http://www.gnu.org/licenses/
    .SYNOPSIS 
        A script for detecting CryptoWall in action, notifying the user, and deploying countermeasures.
    .EXAMPLE
        C:\PS> .\InstallCryptoAlert.ps1 
        This example configures filescreens and drops the CryptoKicknBlock.ps1 in C:\Windows\ for use by the filescreen. 
    .EXAMPLE 
        C:\PS> .\InstallCryptoAlert.ps1 -MailServer mail.comain.com -AdminEmail admin@mail.domain.com
        This example will configure FSRM with your mailserver and admin email the from address with automatically be FRSM@servername.domain.com. It will then configure filescreens and drop the CryptoKicknBlock.ps1 in C:\Windows\ for use by the filescreen. 
    .PARAMETER MailServer
		    Specifies the mail server such as mail.domain.com
    .PARAMETER AdminEmail
		    Specifies the administrative email address such as admin@mail.domain.com
  #>


Param(
  [string]$MailServer,
  [string]$AdminEmail 
)

If (-not(Get-WindowsFeature FS-Resource-Manager | Where-Object {$_.Installed -match “True”})) {
	If (-not $MailServer -or -not $AdminEmail) {
		write-host "FSRM is not installed so you must provide MailServer and AdminEmail parameters"
		Exit
	}
	else {
		Install-WindowsFeature –Name FS-Resource-Manager –IncludeManagementTools
		Set-FsrmSetting -SmtpServer $MailServer -AdminEmailAddress $AdminEmail
	}
}

$drives = gwmi win32_logicaldisk -filter DriveType=3 | Select -ExpandProperty DeviceID

New-FsrmFileGroup -Name "CryptoWall File Monitor" -IncludePattern @("*DECRYPT_*", "*_DECRYPT*","*Restore_files*")
foreach ($drive in $drives){
    $Notification = New-FsrmAction -Type Event -EventType Warning -Body "User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group. This file could be an indication of CryptoWall infection and should be investigated immediately." -RunlimitInterval 0
	$Command = New-FsrmAction Command -Command C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -CommandParameters '-executionpolicy bypass -file C:\Windows\CryptoKicknBlock.ps1 -FileOwner [Source Io Owner]' -SecurityLevel LocalSystem -KillTimeOut 0 -RunLimitInterval 0 -WorkingDirectory C:\Windows\System32\WindowsPowerShell\v1.0\
	$EmailUser = New-FsrmAction -Type Email `
		-RunlimitInterval 5 `
		-MailTo "[Source Io Owner Email]" `
		-Subject "Possible maleware detected. Contact IT immediately!" `
		-Body "User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group. This file could be an indication of CryptoWall infection. To prevent possible futher infection and file corruption your access to [Server] has been blocked. Please contact IT immediately for investgation and to be unblocked."
    New-FsrmFileScreen -Path "$drive" -Active: $false -IncludeGroup "CryptoWall File Monitor" -Notification @($Notification, $Command, $EmailUser)
}

$file = "C:\Windows\CryptoKicknBlock.ps1"
#Warning this will overwrite existing files
NI  $file -type file -force

$KickScript = @'
<#
    .SYNOPSIS 
      Use this script to lock or unlock all shares to a user and kick their current sessions off the server.
    .EXAMPLE
        C:\PS> .\CryptoKicknBlock.ps1 -FileOwner jsmith
        This example adds a deny ACL to the share permissions for all shares for user jsmith
    .EXAMPLE 
        C:\PS> .\CryptoKicknBlock.ps1 -FileOwner jsmith -UnLock
        This example will remove the deny ACL from all shares for user jsmith
    .DESCRIPTION
        This script in conjunction with FSRM screening is meant as a tool to assist in combating Crypto* infections. It will not prevent infection of files as it requires a trigger to activate at which time you probably already have files encrpyted but it should prevent additional folders from becoming victims. By default only nonadministrative shares are blocked. C$, D$ (etc), PRINT$, SYSVOL, NETLOGON are excluded. If wish to include special folders you need to edit the wcript and add type=2147483648 to the filter. This will still exclude printers, IPC$, and any specifically excluded in the filter.

        On its own the script can also be used standalone as a way to block and unblock users access to all shares if this is required.

        NOTE: Server 2012 or above is required due to the use of SMB commands.
    .NOTES
        Author: C. Mohr
        Version: 1.0 Release date: 8/20/2015
        Released under the GNU GPLv3

        This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
    .LINK
        http://www.gnu.org/licenses/
    .PARAMETER FileOwner
		    Specifies the AD username of the account to block
    .PARAMETER UnLock
		    Omit to lock user out, any value will cause an unlock
  #>
Param(
  [Parameter(Mandatory=$true)]
  [string]$FileOwner,
  [string]$Unlock 
)
$Shares = Get-WmiObject -Class win32_share -filter "type=0 and not name like 'PRINT$' and not name like 'SYSVOL' and not name like 'NETLOGON'"
if ($Unlock) {
    ForEach ($Share in $Shares) {
        UnBlock-SmbShareAccess -Name $Share.Name -AccountName $FileOwner -force
    }
}
else {
    ForEach ($Share in $Shares) {
        Block-SmbShareAccess -Name $Share.Name -AccountName $FileOwner -force
    }
    $SMBsession = get-smbsession | where {$_.ClientUserName -like "*$FileOwner*"}
    ForEach ($Session in $SMBsession) {
        Close-smbsession -SessionId $Session.SessionId -force
    }
}
'@
AC $file $KickScript
