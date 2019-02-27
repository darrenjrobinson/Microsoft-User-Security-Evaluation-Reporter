<#

1. Update Line 81 with output path for the CSV

#>
# Connect to Office365 with MSOL to get MFA Methods (not available via MS Graph API yet)
Import-Module MSonline 
Connect-MsolService 

$Accounts = (Get-MsolUser -All | Where-Object {$_.StrongAuthenticationMethods -ne $Null} | Sort-Object DisplayName)
write-host -ForegroundColor Green "$($Accounts.count) MFA Users Retrieved"

# Build Report 
$Report = @()
$i = 0

ForEach ($user in $accounts) { 
    # Write-Host "Processing" $user.DisplayName
    $i++
    $MFA = $Null
    $State = $Null
    $Methods = $null 
    $Method = $null 
    $MFAApp = $null 
    $MFAApp = $User | Select-Object -ExpandProperty StrongAuthenticationPhoneAppDetails
    [int]$AuthTypeCount = 0
    $AppAuthType = $null 
    if ($MFAApp) {
        $AuthTypeCount++
        foreach ($MFAApplication in $MFAApp) {
            if ($AuthTypeCount -gt 1) {
                $AppAuthType += "^$($MFAApp.AuthenticationType)"
            }
            else {
                $AppAuthType += "$($MFAApp.AuthenticationType)" 
            } 
        }
    } 

    [int]$AuthDeviceCount = 0
    $AppDevice = $null 
    if ($MFAApp) {
        $AuthDeviceCount++
        foreach ($MFADevice in $MFAApp) {
            if ($AuthDeviceCount -gt 1) {
                $AppDevice += "^$($MFAApp.DeviceName)"
            }
            else {
                $AppDevice += "$($MFAApp.DeviceName)" 
            } 
        }
    } 

    $Methods = $User | Select-Object -ExpandProperty StrongAuthenticationMethods
    $MFA = $User | Select-Object -ExpandProperty StrongAuthenticationUserDetails
    $State = $User | Select-Object -ExpandProperty StrongAuthenticationRequirements
    $Methods | ForEach-Object { If ($_.IsDefault -eq $True) {$Method = $_.MethodType}}

    If ($State.State -ne $Null) {
        $MFAStatus = $State.State
    }
    Else {
        $MFAStatus = "Disabled"
    }

    $ReportLine = [PSCustomObject][Ordered]@{
        User             = $user.DisplayName
        UPN              = $user.UserPrincipalName
        MFAMethod        = $Method
        MFAApp           = $AppAuthType
        MFAAppDeviceName = $AppDevice
        MFAPhone         = $MFA.PhoneNumber
        MFAEmail         = $MFA.Email
        MFAStatus        = $MFAStatus              
    }
    
    $Report += $ReportLine     
}
Write-Host -ForegroundColor Green $i "accounts with MFA options exported"
# Export CSV
$Report | Export-CSV -NoTypeInformation c:\temp\MFAUsers-16Feb19-withMFAApp-All.CSV

