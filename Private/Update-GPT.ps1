function Update-Gpt {
    param (
        [string]$GpoToModify
    )
    try {


        $domain = New-Object Microsoft.GroupPolicy.GPDomain
        $SysVolPath = Get-RegistryValue -Path 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SysVol'
        $Gpo = $domain.GetGpo($GpoToModify)
        $GpoId = '{' + $Gpo.Id + '}'
        $PathToGpt = "$SysVolPath\$([YourNamespace.Domains]::GetAdFQDN())\Policies\$GpoId\gpt.ini"

        $de = [ADSI]"LDAP://CN=$GpoId,CN=Policies,CN=System,$Variables.AdDN"

        $VersionObject = [convert]::ToInt64($de.Properties['VersionNumber'].Value)

        $HexValue = '{0:x8}' -f $VersionObject
        $HexUserVN = $HexValue.Substring(0, 4)
        $HexComputerVN = $HexValue.Substring(4, 4)
        $UserVN = [convert]::ToInt64($HexUserVN, 16)
        $ComputerVN = [convert]::ToInt64($HexComputerVN, 16)
        $ComputerVN += 3
        $NewHex = "0x$HexUserVN$([convert]::ToString($ComputerVN, 16).PadLeft(4, '0'))"
        $NewVersionObject = [convert]::ToInt64($NewHex, 16)
        $de.Properties['VersionNumber'].Value = $NewVersionObject
        $de.CommitChanges()
        $de.Close()

        #$Gpt = [psobject]::new()
        $Gpt = [IniFile]::new()
        $Gpt.Sections = @{}
        $Gpt.Sections['General'] = [psobject]::new()
        $Gpt.Sections['General'].KeyValuePair = @{}
        $Gpt.Sections['General'].KeyValuePair['Version'] = $NewVersionObject
        $Gpt.WriteAllText($PathToGpt)
        return $true
    } catch {
        Write-Error "An error occurred: $_"
        throw [System.ApplicationException]::new("The GPTs.ini file could not be modified: $_")
    }
}
