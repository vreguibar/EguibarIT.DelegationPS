#Import-Module EguibarIT.DelegationPS

$Administrators = Get-ADGroup Administrators

$ArrayList = [System.Collections.Generic.List[object]]::new()

$ArrayList.Clear()
[void]$ArrayList.Add($Administrators)
[void]$ArrayList.Add('Authenticated Users')
[void]$ArrayList.Add('enterprise domain controllers')


$GptTmpl = Get-GptTemplate -GpoName 'C-Baseline'

$Splat = @{
    CurrentSection = 'Privilege Rights'
    CurrentKey     = 'SeDenyNetworkLogonRight'
    Members        = $ArrayList.ToArray()
    GptTmpl        = $GptTmpl
    Confirm        = $false
}
$GptTmpl = Set-GPOConfigSection @Splat

$GptTmpl.SaveFile()

Update-GpoVersion -GpoName 'C-Baseline'

If ($SettingsOK) {
    Write-Verbose -Message ('Privilege Right granted')
} else {
    Write-Warning -Message ('[WARNING] Privilege Right not granted.')
}
