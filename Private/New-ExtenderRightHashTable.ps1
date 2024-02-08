Function New-ExtenderRightHashTable {
    <#
        .Synopsis
            Function to Read all Extended Rights GUID from Schema
        .DESCRIPTION
            Function that reads all Extended Rights GUID from the Schema and stores into
            a Hash Table named $extendedrightsmap
        .EXAMPLE
            New-ExtenderRightHashTable
        .NOTES
            Version:         1.0
            DateModified:    19/Feb/2015
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([System.Collections.Hashtable])]

    Param()

    Begin {
        $error.clear()

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('This function does not uses any Parameter' )

        ##############################
        # Variables Definition

        [hashtable]$TmpMap = [hashtable]::New()
        [hashtable]$Splat = [hashtable]::New()

    } #end Begin

    Process {
        try {

            If ( ($null -eq $Variables.ExtendedRightsMap) -and
                 ($Variables.ExtendedRightsMap -ne 0) -and
                 ($Variables.ExtendedRightsMap -ne '') -and
                 (   ($Variables.ExtendedRightsMap -isnot [array]) -or
                     ($Variables.ExtendedRightsMap.Length -ne 0)) -and
                 ($Variables.ExtendedRightsMap -ne $false)
            ) {

                # store the GUID value of each extended right in the forest
                $Splat = @{
                    SearchBase = ('CN=Extended-Rights,{0}' -f $Variables.configurationNamingContext)
                    LDAPFilter = '(objectclass=controlAccessRight)'
                    Properties = 'DisplayName', 'rightsGuid'
                }
                $AllExtended = Get-ADObject @Splat

                ForEach ($Item in $AllExtended) {
                    $TmpMap.Add($Item.displayName, [system.guid]$Item.rightsGuid)
                }
                # Include "ALL [nullGUID]"
                $TmpMap.Add('All', [System.GUID]'00000000-0000-0000-0000-000000000000')
            } #end If
        } catch {
            Get-CurrentErrorToDisplay -CurrentError $error[0]
        } #end Try-Catch


    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        $Variables.ExtendedRightsMap = $TmpMap

        Return $Variables.ExtendedRightsMap
    } #end END
}
