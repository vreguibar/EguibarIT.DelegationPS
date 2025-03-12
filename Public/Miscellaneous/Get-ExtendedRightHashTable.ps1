Function Get-ExtendedRightHashTable {
    <#
        .Synopsis
            Function to Read all Extended Rights GUID from Schema
        .DESCRIPTION
            Function that reads all Extended Rights GUID from the Schema and stores into
            a Hash Table named $Variables.ExtendedRightsMap
        .EXAMPLE
            Get-ExtendedRightHashTable
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

        Set-StrictMode -Version Latest

        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            'This function does not uses any Parameter.'
        )
        Write-Verbose -Message $txt

        ##############################
        # Variables Definition

        [hashtable]$TmpMap = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [int32]$i = 0
        [bool]$FillUp = $false

    } #end Begin

    Process {

        # Check if $Variables.ExtendedRightsMap is Null or Empty
        If ( [string]::IsNullOrEmpty($Variables.ExtendedRightsMap) ) {
            # We have to fill it up
            $FillUp = $true
        }

        If ($Force) {
            # We are FORCED to fill it up
            $FillUp = $true
        }

        try {

            If ( $FillUp ) {

                Write-Verbose -Message 'The Extended Rights map is null, empty, zero, or false.'
                Write-Verbose -Message 'Getting the GUID value of each Extended attribute'
                # store the GUID value of each extended right in the forest
                $Splat = @{
                    SearchBase = ('CN=Extended-Rights,{0}' -f $Variables.configurationNamingContext)
                    LDAPFilter = '(objectclass=controlAccessRight)'
                    Properties = 'DisplayName', 'rightsGuid'
                }
                $AllExtended = Get-ADObject @Splat

                Write-Verbose -Message 'Processing all Extended attributes'
                ForEach ($Item in $AllExtended) {
                    $i ++

                    $Splat = @{
                        Activity         = 'Adding {0} Extended attributes to Hashtable' -f $AllExtended.count
                        Status           = 'Reading extended attribute number {0}  ' -f $i
                        PercentComplete  = [math]::Round(($i / $AllExtended.Count) * 100, 2)
                        CurrentOperation = '      Processing Extended Attribute...: {0}' -f $item.lDAPDisplayName
                    }
                    Write-Progress @Splat

                    # add current Guid to $TempMap
                    $TmpMap.Add($Item.displayName, ([system.guid]$Item.rightsGuid).GUID)
                } #end Foreach

                # Include "ALL [nullGUID]"
                $TmpMap.Add('All', $Constants.guidNull)

                Write-Verbose -Message '$Variables.ExtendedRightsMap was empty. Adding values to it!'
                $Variables.ExtendedRightsMap = $TmpMap

            } else {
                Write-Verbose -Message '$Variables.ExtendedRightsMap id defined. You can use it!'
            } #end If-Else
        } catch {
            Write-Error -Message 'Error when filling ExtendedRightsmap variable'
            throw
        } Finally {
            # Remove completed progress bar
            $Splat = @{
                Activity         = 'Adding Extended attributes to Hashtable'
                Status           = 'Completed'
                CurrentOperation = 'Finished'
                PercentComplete  = 100
                Completed        = $true
            }
            Write-Progress @Splat
        } #end Try-Catch-Finally

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'filling up ExtendedRightsMap variable.'
        )
        Write-Verbose -Message $txt
    } #end END
}
