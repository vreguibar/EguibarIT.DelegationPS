Function Get-AttributeSchemaHashTable {
    <#
        .SYNOPSIS
            Gets all GUIDs from the Active Directory schema and stores them in a hashtable.

        .DESCRIPTION
            This function queries the Active Directory schema and retrieves all schema object GUIDs,
            creating a hashtable that maps LDAP display names to their corresponding GUIDs.
            The hashtable is stored in the $Variables.GuidMap variable for later use.

            This function is essential for performing GUID-based operations in Active Directory,
            particularly for security descriptors and permission management.

        .PARAMETER Force
            Forces the function to rebuild the GUID map even if it already exists.

        .PARAMETER Server
            Specifies the domain controller to use for the query.
            If not provided, the function will use the default domain controller.

        .EXAMPLE
            Get-AttributeSchemaHashTable

            Retrieves all schema GUIDs and stores them in $Variables.GuidMap.

        .EXAMPLE
            Get-AttributeSchemaHashTable -Force

            Forces the function to rebuild the GUID map even if it already exists.

        .EXAMPLE
            Get-AttributeSchemaHashTable -Server 'DC01.EguibarIT.local'

            Retrieves all schema GUIDs from the specified domain controller.

        .OUTPUTS
            System.Collections.Hashtable

            A hashtable mapping LDAP display names to their corresponding GUIDs.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-ADObject                               ║ ActiveDirectory
                Write-Progress                             ║ Microsoft.PowerShell.Utility
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Write-Debug                                ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.2
            DateModified:    21/Mar/2025
            LastModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Public/Get-AttributeSchemaHashTable.ps1
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Collections.Hashtable])]

    Param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            Position = 0,
            HelpMessage = 'Forces the function to rebuild the GUID map even if it already exists.'
        )]
        [Alias('Rebuild')]
        [switch]
        $Force,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            Position = 1,
            HelpMessage = 'Specifies the domain controller to use for the query.'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('DC', 'DomainController')]
        [string]$Server
    )

    Begin {

        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and $null -ne $Variables.HeaderDelegation) {
            $txt = ($Variables.HeaderDelegation -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Variables Definition

        [hashtable]$TmpMap = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [hashtable]$ProgressSplat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [bool]$FillUp = $false
        [int32]$ProcessedItems = 0
        [int32]$BatchSize = 1000 # Optimized batch size for AD queries

        # Prepare AD query splatting parameters
        $Splat = @{
            SearchBase = $Variables.SchemaNamingContext
            LDAPFilter = '(schemaidguid=*)'
            Properties = 'lDAPDisplayName', 'schemaIDGUID'
        }

        # Add server if specified
        if ($PSBoundParameters.ContainsKey('Server')) {

            $Splat.Add('Server', $Server)
            Write-Debug -Message ('Using specified server: {0}' -f $Server)

        } #end if

    } #end Begin

    Process {

        # Check if $Variables.GuidMap is Null or Empty
        If ($Force -or
            [string]::IsNullOrEmpty($Variables.GuidMap) -or
            $Variables.GuidMap.Count -eq 0) {

            # We have to fill it up
            $FillUp = $true
            Write-Debug -Message 'The GUID map is null, empty, or Force parameter was specified.'

        } else {

            Write-Debug -Message 'GUID map already exists. Use -Force to rebuild it.'

        } #end If

        If ( $FillUp ) {

            try {

                Write-Debug -Message '
                    The GUID map is null, empty, zero, or false.
                    Getting the GUID value of each schema class and attribute'

                # Add pagination parameters for large environments
                $Splat.Add('ResultPageSize', $BatchSize)

                # Execute the AD query with optimized filter
                Write-Debug -Message ('Executing AD query with parameters: {0}' -f ($ADSplat | ConvertTo-Json -Compress))

                $AllSchema = Get-ADObject @Splat

                if ($null -eq $AllSchema) {
                    Write-Warning -Message 'No schema objects were found.'
                }

                $SchemaCount = ($AllSchema | Measure-Object).Count
                Write-Debug -Message ('Found {0} schema objects' -f $SchemaCount)

                # Process schema objects
                Foreach ($item in $AllSchema) {
                    $ProcessedItems++

                    # Update progress bar
                    $ProgressSplat = @{
                        Activity         = 'Adding Schema attributes to Hashtable'
                        Status           = ('Processing: {0}/{1} ({2:P2} complete)' -f $ProcessedItems, $SchemaCount, ($ProcessedItems / $SchemaCount))
                        PercentComplete  = [math]::Round(($ProcessedItems / $SchemaCount) * 100, 2)
                        CurrentOperation = ('Processing attribute: {0}' -f $Item.lDAPDisplayName)
                    }
                    Write-Progress @ProgressSplat

                    # Convert schemaIDGUID to string GUID format and add to hashtable
                    try {
                        $GuidValue = ([System.GUID]$Item.schemaIDGUID).GUID

                        # Check if the lDAPDisplayName already exists in the hashtable
                        if (-not $TmpMap.ContainsKey($Item.lDAPDisplayName)) {

                            $TmpMap.Add($Item.lDAPDisplayName, $GuidValue)
                            Write-Debug -Message ('Added {0}: {1}' -f $SchemaItem.lDAPDisplayName, $GuidValue)

                        } else {

                            Write-Warning -Message ('
                                Duplicate lDAPDisplayName found: {0}.
                                Using first occurrence only.' -f $SchemaItem.lDAPDisplayName
                            )
                        }
                    } catch {
                        Write-Warning -Message ('
                            Error processing schema item {0}: {1}' -f $SchemaItem.lDAPDisplayName, $_.Exception.Message
                        )
                    } #end Try-Catch

                } #end ForEach

                # Add the "All" entry with null GUID
                if (-not [string]::IsNullOrEmpty($Constants.guidNull)) {

                    $TmpMap.Add('All', $Constants.guidNull)
                    Write-Debug -Message ('Added All: {0}' -f $Constants.guidNull)

                } else {

                    # Add a null GUID if $Constants.guidNull is not defined
                    $TmpMap.Add('All', '00000000-0000-0000-0000-000000000000')
                    Write-Debug -Message 'Added All: 00000000-0000-0000-0000-000000000000'

                } #end If-Else

                # Update the module-level variable with our new hashtable
                Write-Verbose -Message 'Updating $Variables.GuidMap with new values'
                $Variables.GuidMap = $TmpMap

            } catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException] {

                Write-Error -Message ('Active Directory operation error: {0}' -f $_.Exception.Message)
                throw

            } catch [System.UnauthorizedAccessException] {

                Write-Error -Message ('Access denied error: {0}' -f $_.Exception.Message)
                throw

            } catch {

                Write-Error -Message ('Error filling GUID map: {0}' -f $_.Exception.Message)
                throw

            } Finally {

                # Complete the progress bar
                $ProgressSplat = @{
                    Activity         = 'Adding Schema attributes to Hashtable'
                    Status           = 'Completed'
                    CurrentOperation = 'Finished'
                    PercentComplete  = 100
                    Completed        = $true
                }
                Write-Progress @ProgressSplat

            } #end Try-Catch-Finally
        } #end If
    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'filling up GuidMap variable.'
            )
            Write-Verbose -Message $txt
        } #end if

    } # end END
} #end Function Get-AttributeSchemaHashTable
