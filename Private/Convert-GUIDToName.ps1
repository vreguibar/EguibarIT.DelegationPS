function Convert-GUIDToName {
    <#
        .Synopsis
            Helper function to translate GUID to display name
        .DESCRIPTION
            This function translates a GUID into a human readible Display Name
        .EXAMPLE
            Convert-GUIDToName bf967aba-0de6-11d0-a285-00aa003049e2
        .EXAMPLE
            Convert-GUIDToName -Guid bf967aba-0de6-11d0-a285-00aa003049e2
        .EXAMPLE
            ---------- Class Schema
            Convert-GUIDToName -Guid "bf967a86-0de6-11d0-a285-00aa003049e2" # computer
            Convert-GUIDToName -Guid "bf967a9c-0de6-11d0-a285-00aa003049e2" # group
            Convert-GUIDToName -Guid "b7b13124-b82e-11d0-afee-0000f80367c1" # subnet
            Convert-GUIDToName -Guid "bf967aba-0de6-11d0-a285-00aa003049e2" # user
            ---------- Attribute Schema
            Convert-GUIDToName -Guid "bf967915-0de6-11d0-a285-00aa003049e2" # AccountExpires
            Convert-GUIDToName -Guid "f0f8ff84-1191-11d0-a060-00aa006c33ed" # StreetAddress (attributeSchema)
            Convert-GUIDToName -Guid "bf96793e-0de6-11d0-a285-00aa003049e2" # Comment
            Convert-GUIDToName -Guid "bf967950-0de6-11d0-a285-00aa003049e2" # Description
            Convert-GUIDToName -Guid "bf967962-0de6-11d0-a285-00aa003049e2" # Employee-ID
            Convert-GUIDToName -Guid "bf9679b5-0de6-11d0-a285-00aa003049e2" # Manager
            Convert-GUIDToName -Guid "8d3bca50-1d7e-11d0-a081-00aa006c33ed" # Picture
            Convert-GUIDToName -Guid "3e0abfd0-126a-11d0-a060-00aa006c33ed" # SamAccountName
            ---------- Extended Rights
            Convert-GUIDToName -Guid "68b1d179-0d15-4d4f-ab71-46152e79a7bc" # Allowed to Authenticate [Extended Right]
            Convert-GUIDToName -Guid "ba33815a-4f93-4c76-87f3-57574bff8109" # Migrate SID History [Extended Right]
            Convert-GUIDToName -Guid "00299570-246d-11d0-a768-00aa006e0529" # Reset Password [Extended Right]
            Convert-GUIDToName -Guid "ab721a53-1e2f-11d0-9819-00aa0040529b" # Change Password [Extended Right]
            Convert-GUIDToName -Guid "59ba2f42-79a2-11d0-9020-00c04fc2d3cf" # General Information [Extended Right]
            Convert-GUIDToName -Guid "5f202010-79a5-11d0-9020-00c04fc2d4cf" # Logon Information [Property Set]
            Convert-GUIDToName -Guid "77b5b886-944a-11d1-aebd-0000f80367c1" # Personal Information [Property Set]
            Convert-GUIDToName -Guid "4c164200-20c0-11d0-a768-00aa006e0529" # Account Restrictions [Property Set]
        .EXAMPLE
            $Splat = @{
                GUID    = 'bf967aba-0de6-11d0-a285-00aa003049e2'
                Verbose = $true
            }
            Convert-GUIDToName @Splat
        .PARAMETER guid
            STRING representing the GUID
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-ADRootDSE                          | ActiveDirectory
                Get-ADObject                           | ActiveDirectory
        .NOTES
            Version:         1.1
            DateModified:    17/Oct/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Low')]
    [OutputType([String])]

    param
    (
        # PARAM1 STRING representing the GUID
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'STRING representing the GUID',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $guid
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        [String]$Output = $null

       # Ensure string is converted to GUID
        if ($guid -is [String]) {
            Write-Verbose -Message ('Converting string {0} to GUID' -f $guid)
            [GUID]$guid = [System.guid]::New($guid)
        }
    } #end Begin

    Process {

        # Get ALL [nullGUID]
        If($guid -eq $Constants.guidNull) {
            $Output = 'All [GuidNULL]'
        } else {

            $result = Get-ADObject -SearchBase $Variables.SchemaNamingContext.ToString() -Filter {schemaIDGUID -eq $guid} -Properties lDAPDisplayName

            #if $Result return empty, is because GUID is Extended Right
            #Check result value
            If($result) {
                # Check result for classSchema
                If($result.ObjectClass -eq 'classSchema') {
                    Write-Verbose -Message 'Found it as ClassSchema'
                    $Output = ('{0} [classSchema]' -f $result.lDAPDisplayName)
                } #end If

                # Check result for attributeSchema
                If($result.ObjectClass -eq 'attributeSchema') {
                    Write-Verbose -Message 'Found it as AttributeSchema'
                    $Output = ('{0} [attributeSchema]' -f $result.lDAPDisplayName)
                } #end If
            } elseif($null -eq $result -and
                    $value -ne 0 -and
                    $value -ne '' -and
                    ($value -isnot [array] -or $value.Length -ne 0) -and
                    $value -ne $false) {
                # Check GUID for Extended Right
                $SearchBase = 'CN=Extended-Rights,{0}' -f $Variables.configurationNamingContext.ToString()
                $result = Get-ADObject -SearchBase $SearchBase -Filter {rightsGUID -eq $guid} -Properties DisplayName, rightsGUID
                Write-Verbose -Message 'Found it as ExtendedRight'
                $Output = ('{0} [ExtendedRight]' -f $Result.DisplayName)
            } #end If-ElseIf
        } #end If-Else

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        Return $Output
    } #end End
}
