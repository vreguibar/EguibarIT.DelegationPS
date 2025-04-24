Function Remove-PreWin2000FromOU {
    <#
        .SYNOPSIS
            Remove Pre-Windows 2000 Compatible Access built-in group from the specified OU.
        .DESCRIPTION
            Remove the built-in group Pre-Windows 2000 Compatible Access from the specified OU.
        .EXAMPLE
            Remove-PreWin2000FromOU -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .PARAMETER LDAPpath
            [String] Distinguished Name of the object
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor6                    | EguibarIT.DelegationPS
                Get-AttributeSchemaHashTable           | EguibarIT.DelegationPS
        .NOTES
            Version:         1.1
            DateModified:    29/Sep/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Object Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Object Distinguished Name',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'If present, the function will not ask for confirmation when performing actions.',
            Position = 1)]
        [Switch]
        $Force
    )

    begin {

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
        # Module imports

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Get 'Pre-Windows 2000 Compatible Access' group by SID
        $PreWin2000 = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-554' }

        Write-Verbose -Message 'Checking variable $Variables.GuidMap. In case is empty a function is called to fill it up.'
        Get-AttributeSchemaHashTable
    } #end Begin

    process {
        try {
            # Remove inheritance, otherwise is not possible to remove
            Set-AdInheritance -LDAPpath $PSBoundParameters['LDAPpath'] -RemoveInheritance $true -RemovePermissions $true

            # Remove the List Children
            $Splat = @{
                Id                    = $PreWin2000
                LDAPPath              = $PSBoundParameters['LDAPpath']
                AdRight               = 'ListChildren'
                AccessControlType     = 'Allow'
                ObjectType            = $Constants.guidNull
                AdSecurityInheritance = 'All'
                RemoveRule            = $true
            }
            If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove "Pre-Windows 2000 Compatible Access"?')) {
                Set-AclConstructor5 @Splat
            } #end If

            # Remove inetOrgPerson
            $Splat = @{
                Id                    = 'Pre-Windows 2000 Compatible Access'
                LDAPPath              = $PSBoundParameters['LDAPpath']
                AdRight               = 'ReadProperty', 'ListObject', 'ReadControl'
                AccessControlType     = 'Allow'
                ObjectType            = $Constants.guidNull
                AdSecurityInheritance = 'Descendents'
                InheritedObjectType   = $Variables.GuidMap['inetOrgPerson']
                RemoveRule            = $true
            }
            If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove "Pre-Windows 2000 Compatible Access"?')) {
                Set-AclConstructor6 @Splat
            } #end If

            # Remove Group
            $Splat = @{
                Id                    = 'Pre-Windows 2000 Compatible Access'
                LDAPPath              = $PSBoundParameters['LDAPpath']
                AdRight               = 'ReadProperty', 'ListObject', 'ReadControl'
                AccessControlType     = 'Allow'
                ObjectType            = $Constants.guidNull
                AdSecurityInheritance = 'Descendents'
                InheritedObjectType   = $Variables.GuidMap['group']
                RemoveRule            = $true
            }
            If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove "Pre-Windows 2000 Compatible Access"?')) {
                Set-AclConstructor6 @Splat
            } #end If

            # Remove User
            $Splat = @{
                Id                    = 'Pre-Windows 2000 Compatible Access'
                LDAPPath              = $PSBoundParameters['LDAPpath']
                AdRight               = 'ReadProperty', 'ListObject', 'ReadControl'
                AccessControlType     = 'Allow'
                ObjectType            = $Constants.guidNull
                AdSecurityInheritance = 'Descendents'
                InheritedObjectType   = $Variables.GuidMap['user']
                RemoveRule            = $true
            }
            If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove "Pre-Windows 2000 Compatible Access"?')) {
                Set-AclConstructor6 @Splat
            } #end If
        } catch {
            Write-Error -Message 'Error when removing Pre-Windows 2000 from OU'
            throw
        }
    } #end Process

    end {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'removing Pre-Windows 2000 Compatible Access from OU.'
        )
        Write-Verbose -Message $txt
    } #end END
}
