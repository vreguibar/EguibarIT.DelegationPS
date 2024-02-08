# Constructor W/6 attributes https://msdn.microsoft.com/en-us/library/w72e8e69.aspx

function Set-AclConstructor6 {
  <#
      .Synopsis
      Helper function calling the AdAccessRule constructor
      using the corresponding 6 attributes
      .EXAMPLE
      Set-AclConstructor6 -Id "SG_SiteAdmins_XXXX"
      -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
      -AdRight "CreateChild,DeleteChild"
      -AccessControlType "Allow"
      -InheritedObjectType 12345678-abcd-1234-abcd-0123456789012
      -AdSecurityInheritance "All"
      -ObjectType 12345678-abcd-1234-abcd-0123456789012
      .PARAMETER Id
        [String] Identity of the Delegated Group
      .PARAMETER LDAPpath
        [String] Distinguished Name of the object
      .PARAMETER AdRight
        [String] Active Directory Right
      .PARAMETER AccessControlType
        [String] Allow or Deny access to the given object
      .PARAMETER InheritedObjectType
        [GUID] of the Inherited object or Extended Right
      .PARAMETER AdSecurityInheritance
        [String] Security inheritance of the new right
      .PARAMETER ObjectType
        [GUID] of the object
      .PARAMETER RemoveRule
        Switch to togle between ADD or REMOVE the rule
      .NOTES
      Version:         1.0
      DateModified:    02/Feb/2015
      LasModifiedBy:   Vicente Rodriguez Eguibar
      vicente@eguibar.com
      Eguibar Information Technology S.L.
      http://www.eguibarit.com
  #>
  [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]

  param (
    # PARAM1 STRING for the Delegated Identity
    # An IdentityReference object that identifies the trustee of the access rule.
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
      HelpMessage = 'Identity of the Delegated Group',
      Position = 0)]
    [ValidateNotNullOrEmpty()]
    [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
    [String]
    $Id,

    # PARAM2 STRING for the object's LDAP path
    # The LDAP path to the object where the ACL will be changed
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
      HelpMessage = 'Distinguished Name of the object',
      Position = 1)]
    [ValidateNotNullOrEmpty()]
    [Alias('DN', 'DistinguishedName')]
    [String]
    $LDAPpath,

    # PARAM3 STRING representing AdRight
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
      HelpMessage = 'Active Directory Right',
      Position = 2)]
    [ValidateNotNullOrEmpty()]
    #[ValidateScript({ [ActiveDirectoryRights]::new().GetValidValues().Contains($_) })]
    #[ValidateSet('CreateChild', 'DeleteChild', 'Delete', 'DeleteTree', 'ExtendedRight', 'GenericAll', 'GenericExecute', 'GenericRead', 'GenericWrite', 'ListChildren', 'ListObject', 'ReadControl', 'ReadProperty', 'Self', 'Synchronize', 'WriteDacl', 'WriteOwner', 'WriteProperty')]
    [ValidateSet([ActiveDirectoryRights])]
    [Alias('ActiveDirectoryRights')]
    [String[]]
    $AdRight,

    # PARAM4 STRING representing Access Control Type
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
      HelpMessage = 'Allow or Deny access to the given object',
      Position = 3)]
    [ValidateSet('Allow', 'Deny')]
    [String]
    $AccessControlType,

    # PARAM5 STRING representing the object GUID
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
      HelpMessage = 'GUID of the object',
      Position = 4)]
    [AllowNull()]
    [GUID]
    $ObjectType,

    # PARAM6 STRING representing ActiveDirectory Security Inheritance
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
      HelpMessage = 'Security inheritance of the new right (All, Children, Descendents, None, SelfAndChildren)',
      Position = 5)]
    [ValidateSet('All', 'Children', 'Descendents', 'None', 'SelfAndChildren')]
    [Alias('InheritanceType', 'ActiveDirectorySecurityInheritance')]
    [String]
    $AdSecurityInheritance,

    # PARAM7 Object GUID (or Extended Right)
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
      HelpMessage = 'GUID of the Inherited object or Extended Right',
      Position = 6)]
    [AllowNull()]
    [GUID]
    $InheritedObjectType,

    # PARAM8 SWITCH if $false (default) will add the rule. If $true, it will remove the rule
    [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
      HelpMessage = 'If present, the access rule will be removed.',
      Position = 7)]
    [Switch]
    $RemoveRule
  )

  Begin {
    Write-Verbose -Message '|=> ************************************************************************ <=|'
    Write-Verbose -Message (Get-Date).ToShortDateString()
    Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
    Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

    ##############################
    # Variables Definition

    $groupObject, $groupSID, $acl, $Arg1, $Arg2, $Arg3, $Arg4, $Arg5, $Arg6, $RuleArguments = $null

    Set-Location -Path AD:\
  } #end Begin

  Process {
    try {
      Switch ($PSBoundParameters['Id']) {
        'EVERYONE' {
          $groupSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ('S-1-1-0')
        }
        'SELF' {
          $groupSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ('S-1-5-10')
        }
        'AUTHENTICATED USERS' {
          $groupSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ('S-1-5-11')
        }
        default {
          # Collect the SID for the trustee we will be delegating to
          $groupObject = Get-ADGroup -Identity $PSBoundParameters['Id']
          $groupSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $groupObject.SID
        }
      }

      #Get a reference to the Object we want to delegate
      $object = Get-ADObject -Identity $PSBoundParameters['LDAPPath']

      #Get a copy of the current DACL on the object
      $acl = Get-Acl -Path ($object.DistinguishedName)

      # Start creating the Access Rule Arguments
      #  Provide the trustee identity (Group who gets the permissions)
      $Arg1 = [Security.Principal.IdentityReference] $groupSID

      # Set what to do (AD Rights http://msdn.microsoft.com/en-us/library/system.directoryservices.activedirectoryrights(v=vs.110).aspx)
      $Arg2 = [DirectoryServices.ActiveDirectoryRights] $PSBoundParameters['AdRight']

      # Define if allowed or denied (AccessControlType - Allow/Denied)
      $Arg3 = [Security.AccessControl.AccessControlType] $PSBoundParameters['AccessControlType']

      # Set the object GUID
      $Arg4 = $PSBoundParameters['ObjectType']

      # Set the scope (AdSecurityInheritance - http://msdn.microsoft.com/en-us/library/system.directoryservices.activedirectorysecurityinheritance(v=vs.110).aspx)
      $Arg5 = [DirectoryServices.ActiveDirectorySecurityInheritance] $PSBoundParameters['AdSecurityInheritance']

      # Set the object GUID
      $Arg6 = $PSBoundParameters['InheritedObjectType']

      $RuleArguments = $Arg1, $Arg2, $Arg3, $Arg4, $Arg5, $Arg6

      # If parameter RemoveRule is False (default when omitted) it will ADD the Access Rule
      # if TRUE then will REMOVE the access rule
      If ($PSBoundParameters['RemoveRule']) {
        # Action when TRUE is REMOVE
        #Create an Access Control Entry for new permission we wish to remove
        $null = $acl.RemoveAccessRule((New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $RuleArguments))
      } else {
        # Action when FALSE is ADD
        #Create an Access Control Entry for new permission we wish to add
        $null = $acl.AddAccessRule((New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $RuleArguments))
      }

      #Re-apply the modified DACL to the OU
      Set-Acl -AclObject $acl -Path ('AD:\{0}' -f $object.DistinguishedName)
    } Catch {
      throw
    }
  } #end Process

  End {
    Set-Location -Path $env:HOMEDRIVE\

    Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
    Write-Verbose -Message ''
    Write-Verbose -Message '-------------------------------------------------------------------------------'
    Write-Verbose -Message ''
  } #end END
}
