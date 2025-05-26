# Remote Debugging Configuration for EguibarIT.DelegationPS

This document provides instructions for debugging the EguibarIT.DelegationPS module on a remote Windows Server 2025 CORE machine (DC1) using Visual Studio Code.

## Prerequisites

- PowerShell 7.5+ on both local and remote machines
- PowerShell remoting enabled between the machines
- VS Code with the PowerShell extension installed
- EguibarIT.DelegationPS module installed on the remote server at `C:\Program Files\PowerShell\Modules\EguibarIT.DelegationPS`

## Known Issues and Fixes

### Set-GpoPrivilegeRight Empty Collection Issue (Fixed May 21, 2025)

#### Issue:
- Function `Set-GpoPrivilegeRight` was failing with error: "Cannot bind argument to parameter 'Collection' because it is an empty collection"
- This occurred when calling `Add-EmptyPrivilegeRight` with an empty collection
- The issue is a PowerShell parameter binding limitation with empty collections and `[Parameter(Mandatory = $true)]` attributes
- Additional issue found: "Unable to find type [System.Management.Automation.PSBoundParametersDictionary]" in `Add-ParameterBasedRight.ps1`

#### Root Cause:
- PowerShell's parameter binding treats empty collections specially
- When a parameter is marked with `[Parameter(Mandatory = $true)]`, PowerShell may reject empty collections even if they're the correct type
- This happens because PowerShell applies additional validation beyond type checking
- This is a known PowerShell behavior and not a coding error in the original function
- The type issue was due to using a specific PowerShell type that might not be available in all environments

#### Solution:
1. Created a dedicated function `Add-EmptyPrivilegeRightLocal.ps1` in the Private folder that:
   - Avoids `[Parameter(Mandatory = $true)]` by using `[Parameter(Mandatory = $false)]`
   - Includes `[AllowNull()]` and `[AllowEmptyCollection()]` attributes
   - Adds items directly to the collection rather than calling `Add-Right`
   - Has proper error handling and verbose output
2. Modified `Add-ParameterBasedRight.ps1` to use `[System.Collections.IDictionary]` instead of `[System.Management.Automation.PSBoundParametersDictionary]`
3. Updated `Set-GpoPrivilegeRight.ps1` to call the new external function
4. Added comprehensive documentation and test cases

#### Lessons Learned:
- When passing empty collections to functions with `[Parameter(Mandatory = $true)]` parameters, use helper functions
- Avoid chained calls with empty collections when Mandatory parameters are involved
- Consider making collection parameters not mandatory or add the `[AllowEmptyCollection()]` attribute
- Use more general interface types like `IDictionary` rather than specific implementation types

#### References:
- This is a known PowerShell behavior: https://github.com/PowerShell/PowerShell/issues/4616
- Avoid mandatory parameters for collections that might be empty
- PowerShell parameter attributes: https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/parameter-attribute-declaration

## Available Debug Configurations

### VS Code Launch Configurations (F5)

1. **PowerShell: DC1 - Debug Module**
   Connects to DC1 and attaches to a PowerShell process for debugging.

2. **PowerShell: Deploy & Debug Module on DC1**
   Deploys the module to DC1 and sets up a debugging session.

3. **PowerShell: DC1 - Test Function**
   Runs a specific function on DC1 for testing.

4. **PowerShell: DC1 - Run Pester Tests**
   Runs Pester tests on DC1.

5. **PowerShell: Remote PSSession to DC1**
   Opens an interactive PowerShell session with DC1.

### VS Code Tasks (Ctrl+Shift+P -> Tasks: Run Task)

1. **DC1: Deploy Module**
   Deploys the module to the remote server.

2. **DC1: Test Module**
   Tests the basic functionality of the module.

3. **DC1: Interactive Session**
   Opens an interactive PowerShell session.

4. **DC1: Debug**
   Sets up a debugging session.

5. **DC1: Run Pester Tests**
   Runs Pester tests on the remote server.

## Helper Script: Debug-RemoteModule.ps1

A comprehensive script for remote debugging operations with the following actions:

- **DeployModule**: Deploys the module to the remote server
- **TestModule**: Tests module functionality
- **RunTests**: Runs Pester tests
- **Debug**: Sets up a debugging session
- **Interactive**: Opens an interactive session

### Examples

```powershell
# Deploy the module to DC1
.\Debug-RemoteModule.ps1 -Action DeployModule -Verbose

# Test a specific function
.\Debug-RemoteModule.ps1 -Action TestModule -FunctionName "Test-IsValidDN" -Parameters @{ObjectDN="CN=Administrator,CN=Users,DC=domain,DC=com"}

# Run a specific Pester test
.\Debug-RemoteModule.ps1 -Action RunTests -TestFile "Test-IsValidDN.Tests.ps1"

# Set up a debugging session
.\Debug-RemoteModule.ps1 -Action Debug

# Open an interactive session
.\Debug-RemoteModule.ps1 -Action Interactive
```

## Debugging Workflow

1. **Deploy the latest module version**:
   - Use the "DC1: Deploy Module" task or the "PowerShell: Deploy & Debug Module on DC1" launch configuration

2. **Set breakpoints** in your code files

3. **Start debugging**:
   - Choose the appropriate launch configuration
   - When prompted, provide credentials for DC1

4. **Debug your code**:
   - Use the VS Code debugging controls (Step Into, Step Over, Continue, etc.)
   - Use the Debug Console to examine variables

5. **Run tests**:
   - Use the "DC1: Run Pester Tests" task to verify functionality

## Troubleshooting

- **Connection Issues**: Verify that PowerShell remoting is enabled and that you have network connectivity to DC1
- **Module Not Found**: Verify that the module is correctly installed at `C:\Program Files\PowerShell\Modules\EguibarIT.DelegationPS` on DC1
- **Debugging Not Working**: Ensure that you're running PowerShell 7.5+ on both machines and that the PowerShell extension in VS Code is up to date
