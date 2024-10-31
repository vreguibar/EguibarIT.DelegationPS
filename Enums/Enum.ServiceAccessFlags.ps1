Add-Type -TypeDefinition @'
  [System.FlagsAttribute]
  public enum ServiceAccessFlags : uint
  {
      QueryConfig          = 1,
      ChangeConfig         = 2,
      QueryStatus          = 4,
      EnumerateDependents  = 8,
      Start                = 16,
      Stop                 = 32,
      PauseContinue        = 64,
      Interrogate          = 128,
      UserDefinedControl   = 256,
      Delete               = 65536,
      ReadControl          = 131072,
      WriteDac             = 262144,
      WriteOwner           = 524288,
      AllAccess            = 983103,
      Synchronize          = 1048576,
      AccessSystemSecurity = 16777216,
      GenericAll           = 268435456,
      GenericExecute       = 536870912,
      GenericWrite         = 1073741824,
      GenericRead          = 2147483648,
  }
'@

# Service Security and Access Rights
# https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights?ranMID=46133&ranEAID=wizKxmN8no4&ranSiteID=wizKxmN8no4-IeZwvoh43192JZrq0xrt5A&epi=wizKxmN8no4-IeZwvoh43192JZrq0xrt5A&irgwc=1&OCID=AIDcmm549zy227_aff_7791_1243925&tduid=(ir__uh6z3jtojwkfby6tfvng2qx9i22xd0oxvpg0khbx00)(7791)(1243925)(wizKxmN8no4-IeZwvoh43192JZrq0xrt5A)()&irclickid=_uh6z3jtojwkfby6tfvng2qx9i22xd0oxvpg0khbx00
