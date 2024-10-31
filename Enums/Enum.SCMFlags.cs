  [System.FlagsAttribute]
  public enum SCMFlags : uint
  {
      SC_MANAGER_CONNECT            = 1,
      SC_MANAGER_CREATE_SERVICE     = 2,
      SC_MANAGER_ENUMERATE_SERVICE  = 4,
      SC_MANAGER_LOCK               = 8,
      SC_MANAGER_QUERY_LOCK_STATUS  = 16,
      SC_MANAGER_MODIFY_BOOT_CONFIG = 32,
      SC_MANAGER_ALL_ACCESS         = 983103,
      Generic_All                   = 268435456,
      Generic_Execute               = 536870912,
      Generic_Write                 = 1073741824,
      Generic_Read                  = 2147483648,
  }


// Service Security and Access Rights
// https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights?ranMID=46133&ranEAID=wizKxmN8no4&ranSiteID=wizKxmN8no4-IeZwvoh43192JZrq0xrt5A&epi=wizKxmN8no4-IeZwvoh43192JZrq0xrt5A&irgwc=1&OCID=AIDcmm549zy227_aff_7791_1243925&tduid=(ir__uh6z3jtojwkfby6tfvng2qx9i22xd0oxvpg0khbx00)(7791)(1243925)(wizKxmN8no4-IeZwvoh43192JZrq0xrt5A)()&irclickid=_uh6z3jtojwkfby6tfvng2qx9i22xd0oxvpg0khbx00
