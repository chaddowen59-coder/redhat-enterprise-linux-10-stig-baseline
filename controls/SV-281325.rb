control 'SV-281325' do
  title 'RHEL 10 must implement certificate status checking for multifactor authentication.'
  desc <<~DESC
    Using an authentication device, such as a DOD common access card (CAC) or token that is separate from the information system, ensures that even if the information system is compromised, credentials stored on the authentication device will not be affected.

    Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification (PIV) card and the DOD CAC.

    RHEL 10 includes multiple options for configuring certificate status checking but for this requirement focuses on the System Security Services Daemon (SSSD). By default, SSSD performs Online Certificate Status Protocol (OCSP) checking and certificate verification using a sha256 digest function.

    Satisfies: SRG-OS-000375-GPOS-00160, SRG-OS-000377-GPOS-00162, SRG-OS-000705-GPOS-00150
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If the system administrator (SA) demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

    Verify RHEL 10 implements OCSP and is using the proper digest value on the system with the following command:

    $ sudo grep -irs certificate_verification /etc/sssd/sssd.conf /etc/sssd/conf.d/ | grep -v "^#"
    /etc/sssd/conf.d/certificate_verification.conf:certificate_verification = ocsp_dgst=sha512

    If the certificate_verification line is missing from the [sssd] section, or is missing "ocsp_dgst=sha512", ask the SA to indicate what type of multifactor authentication is being used and how the system implements certificate status checking. 

    If there is no evidence of certificate status checking being used, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to implement certificate status checking for multifactor authentication.

    Review the "/etc/sssd/conf.d/certificate_verification.conf" file to determine if the system is configured to prevent OCSP or certificate verification.

    Add the following line to the [sssd] section of the "/etc/sssd/conf.d/certificate_verification.conf" file:

    certificate_verification = ocsp_dgst=sha512

    Set the correct ownership and permissions on the "/etc/sssd/conf.d/certificate_verification.conf" file by running these commands:

    $ sudo chown root:root "/etc/sssd/conf.d/certificate_verification.conf"
    $ sudo chmod 600 "/etc/sssd/conf.d/certificate_verification.conf"

    Restart the "sssd" service with the following command for the changes to take effect: 

    $ sudo systemctl restart sssd.service
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281325'
  tag rid: 'SV-281325r1184772_rule'
  tag stig_id: 'RHEL-10-701230'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-85791r1167124_fix'
  tag cci: ['CCI-004046', 'CCI-001954', 'CCI-004047']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/sssd/conf.d/certificate_verification.conf') do
    it { should exist }
    its('content') { should match(/^#/i) }
  end
end
