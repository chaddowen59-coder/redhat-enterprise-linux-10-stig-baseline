control 'SV-281324' do
  title 'RHEL 10 must enable certificate-based smart card authentication.'
  desc <<~DESC
    Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. Multifactor authentication requires using two or more factors to achieve authentication. A privileged account is defined as an information system account with authorizations of a privileged user. The DOD Common Access Card (CAC) with DOD-approved public key infrastructure (PKI) is an example of multifactor authentication.

    Satisfies: SRG-OS-000375-GPOS-00160, SRG-OS-000105-GPOS-00052, SRG-OS-000106-GPOS-00053, SRG-OS-000107-GPOS-00054, SRG-OS-000108-GPOS-00055
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If the system administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

    Verify RHEL 10 enables smart cards in the System Security Services Daemon (SSSD) with the following command:

    $ sudo grep -ir pam_cert_auth /etc/sssd/sssd.conf /etc/sssd/conf.d/
    /etc/sssd/conf.d/sssd.conf:pam_cert_auth = True

    If "pam_cert_auth" is not set to "True", the line is commented out, or the line is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enable certificate-based smart card authentication.

    Edit the file "/etc/sssd/sssd.conf" or a configuration file in "/etc/sssd/conf.d" and add or edit the following line:

    pam_cert_auth = True
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281324'
  tag rid: 'SV-281324r1167122_rule'
  tag stig_id: 'RHEL-10-701220'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-85790r1167121_fix'
  tag cci: ['CCI-004046', 'CCI-000765', 'CCI-000766']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -ir pam_cert_auth /etc/sssd/sssd.conf /etc/sssd/conf.d/") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
