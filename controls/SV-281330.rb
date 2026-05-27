control 'SV-281330' do
  title 'RHEL 10 must map the authenticated identity to the user or group account for public key infrastructure (PKI)-based authentication.'
  desc <<~DESC
    Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If the system administrator (SA) demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

    Verify RHEL 10 maps the authenticated identity to the user or group account for PKI-based authentication.

    Verify the certificate of the user or group is mapped to the corresponding user or group in the "sssd.conf" file with the following command:

    $ sudo find /etc/sssd/sssd.conf /etc/sssd/conf.d/ -type f -exec cat {} \;
    [certmap/testing.test/rule_name]
    matchrule =<SAN>.*EDIPI@mil
    maprule = (userCertificate;binary={cert!bin})
    domains = testing.test

    If the certmap section does not exist, ask the SA to indicate how certificates are mapped to accounts.

    If there is no evidence of certificate mapping, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to map the authenticated identity to the user or group account by adding or modifying the certmap section of the "/etc/sssd/sssd.conf" file based on the following example:

    [certmap/testing.test/rule_name]
    matchrule = .*EDIPI@mil
    maprule = (userCertificate;binary={cert!bin})
    domains = testing.test

    Restart the "sssd" service with the following command for the changes to take effect:

    $ sudo systemctl restart sssd.service
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281330'
  tag rid: 'SV-281330r1167140_rule'
  tag stig_id: 'RHEL-10-701280'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag fix_id: 'F-85796r1167139_fix'
  tag cci: ['CCI-000187']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("find /etc/sssd/sssd.conf /etc/sssd/conf.d/ -type f -exec cat {} \\;") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
