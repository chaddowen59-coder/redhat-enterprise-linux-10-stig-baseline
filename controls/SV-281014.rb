control 'SV-281014' do
  title 'RHEL 10 must use FIPS 140-3-approved cryptographic algorithms for IP tunnels.'
  desc <<~DESC
    Overriding the systemwide cryptographic policy makes the behavior of the Libreswan service violate expectations and makes system configuration more fragmented.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If the IPsec service is not installed, this requirement is not applicable.

    Verify RHEL 10 sets the IPsec service to use the systemwide cryptographic policy with the following command:

    $ sudo grep include /etc/ipsec.conf /etc/ipsec.d/*.conf
    /etc/ipsec.conf:include /etc/crypto-policies/back-ends/libreswan.config

    If the ipsec configuration file does not contain "include /etc/crypto-policies/back-ends/libreswan.config", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that Libreswan uses the systemwide cryptographic policy.

    Add the following line to "/etc/ipsec.conf":

    include /etc/crypto-policies/back-ends/libreswan.config
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-281014'
  tag rid: 'SV-281014r1165397_rule'
  tag stig_id: 'RHEL-10-300070'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-85480r1165396_fix'
  tag cci: ['CCI-000068']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep include /etc/ipsec.conf /etc/ipsec.d/*.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
