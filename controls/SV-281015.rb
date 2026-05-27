control 'SV-281015' do
  title 'RHEL 10 must implement DOD-approved encryption in the bind package.'
  desc <<~DESC
    Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

    Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

    RHEL 10 incorporates systemwide crypto policies by default. The employed algorithms can be viewed in the "/etc/crypto-policies/back-ends/" directory.

    Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000426-GPOS-00190
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If the "bind" package is not installed, this requirement is not applicable.

    Verify RHEL 10 BIND uses the systemwide cryptographic policy with the following command:

    $ sudo grep include /etc/named.conf
    include "/etc/crypto-policies/back-ends/bind.config";'

    If BIND is installed and the BIND config file does not contain the include "/etc/crypto-policies/back-ends/bind.config" directive, or the line is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 BIND to use the systemwide cryptographic policy.

    Add the following line to the "options" section in "/etc/named.conf":

    include "/etc/crypto-policies/back-ends/bind.config";
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-281015'
  tag rid: 'SV-281015r1184783_rule'
  tag stig_id: 'RHEL-10-300080'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-85481r1165399_fix'
  tag cci: ['CCI-002418', 'CCI-002422']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep include /etc/named.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
