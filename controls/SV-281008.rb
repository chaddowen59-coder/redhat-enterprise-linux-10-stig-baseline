control 'SV-281008' do
  title 'RHEL 10 must implement a FIPS 140-3-compliant systemwide cryptographic policy.'
  desc <<~DESC
    Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.

    Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000396-GPOS-00176, SRG-OS-000393-GPOS-00173, SRG-OS-000394-GPOS-00174
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is set to use a FIPS 140-3-compliant systemwide cryptographic policy.

    Verify the current systemwide crypto-policy with the following command:

    $ update-crypto-policies --show
    FIPS

    If the systemwide crypto-policy is not set to "FIPS", this is a finding.

    Verify the current minimum crypto-policy configuration with the following commands:

    $ sudo grep -E 'rsa_size|hash' /etc/crypto-policies/state/CURRENT.pol
    hash = SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512 SHAKE-256
    min_rsa_size = 2048

    If the "hash" values do not include at least the following FIPS 140-3-compliant algorithms, this is a finding:

    "SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512 SHAKE-256"

    If any algorithms include "SHA1" or a hash value less than "224", this is a finding.

    If the "min_rsa_size" is not set to a value of at least "2048", this is a finding.

    If these commands do not return any output, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to use a FIPS 140-3-compliant systemwide cryptographic policy.

    Set the systemwide crypto-policy to FIPS with the following command:

    $ sudo update-crypto-policies --set FIPS
    Setting system policy to FIPS

    Note: Systemwide crypto-policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-281008'
  tag rid: 'SV-281008r1195401_rule'
  tag stig_id: 'RHEL-10-300010'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-85474r1165378_fix'
  tag cci: ['CCI-000068', 'CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/crypto-policies/state/current.pol') do
    it { should exist }
    its('content') { should match(/rsa_size|hash/i) }
  end
end
