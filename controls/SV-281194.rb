control 'SV-281194' do
  title 'RHEL 10 must automatically lock an account when three unsuccessful login attempts occur.'
  desc <<~DESC
    By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

    Satisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-00005
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured to lock an account after three unsuccessful login attempts with the following command:

    $ sudo grep 'deny =' /etc/security/faillock.conf
    deny = 3

    If the "deny" option is not set to "3" or less (but not "0"), or is missing or commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to lock an account when three unsuccessful login attempts occur.

    Add/modify the "/etc/security/faillock.conf" file to match the following line:

    deny = 3
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281194'
  tag rid: 'SV-281194r1166534_rule'
  tag stig_id: 'RHEL-10-600410'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-85660r1166533_fix'
  tag cci: ['CCI-002238', 'CCI-000044']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/security/faillock.conf') do
    it { should exist }
    its('content') { should match(/deny =/i) }
  end
end
