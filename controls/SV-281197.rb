control 'SV-281197' do
  title 'RHEL 10 must maintain an account lock until the locked account is released by an administrator.'
  desc <<~DESC
    By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.

    Satisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-00005
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured to lock an account after three unsuccessful login attempts until released by an administrator with the following command:

    $ sudo grep 'unlock_time =' /etc/security/faillock.conf
    unlock_time = 0

    If the "unlock_time" option is not set to "0", or the line is missing or commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to lock an account after three unsuccessful login attempts until released by an administrator with the following command:

    $ authselect enable-feature with-faillock

    Edit the "/etc/security/faillock.conf" file as follows:

    unlock_time = 0
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281197'
  tag rid: 'SV-281197r1166543_rule'
  tag stig_id: 'RHEL-10-600425'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-85663r1166542_fix'
  tag cci: ['CCI-002238', 'CCI-000044']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/security/faillock.conf') do
    it { should exist }
    its('content') { should match(/unlock_time =/i) }
  end
end
