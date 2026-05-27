control 'SV-281195' do
  title 'RHEL 10 must automatically lock the root account until the root account is released by an administrator when three unsuccessful login attempts occur during a 15-minute time period.'
  desc <<~DESC
    By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, also known as brute-forcing, is reduced. Limits are imposed by locking the account.

    Satisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-00005
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured to lock the root account after three unsuccessful login attempts with the following command:

    $ sudo grep even_deny_root /etc/security/faillock.conf
    even_deny_root

    If the "even_deny_root" option is not set or is missing or commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to lock out the "root" account after a number of incorrect login attempts using "pam_faillock.so".

    Enable the feature using the following command:

    $ sudo authselect enable-feature with-faillock

    Edit the "/etc/security/faillock.conf" by uncommenting or adding the following line:

    even_deny_root
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281195'
  tag rid: 'SV-281195r1166537_rule'
  tag stig_id: 'RHEL-10-600415'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-85661r1166536_fix'
  tag cci: ['CCI-002238', 'CCI-000044']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep even_deny_root /etc/security/faillock.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
