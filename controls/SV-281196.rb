control 'SV-281196' do
  title 'RHEL 10 must automatically lock an account when three unsuccessful login attempts occur during a 15-minute time period.'
  desc <<~DESC
    By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.

    Satisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-00005
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 locks an account after three unsuccessful login attempts within a period of 15 minutes with the following command:

    $ sudo grep fail_interval /etc/security/faillock.conf
    fail_interval = 900

    If the "fail_interval" option is not set to "900" or less (but not "0"), the line is commented out, or the line is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to lock out the "root" account after a number of incorrect login attempts within 15 minutes using "pam_faillock.so". 

    Enable the feature using the following command:

    $ authselect enable-feature with-faillock

    Edit the "/etc/security/faillock.conf" file as follows:

    fail_interval = 900
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281196'
  tag rid: 'SV-281196r1166540_rule'
  tag stig_id: 'RHEL-10-600420'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-85662r1166539_fix'
  tag cci: ['CCI-002238', 'CCI-000044']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep fail_interval /etc/security/faillock.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
