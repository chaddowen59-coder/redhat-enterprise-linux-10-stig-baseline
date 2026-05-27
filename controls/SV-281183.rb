control 'SV-281183' do
  title 'RHEL 10 must enforce password complexity by requiring that at least one lowercase character be used.'
  desc <<~DESC
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that must be tested before the password is compromised.

    Requiring a minimum number of lowercase characters makes password guessing attacks more difficult by ensuring a larger search space.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enforces password complexity by requiring that at least one lowercase character be used with the following command:

    $ sudo grep -s lcredit /etc/security/pwquality.conf /etc/security/pwquality.conf/*.conf
    /etc/security/pwquality.conf:lcredit = -1

    If the value of "lcredit" is a positive number or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enforce password complexity by requiring that at least one lowercase character be used by setting the "lcredit" option.

    Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "lcredit" parameter:

    lcredit = -1
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281183'
  tag rid: 'SV-281183r1195427_rule'
  tag stig_id: 'RHEL-10-600240'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag fix_id: 'F-85649r1195426_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -s lcredit /etc/security/pwquality.conf /etc/security/pwquality.conf/*.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
