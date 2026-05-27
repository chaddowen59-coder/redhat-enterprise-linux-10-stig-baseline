control 'SV-281184' do
  title 'RHEL 10 must enforce password complexity by requiring that at least one uppercase character be used.'
  desc <<~DESC
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that must be tested before the password is compromised.

    Requiring a minimum number of uppercase characters makes password guessing attacks more difficult by ensuring a larger search space.

    Satisfies: SRG-OS-000069-GPOS-00037, SRG-OS-000070-GPOS-00038
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enforces password complexity by requiring that at least one uppercase character be used.

    Check the value for "ucredit" with the following command:

    $ sudo grep -s ucredit /etc/security/pwquality.conf /etc/security/pwquality.conf/*.conf
    /etc/security/pwquality.conf:ucredit = -1

    If the value of "ucredit" is a positive number or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enforce password complexity by requiring that at least one uppercase character be used by setting the "ucredit" option.

    Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "ucredit" parameter:

    ucredit = -1
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281184'
  tag rid: 'SV-281184r1197239_rule'
  tag stig_id: 'RHEL-10-600250'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-85650r1195429_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -s ucredit /etc/security/pwquality.conf /etc/security/pwquality.conf/*.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
