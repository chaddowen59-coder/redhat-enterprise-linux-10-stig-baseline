control 'SV-281190' do
  title 'RHEL 10 must enforce password complexity by requiring that at least one numeric character be used.'
  desc <<~DESC
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that must be tested before the password is compromised.

    Requiring digits makes password guessing attacks more difficult by ensuring a larger search space.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enforces password complexity by requiring that at least one numeric character be used.

    Check the value for "dcredit" with the following command:

    $ sudo grep -s dcredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
    /etc/security/pwquality.conf:dcredit = -1

    If the value of "dcredit" is a positive number or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enforce password complexity by requiring that at least one numeric character be used by setting the "dcredit" option.

    Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "dcredit" parameter:

    dcredit = -1
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281190'
  tag rid: 'SV-281190r1195445_rule'
  tag stig_id: 'RHEL-10-600310'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-85656r1195444_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -s dcredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
