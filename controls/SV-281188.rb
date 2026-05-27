control 'SV-281188' do
  title 'RHEL 10 must require that the maximum number of repeating characters be limited to three when passwords are changed.'
  desc <<~DESC
    Use of a complex password helps to increase the time and resources required to compromise the password.

    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex a password is, the greater the number of possible combinations that must be tested before the password is compromised.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 limits the value of the "maxrepeat" option in "/etc/security/pwquality.conf" with the following command:

    $ sudo grep -s maxrepeat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
    /etc/security/pwquality.conf:maxrepeat = 3

    If the value of "maxrepeat" is set to more than "3" or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to require the change of the number of repeating consecutive characters when passwords are changed by setting the "maxrepeat" option.

    Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "maxrepeat" parameter:

    maxrepeat = 3
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281188'
  tag rid: 'SV-281188r1195439_rule'
  tag stig_id: 'RHEL-10-600290'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-85654r1195438_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -s maxrepeat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
