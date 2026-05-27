control 'SV-281185' do
  title 'RHEL 10 must require the change of at least eight characters when passwords are changed.'
  desc <<~DESC
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute–force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that must be tested before the password is compromised.

    Requiring a minimum number of different characters during password changes ensures that newly changed passwords should not resemble previously compromised ones.

    Note that passwords that are changed on compromised systems will still be compromised.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 requires the change of at least eight characters when passwords are changed by checking the value of the "difok" option in "/etc/security/pwquality.conf" with the following command:

    $ sudo grep difok -s /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
    /etc/security/pwquality.conf:difok = 8

    If the value of "difok" is set to less than "8" or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to require the change of at least eight of the total number of characters when passwords are changed by setting the "difok" option.

    Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "difok" parameter:

    difok = 8
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281185'
  tag rid: 'SV-281185r1195433_rule'
  tag stig_id: 'RHEL-10-600260'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-85651r1195432_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep difok -s /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
