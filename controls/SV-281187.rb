control 'SV-281187' do
  title 'RHEL 10 must require the maximum number of repeating characters of the same character class to be limited to four when passwords are changed.'
  desc <<~DESC
    Use of a complex password helps to increase the time and resources required to compromise the password.

    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex a password is, the greater the number of possible combinations that must be tested before the password is compromised.

    Satisfies: SRG-OS-000072-GPOS-00040, SRG-OS-000730-GPOS-00190
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 limits the value of the "maxclassrepeat" option in "/etc/security/pwquality.conf" with the following command:

    $ sud grep -s maxclassrepeat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
    /etc/security/pwquality.conf:maxclassrepeat = 4

    If the value of "maxclassrepeat" is set to "0" or more than "4" or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to require the change of the number of repeating characters of the same character class when passwords are changed by setting the "maxclassrepeat" option.

    Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "maxclassrepeat" parameter:

    maxclassrepeat = 4
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281187'
  tag rid: 'SV-281187r1195436_rule'
  tag stig_id: 'RHEL-10-600280'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-85653r1195435_fix'
  tag cci: ['CCI-004066', 'CCI-004065']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("sud grep -s maxclassrepeat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
