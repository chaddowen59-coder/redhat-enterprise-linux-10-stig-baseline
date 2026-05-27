control 'SV-281182' do
  title 'RHEL 10 must enforce password complexity by requiring at least one special character to be used.'
  desc <<~DESC
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that must be tested before the password is compromised.

    RHEL 10 uses "pwquality" as a mechanism to enforce password complexity. Note that to require special characters without degrading the "minlen" value, the credit value must be expressed as a negative number in "/etc/security/pwquality.conf".
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enforces password complexity by requiring that at least one special character be used with the following command:

    $ sudo grep -s ocredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
    /etc/security/pwquality.conf:# ocredit = 0

    If the value of "ocredit" is a positive number or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enforce password complexity by requiring that at least one special character be used by setting the "ocredit" option.

    Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "ocredit" parameter:

    ocredit = -1
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281182'
  tag rid: 'SV-281182r1195424_rule'
  tag stig_id: 'RHEL-10-600230'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-85648r1195423_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -s ocredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
