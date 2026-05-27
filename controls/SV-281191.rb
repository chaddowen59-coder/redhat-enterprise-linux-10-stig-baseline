control 'SV-281191' do
  title 'RHEL 10 must prevent the use of dictionary words for passwords.'
  desc <<~DESC
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    If RHEL 10 allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.

    Satisfies: SRG-OS-000480-GPOS-00225, SRG-OS-000072-GPOS-00040
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 prevents the use of dictionary words for passwords with the following command:

    $ sudo grep -s dictcheck /etc/security/pwquality.conf /etc/pwquality.conf.d/*.conf
    /etc/security/pwquality.conf:dictcheck=1

    If "dictcheck" does not have a value other than "0" or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent the use of dictionary words for passwords.

    Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "dictcheck" parameter:

    dictcheck=1
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281191'
  tag rid: 'SV-281191r1195448_rule'
  tag stig_id: 'RHEL-10-600320'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-85657r1195447_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -s dictcheck /etc/security/pwquality.conf /etc/pwquality.conf.d/*.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
