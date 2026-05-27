control 'SV-281220' do
  title 'RHEL 10 must be configured so that password-auth uses a sufficient number of hashing rounds.'
  desc <<~DESC
    Passwords must be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords that are encrypted with a weak algorithm are no more protected than if they are kept in plain text.

    Using more hashing rounds makes password cracking attacks more difficult.

    Satisfies: SRG-OS-000073-GPOS-00041, SRG-OS-000120-GPOS-00061
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured to use a sufficient number of rounds for password hashing with the following command:

    $ sudo grep rounds /etc/pam.d/password-auth
    password sufficient pam_unix.so sha512 rounds=100000

    If the setting is not configured or "rounds" is less than "100000", this a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to use "100000" hashing rounds for hashing passwords.

    Add or modify the following line in "/etc/pam.d/password-auth" and set "rounds" to "100000":

    password sufficient pam_unix.so sha512 rounds=100000
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281220'
  tag rid: 'SV-281220r1166612_rule'
  tag stig_id: 'RHEL-10-600720'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-85686r1166611_fix'
  tag cci: ['CCI-004062', 'CCI-000803']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep rounds /etc/pam.d/password-auth") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
