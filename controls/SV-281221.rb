control 'SV-281221' do
  title 'RHEL 10 must employ FIPS 140-3-approved cryptographic hashing algorithms for all stored passwords.'
  desc <<~DESC
    The system must use a strong hashing algorithm to store the password.

    Passwords must be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

    Satisfies: SRG-OS-000073-GPOS-00041, SRG-OS-000120-GPOS-00061
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 employs FIPS 140-3-approved cryptographic hashing algorithms for all stored passwords for interactive user accounts with the following command:

    $ sudo cut -d: -f2 /etc/shadow
    $6$kcOnRq/5$NUEYPuyL.wghQwWssXRcLRFiiru7f5JPV6GaJhNC2aK5F3PZpE/BCCtwrxRc/AInKMNX3CdMw11m9STiql12f/

    Password hashes "!" or "*" indicate inactive accounts not available for login and are not evaluated.

    If any interactive user password hash does not begin with "$6", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to employ FIPS 140-3-approved cryptographic hashing algorithms for all stored passwords.

    Lock all interactive user accounts not using SHA-512 hashing until the passwords can be regenerated with SHA-512.
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-281221'
  tag rid: 'SV-281221r1166615_rule'
  tag stig_id: 'RHEL-10-600730'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-85687r1166614_fix'
  tag cci: ['CCI-004062', 'CCI-000803']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("cut -d: -f2 /etc/shadow") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
