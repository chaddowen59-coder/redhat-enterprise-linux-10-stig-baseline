control 'SV-281223' do
  title 'RHEL 10 must be configured so that user and group account administration utilities are configured to store only encrypted representations of passwords.'
  desc <<~DESC
    Passwords must be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords that are encrypted with a weak algorithm are no more protected than if they are kept in plain text.

    This setting ensures user and group account administration utilities are configured to store only encrypted representations of passwords. Additionally, the "crypt_style" configuration option ensures the use of a strong hashing algorithm that makes password cracking attacks more difficult.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 user and group account administration utilities are configured to store only encrypted representations of passwords with the following command:

    $ sudo grep crypt /etc/libuser.conf
    crypt_style = sha512

    If the "crypt_style" variable is not set to "yescrypt", is not in the defaults section, is commented out, or does not exist, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to use the SHA-512 algorithm for password hashing.

    Add or change the following line in the "[default]" section of the "/etc/libuser.conf" file:

    crypt_style = sha512
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-281223'
  tag rid: 'SV-281223r1166621_rule'
  tag stig_id: 'RHEL-10-600750'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-85689r1166620_fix'
  tag cci: ['CCI-004062']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep crypt /etc/libuser.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
