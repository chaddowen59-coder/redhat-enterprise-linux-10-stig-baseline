control 'SV-281326' do
  title 'RHEL 10 must, for PKI-based authentication, enforce authorized access to the corresponding private key.'
  desc <<~DESC
    If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

    The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

    If the private key is stolen, this will lead to the compromise of the authentication and nonrepudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

    Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If the system administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

    Verify RHEL 10 SSH private key files have a passcode.

    For each private key stored on the system, use the following command:

    $ sudo ssh-keygen -y -f /path/to/file

    The expected output is a password prompt:
     "Enter passphrase:"

    If the password prompt is not displayed, and the contents of the key are displayed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10, for PKI-based authentication, enforces authorized access to the corresponding private key.

    Create a new private and public key pair that uses a passcode with the following command:

    $ sudo ssh-keygen -N [passphrase]
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281326'
  tag rid: 'SV-281326r1184637_rule'
  tag stig_id: 'RHEL-10-701240'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-85792r1167127_fix'
  tag cci: ['CCI-000186']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("ssh-keygen -y -f /path/to/file") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
