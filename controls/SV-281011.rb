control 'SV-281011' do
  title 'RHEL 10 must be configured so that Secure Shell (SSH) servers use only DOD-approved encryption ciphers employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.'
  desc <<~DESC
    Without cryptographic integrity protections, unauthorized users can alter information without detection.

    Remote access (e.g., Remote Desktop Protocol [RDP]) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganizational-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

    Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions that use asymmetric cryptography. This enables distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

    RHEL 10 incorporates systemwide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the "/etc/sysconfig/sshd" file. The employed algorithms can be viewed in the "/etc/crypto-policies/back-ends/opensshserver.config" file.

    Satisfies: SRG-OS-000125-GPOS-00065, SRG-OS-000250-GPOS-00093
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 SSH servers are configured to use only ciphers employing FIPS 140-3-approved algorithms.

    To verify the ciphers in the systemwide SSH configuration file, use the following command:

    $ sudo grep -i Ciphers /etc/crypto-policies/back-ends/opensshserver.config
    Ciphers aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr

    If the cipher entries in the "opensshserver.config" file have any ciphers other than "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr", or they are missing or commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 SSH servers to use only ciphers employing FIPS 140-3-approved algorithms.

    Reinstall crypto-policies with the following command:

    $ sudo dnf -y reinstall crypto-policies

    Set the crypto-policy to FIPS with the following command:

    $ sudo update-crypto-policies --set FIPS
    Setting system policy to FIPS

    Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-281011'
  tag rid: 'SV-281011r1184644_rule'
  tag stig_id: 'RHEL-10-300040'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-85477r1165387_fix'
  tag cci: ['CCI-000877', 'CCI-001453']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -i Ciphers /etc/crypto-policies/back-ends/opensshserver.config") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
