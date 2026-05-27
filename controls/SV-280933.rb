control 'SV-280933' do
  title 'RHEL 10 must check the GNU Privacy Guard (GPG) signature of locally installed software packages before installation.'
  desc <<~DESC
    Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

    All software packages must be signed with a cryptographic key recognized and approved by the organization.

    Verifying the authenticity of software prior to installation validates the integrity of the software package received from a vendor.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 dnf always checks the GPG signature of locally installed software packages before installation with the following command:

    $ sudo grep localpkg_gpgcheck /etc/dnf/dnf.conf
    localpkg_gpgcheck=1

    If "localpkg_gpgcheck" is not set to "1", or if the option is missing or commented out, ask the system administrator how the GPG signatures of local software packages are being verified.

    If no process to verify GPG signatures has been approved by the organization, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 dnf to always check the GPG signature of local software packages before installation.

    Add or update the following line in the [main] section of the "/etc/dnf/dnf.conf" file:

    localpkg_gpgcheck=1
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-280933'
  tag rid: 'SV-280933r1197217_rule'
  tag stig_id: 'RHEL-10-001040'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-85399r1165153_fix'
  tag cci: ['CCI-003992']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep localpkg_gpgcheck /etc/dnf/dnf.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
