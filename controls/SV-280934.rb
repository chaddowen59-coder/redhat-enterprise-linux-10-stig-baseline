control 'SV-280934' do
  title 'RHEL 10 must have GNU Privacy Guard (GPG) signature verification enabled for all software repositories.'
  desc <<~DESC
    Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and has been provided by a trusted vendor.

    All software packages must be signed with a cryptographic key recognized and approved by the organization.

    Verifying the authenticity of software prior to installation validates the integrity of the software package received from a vendor.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 software repositories defined in "/etc/yum.repos.d/" have been configured with "gpgcheck" enabled with the following command:

    $ sudo grep -w gpgcheck /etc/yum.repos.d/*.repo | more
    gpgcheck = 1

    If "localpkg_gpgcheck" is not set to "1", or if the option is missing or commented out, ask the system administrator how the GPG signatures of local software packages are being verified.

    If no process to verify GPG signatures has been approved by the organization, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 software repositories defined in "/etc/yum.repos.d/" to have "gpgcheck" enabled with the following command:

    $ sudo sed -i 's/gpgcheck\s*=.*/gpgcheck=1/g' /etc/yum.repos.d/*
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-280934'
  tag rid: 'SV-280934r1165157_rule'
  tag stig_id: 'RHEL-10-001050'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-85400r1165156_fix'
  tag cci: ['CCI-003992']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -w gpgcheck /etc/yum.repos.d/*.repo | more") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
