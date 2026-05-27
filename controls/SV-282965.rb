control 'SV-282965' do
  title 'RHEL 10 must be a vendor-supported release.'
  desc <<~DESC
    An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

    Red Hat offers the Extended Update Support (EUS) add-on to a Red Hat Enterprise Linux subscription, for a fee, for customers who wish to standardize on a specific minor release for an extended period.

    End-of-life dates for Red Hat Linux 10 releases are as follows:
    - Current end of Full Support for Red Hat Linux 10 is 31 May 2030.
    - Current end of Maintenance Support for Red Hat Linux 10 is 31 May 2035.
    - Current end of Extended Life Cycle Support (ELS) for Red Hat Linux 9 is 31 May 2038.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is a vendor-supported version with the following command:

    $ cat /etc/redhat-release
    Red Hat Enterprise Linux release 10.0 (Coughlan)

    If the installed version of RHEL 10 is not supported, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Upgrade to a supported version of RHEL 10.
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-282965'
  tag rid: 'SV-282965r1197252_rule'
  tag stig_id: 'RHEL-10-001000'
  tag gtitle: 'SRG-OS-000830-GPOS-00300'
  tag fix_id: 'F-87432r1195333_fix'
  tag cci: ['CCI-003376']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("cat /etc/redhat-release") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
