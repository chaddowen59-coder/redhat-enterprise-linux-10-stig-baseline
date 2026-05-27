control 'SV-280938' do
  title 'RHEL 10 must use a separate file system for "/tmp".'
  desc <<~DESC
    The "/tmp" partition is used as temporary storage by many programs. Placing "/tmp" in its own partition enables the setting of more restrictive mount options, which can help protect programs that use it.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 uses a separate file system/partition for "/tmp" with the following command:

    $ mount | grep /tmp
    /dev/mapper/luks-2d7e1b45-73c4-4282-8838-15a897e0d04e on /tmp type xfs(rw,nodev,nosuid,noexec,seclabel)

    Note: Options displayed for mount may differ.

    If a separate entry for "/tmp" is not in use, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to use a separate file system for temporary storage directories by migrating the "/tmp" path onto a separate file system.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280938'
  tag rid: 'SV-280938r1184728_rule'
  tag stig_id: 'RHEL-10-000540'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85404r1165168_fix'
  tag cci: ['CCI-002385']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("mount | grep /tmp") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
