control 'SV-280940' do
  title 'RHEL 10 must use a separate file system for "/var/log".'
  desc <<~DESC
    Placing "/var/log" in its own partition enables better separation between log files and other files in "/var/".
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 uses a separate file system/partition for "/var/log" with the following command:

    $ mount | grep /var/log
    /dev/mapper/luks-c651f493-9fdc-4c6e-a711-0a4f03149661 on /var/log type xfs (rw,nosuid,nodev,noexec,relatime,seclabel,attr2)
    Note: Options displayed for mount may differ.

    If a separate entry for "/var/log" is not in use, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to use a separate file system for log file directories by migrating the "/var/log" path onto a separate file system.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280940'
  tag rid: 'SV-280940r1184730_rule'
  tag stig_id: 'RHEL-10-000560'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85406r1165174_fix'
  tag cci: ['CCI-002385']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("mount | grep /var/log") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
