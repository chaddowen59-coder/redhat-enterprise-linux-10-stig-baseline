control 'SV-280939' do
  title 'RHEL 10 must use a separate file system for "/var".'
  desc <<~DESC
    Ensuring that "/var" is mounted on its own partition enables the setting of more restrictive mount options. This helps protect system services such as daemons or other programs that use it. It is not uncommon for the "/var" directory to contain world-writable directories installed by other software packages.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 uses a separate file system/partition for "/var" with the following command:

    $ mount | grep /var
    /dev/mapper/luks-51150299-f295-4145-b8f0-ebe9c6dfd5a0 on /var type xfs (rw,nodev,relatime,seclabel,attr2)
    Note: Options displayed for mount may differ.

    If a separate entry for "/var" is not in use, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to use a separate file system for the "/var" directory by migrating the "/var" path onto a separate file system.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280939'
  tag rid: 'SV-280939r1184729_rule'
  tag stig_id: 'RHEL-10-000550'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85405r1165171_fix'
  tag cci: ['CCI-002385']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("mount | grep /var") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
