control 'SV-281233' do
  title 'RHEL 10 must prevent files with the "setuid" and "setgid" bit set from being executed on the "/boot" directory.'
  desc <<~DESC
    The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the "/boot" directory is mounted with the "nosuid" option with the following command:

    $ mount | grep '\s/boot\s'
    /dev/sda1 on /boot type xfs (rw,nodev,nosuid,relatime,seclabel,attr2)

    If the "/boot" file system does not have the "nosuid" option set, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent files with the "setuid" and "setgid" bit set from being executed on the "/boot" directory.

    Modify "/etc/fstab" to use the "nosuid" option on the "/boot" directory.

    To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

    $ sudo systemctl daemon-reload

    Use the following command to apply the changes immediately without a reboot:

    $ sudo mount -o remount /boot
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281233'
  tag rid: 'SV-281233r1166651_rule'
  tag stig_id: 'RHEL-10-700125'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-85699r1166650_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe file('/dev/sda1') do
    it { should exist }
    its('content') { should match(%r{\s/boot\s}i) }
  end
end
