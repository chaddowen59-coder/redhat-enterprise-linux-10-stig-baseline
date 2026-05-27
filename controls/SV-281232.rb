control 'SV-281232' do
  title 'RHEL 10 must mount "/boot" with the "nodev" option.'
  desc <<~DESC
    The only legitimate location for device files is the "/dev" directory located on the root partition. The only exception to this is chroot jails.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the "/boot" mount point has the "nodev" option with the following command:

    $ mount | grep '\s/boot\s'
    /dev/sda1 on /boot type xfs (rw,nodev,nosuid,relatime,seclabel,attr2)

    If the "/boot" file system does not have the "nodev" option set, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to mount "/boot" with the "nodev" option.

    Modify "/etc/fstab" to use the "nodev" option on the "/boot" directory.

    To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

    $ sudo systemctl daemon-reload

    Use the following command to apply the changes immediately without a reboot:

    $ sudo mount -o remount /boot
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281232'
  tag rid: 'SV-281232r1166648_rule'
  tag stig_id: 'RHEL-10-700120'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-85698r1166647_fix'
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
