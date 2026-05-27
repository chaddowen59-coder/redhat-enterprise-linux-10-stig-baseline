control 'SV-281234' do
  title 'RHEL 10 must prevent files with the "setuid" and "setgid" bit set from being executed on the "/boot/efi" directory.'
  desc <<~DESC
    The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: For systems that use BIOS and for vfat systems, this requirement is not applicable.

    Verify RHEL 10 is configured so that the "/boot/efi "directory is mounted with the "nosuid" option with the following command:

    $ mount | grep '\s/boot/efi\s'
    /dev/sda1 on /boot/efi type vfat (rw,nosuid,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=ascii,shortname=winnt,errors=remount-ro)

    If the "/boot/efi" file system does not have the "nosuid" option set, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent files with the "setuid" and "setgid" bit set from being executed on the "/boot/efi" directory.

    Modify "/etc/fstab" to use the "nosuid" option on the "/boot/efi" directory.

    To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

    $ sudo systemctl daemon-reload

    Use the following command to apply the changes immediately without a reboot:

    $ sudo mount -o remount /boot/efi
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281234'
  tag rid: 'SV-281234r1166654_rule'
  tag stig_id: 'RHEL-10-700130'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85700r1166653_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe file('/dev/sda1') do
    it { should exist }
    its('content') { should match(%r{\s/boot/efi\s}i) }
  end
end
