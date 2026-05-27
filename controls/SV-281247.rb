control 'SV-281247' do
  title 'RHEL 10 must mount "/var/tmp" with the "nosuid" option.'
  desc <<~DESC
    The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that "/var/tmp" is mounted with the "nosuid" option:

    $ mount | grep /var/tmp
    /dev/mapper/luks-c98555c8-0462-4b97-9afa-6db8c4bfee3b on /var/tmp type xfs (rw,nosuid,nodev,noexec,relatime,seclabel,attr2)

    If the "/var/tmp" file system is mounted without the "nosuid" option, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to mount "/var/tmp" with the "nosuid" option.

    Modify "/etc/fstab" to use the "nosuid" option on the "/var/tmp" directory.

    To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

    $ sudo systemctl daemon-reload

    Use the following command to apply the changes immediately without a reboot:

    $ sudo mount -o remount /var/tmp
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281247'
  tag rid: 'SV-281247r1166693_rule'
  tag stig_id: 'RHEL-10-700195'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-85713r1166692_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("mount | grep /var/tmp") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
