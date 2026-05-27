control 'SV-281240' do
  title 'RHEL 10 must mount "/tmp" with the "nosuid" option.'
  desc <<~DESC
    The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that "/tmp" is mounted with the "nosuid" option:

    $ mount | grep /tmp
    /dev/mapper/luks-c98555c8-0462-4b97-9afa-6db8c4bfee3b on /var/tmp type xfs (rw,nosuid,nodev,noexec,relatime,seclabel,attr2)

    If the "/tmp" file system is mounted without the "nosuid" option, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to mount "/tmp" with the "nosuid" option.

    Modify "/etc/fstab" to use the "nosuid" option on the "/tmp" directory.

    To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

    $ sudo systemctl daemon-reload

    Use the following command to apply the changes immediately without a reboot:

    $ sudo mount -o remount /tmp
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281240'
  tag rid: 'SV-281240r1166672_rule'
  tag stig_id: 'RHEL-10-700160'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-85706r1166671_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("mount | grep /tmp") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
