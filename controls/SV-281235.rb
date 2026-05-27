control 'SV-281235' do
  title 'RHEL 10 must mount "/dev/shm" with the "nodev" option.'
  desc <<~DESC
    The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

    The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that "/dev/shm" is mounted with the "nodev" option with the following command:

    $ mount | grep /dev/shm
    tmpfs on /dev/shm type tmpfs (rw,nodev,nosuid,noexec,seclabel)

    If the "/dev/shm" file system is mounted without the "nodev" option, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to mount "/dev/shm" with the "nodev" option.

    Modify "/etc/fstab" to use the "nodev" option on the "/dev/shm" file system.

    To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

    $ sudo systemctl daemon-reload

    Use the following command to apply the changes immediately without a reboot:

    $ sudo mount -o remount /dev/shm
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281235'
  tag rid: 'SV-281235r1166657_rule'
  tag stig_id: 'RHEL-10-700135'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-85701r1166656_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("mount | grep /dev/shm") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
