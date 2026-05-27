control 'SV-281091' do
  title 'RHEL 10 must mount "/var/log/audit" with the "nodev" option.'
  desc <<~DESC
    The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

    The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that "/var/log/audit" is mounted with the "nodev" option:

    $ mount | grep /var/log/audit
    /dev/mapper/luks-4e45e1ad-5337-42c4-a19f-ee12ccc1d502 on /var/log/audit type xfs (rw,nodev,nosuid,noexec,seclabel)

    If the "/var/log/audit" file system is mounted without the "nodev" option, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to mount "/var/log/audit" with the "nodev" option.

    Modify "/etc/fstab" to use the "nodev" option on the "/var/log/audit" directory.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281091'
  tag rid: 'SV-281091r1165628_rule'
  tag stig_id: 'RHEL-10-400400'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-85557r1165627_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("mount | grep /var/log/audit") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
