control 'SV-281088' do
  title 'RHEL 10 must prevent device files from being interpreted on file systems that contain user home directories.'
  desc <<~DESC
    The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

    The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that "/home" is mounted with the "nodev" option with the following command:

    Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is automatically a finding, as the "nodev" option cannot be used on the "/" system.

    $ mount | grep /home
    /dev/mapper/luks-ca2261ed-7b00-4b7b-84cd-8cd6d8fa4b28 on /home type xfs (rw,nodev,nosuid,noexec,seclabel)

    If the "/home" file system is mounted without the "nodev" option, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent device files from being interpreted on file systems that contain user home directories.

    Modify "/etc/fstab" to use the "nodev" option on the "/home" directory.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281088'
  tag rid: 'SV-281088r1165619_rule'
  tag stig_id: 'RHEL-10-400355'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-85554r1165618_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("mount | grep /home") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
