control 'SV-281090' do
  title 'RHEL 10 must prevent code from being executed on file systems that contain user home directories.'
  desc <<~DESC
    The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that "/home" is mounted with the "noexec" option with the following command:

    Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is automatically a finding, as the "noexec" option cannot be used on the "/" system.

    $ mount | grep /home
    /dev/mapper/luks-ca2261ed-7b00-4b7b-84cd-8cd6d8fa4b28 on /home type xfs (rw,nodev,nosuid,noexec,seclabel)

    If the "/home" file system is mounted without the "noexec" option, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent code from being executed on file systems that contain user home directories.

    Modify "/etc/fstab" to use the "noexec" option on the "/home" directory.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281090'
  tag rid: 'SV-281090r1165625_rule'
  tag stig_id: 'RHEL-10-400365'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85556r1165624_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("mount | grep /home") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
