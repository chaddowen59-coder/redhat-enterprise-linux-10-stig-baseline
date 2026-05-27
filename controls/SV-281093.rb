control 'SV-281093' do
  title 'RHEL 10 must mount "/var/log/audit" with the "nosuid" option.'
  desc <<~DESC
    The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that "/var/log/audit" is mounted with the "nosuid" option:

    $ mount | grep /var/log/audit
    /dev/mapper/luks-4e45e1ad-5337-42c4-a19f-ee12ccc1d502 on /var/log/audit type xfs (rw,nodev,nosuid,noexec,seclabel)

    If the "/var/log/audit" file system is mounted without the "nosuid" option, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to mount "/var/log/audit" with the "nosuid" option.

    Modify "/etc/fstab" to use the "nosuid" option on the "/var/log/audit" directory.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281093'
  tag rid: 'SV-281093r1165634_rule'
  tag stig_id: 'RHEL-10-400410'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-85559r1165633_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("mount | grep /var/log/audit") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
