control 'SV-281058' do
  title 'RHEL 10 must enforce mode "755" or less permissive for system commands.'
  desc <<~DESC
    If RHEL 10 allowed any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

    This requirement applies to RHEL 10 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the system commands contained in the following directories have mode "755" or less permissive with the following command:

    $ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin -perm /022 -exec ls -l {} \;

    If any system commands are found to be group-writable or world-writable, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the system commands to be protected from unauthorized access.

    Run the following command, replacing "[FILE]" with any system command with a mode more permissive than "755".

    $ sudo chmod 755 [FILE]
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281058'
  tag rid: 'SV-281058r1165529_rule'
  tag stig_id: 'RHEL-10-400205'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-85524r1165528_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin -perm /022 -exec ls -l {} \\;") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
