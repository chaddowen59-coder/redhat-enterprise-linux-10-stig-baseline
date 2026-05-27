control 'SV-281152' do
  title 'RHEL 10 must generate audit records for successful and unsuccessful uses of the "umount" system call.'
  desc <<~DESC
    The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing discretionary access control (DAC) modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.

    Satisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000062-GPOS-00031, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 generates an audit record for all uses of the "umount" system call with the following command:

    $ sudo auditctl -l | grep b32 | grep 'umount\b'
    -a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=-1 -F key=privileged-umount

    If the command does not return a line, or the line is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to generate audit records upon successful and unsuccessful uses of the "umount" system call by adding or updating the following rules in "/etc/audit/audit.rules" and adding the following rules to "/etc/audit/rules.d/perm_mod.rules" or updating the existing rules in files in the "/etc/audit/rules.d/" directory:

    -a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=unset -k privileged-umount

    Restart the audit daemon with the following command for the changes to take effect:

    $ sudo service auditd restart
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281152'
  tag rid: 'SV-281152r1166408_rule'
  tag stig_id: 'RHEL-10-500660'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-85618r1166407_fix'
  tag cci: ['CCI-000130', 'CCI-000169', 'CCI-002884', 'CCI-000172']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("auditctl -l | grep b32 | grep 'umount\\b'") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
