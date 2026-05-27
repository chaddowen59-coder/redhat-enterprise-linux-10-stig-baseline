control 'SV-281160' do
  title 'RHEL 10 must generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/shadow".'
  desc <<~DESC
    In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.

    Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000062-GPOS-00031, SRG-OS-000304-GPOS-00121, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000470-GPOS-00214, SRG-OS-000471-GPOS-00215, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000466-GPOS-00210, SRG-OS-000476-GPOS-00221
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/shadow" with the following command:

    $ sudo auditctl -l | egrep '(/etc/shadow)'
    -a always,exit -F arch=b32 -F path=/etc/shadow -F perm=wa -F key=identity
    -a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -F key=identity

    If the command does not return a line, or the line is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/shadow".

    Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

    -a always,exit -F arch=b32 -F path=/etc/shadow -F perm=wa -F key=identity
    -a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -F key=identity

    Restart the audit daemon with the following command for the changes to take effect:

    $ sudo service auditd restart
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281160'
  tag rid: 'SV-281160r1184695_rule'
  tag stig_id: 'RHEL-10-500740'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-85626r1166431_fix'
  tag cci: ['CCI-000018', 'CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000015', 'CCI-002884', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("auditctl -l | egrep '(/etc/shadow)'") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
