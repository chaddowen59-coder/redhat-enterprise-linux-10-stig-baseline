control 'SV-281162' do
  title 'RHEL 10 must generate audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/lastlog".'
  desc <<~DESC
    Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    Satisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000062-GPOS-00031, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215, SRG-OS-000473-GPOS-00218, SRG-OS-000470-GPOS-00214
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 generates audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/lastlog" with the following command:

    $ sudo auditctl -l | grep /var/log/lastlog
    -a always,exit -F arch=b32 -F path=/var/log/lastlog -F perm=wa -F key=logins
    -a always,exit -F arch=b64 -F path=/var/log/lastlog -F perm=wa -F key=logins

    If the command does not return a line, or the line is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/lastlog".

    Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

    -a always,exit -F arch=b32 -F path=/var/log/lastlog -F perm=wa -F key=logins
    -a always,exit -F arch=b64 -F path=/var/log/lastlog -F perm=wa -F key=logins

    Restart the audit daemon with the following command for the changes to take effect:

    $ sudo service auditd restart
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281162'
  tag rid: 'SV-281162r1166438_rule'
  tag stig_id: 'RHEL-10-500760'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-85628r1166437_fix'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-002884', 'CCI-000172']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("auditctl -l | grep /var/log/lastlog") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
