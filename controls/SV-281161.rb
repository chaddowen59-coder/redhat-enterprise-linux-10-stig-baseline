control 'SV-281161' do
  title 'RHEL 10 must generate audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/faillock".'
  desc <<~DESC
    Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    Satisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000470-GPOS-00214, SRG-OS-000473-GPOS-00218
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 generates audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/faillock" with the following command:

    $ sudo auditctl -l | grep /var/log/faillock
    -a always,exit -F arch=b32 -F path=/var/log/faillock -F perm=wa -F key=identity
    -a always,exit -F arch=b64 -F path=/var/log/faillock -F perm=wa -F key=identity

    If the command does not return a line, or the line is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/faillock".

    Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

    -a always,exit -F arch=b32 -F path=/var/log/faillock -F perm=wa -F key=identity
    -a always,exit -F arch=b64 -F path=/var/log/faillock -F perm=wa -F key=identity

    Restart the audit daemon with the following command for the changes to take effect:

    $ sudo service auditd restart
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281161'
  tag rid: 'SV-281161r1166435_rule'
  tag stig_id: 'RHEL-10-500750'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-85627r1166434_fix'
  tag cci: ['CCI-002884', 'CCI-000172']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("auditctl -l | grep /var/log/faillock") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
