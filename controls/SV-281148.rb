control 'SV-281148' do
  title 'RHEL 10 must generate audit records for successful and unsuccessful uses of the "init" command.'
  desc <<~DESC
    Misuse of the "init" command may cause availability issues for the system.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured to audit the execution of the "init" command with the following command:

    $ sudo auditctl -l | grep /usr/sbin/init
    -a always,exit -S all -F path=/usr/sbin/init -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-init

    If the command does not return a line, or the line is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to generate audit records upon successful and unsuccessful uses of the "init" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

    -a always,exit -F path=/usr/sbin/init -F perm=x -F auid>=1000 -F auid!=unset -k privileged-init

    Restart the audit daemon with the following command for the changes to take effect:

    $ sudo service auditd restart
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281148'
  tag rid: 'SV-281148r1166396_rule'
  tag stig_id: 'RHEL-10-500620'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-85614r1166395_fix'
  tag cci: ['CCI-000172']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("auditctl -l | grep /usr/sbin/init") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
