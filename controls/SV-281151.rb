control 'SV-281151' do
  title 'RHEL 10 must generate audit records for successful and unsuccessful uses of the shutdown command.'
  desc <<~DESC
    Misuse of the shutdown command may cause availability issues for the system.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured to audit the execution of the "shutdown" command with the following command:

    $ sudo cat /etc/audit/rules.d/* | grep shutdown
    -a always,exit -S all -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-shutdown

    If the command does not return a line, or the line is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to generate audit records upon successful and unsuccessful uses of the "shutdown" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

    -a always,exit -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=unset -k privileged-shutdown

    Restart the audit daemon with the following command for the changes to take effect:

    $ sudo service auditd restart
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281151'
  tag rid: 'SV-281151r1166405_rule'
  tag stig_id: 'RHEL-10-500650'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-85617r1166404_fix'
  tag cci: ['CCI-000172']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("cat /etc/audit/rules.d/* | grep shutdown") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
