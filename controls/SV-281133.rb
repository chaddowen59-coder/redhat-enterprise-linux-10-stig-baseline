control 'SV-281133' do
  title 'RHEL 10 must generate audit records for successful and unsuccessful uses of the "newgrp" command.'
  desc <<~DESC
    Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information system (e.g., module or policy filter).

    When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

    The system call rules are loaded into a matching engine that intercepts each system call made by all programs on the system. Therefore, it is very important to use system call rules only when absolutely necessary because these affect performance. More rules lead to poorer performance. The performance can be helped, however, by combining system calls into one rule whenever possible.

    Satisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000062-GPOS-00031, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured to audit the execution of the "newgrp" command with the following command:

    $ sudo auditctl -l | grep newgrp
    -a always,exit -S all -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd

    If the command does not return a line, or the line is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to generate audit records upon successful and unsuccessful attempts to use the "newgrp" command by adding or updating the following rule in "/etc/audit/rules.d/audit.rules":

    -a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd

    Restart the audit daemon with the following command for the changes to take effect:

    $ sudo service auditd restart
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281133'
  tag rid: 'SV-281133r1166351_rule'
  tag stig_id: 'RHEL-10-500470'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-85599r1166350_fix'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-002884', 'CCI-000172']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("auditctl -l | grep newgrp") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
