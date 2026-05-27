control 'SV-281099' do
  title 'RHEL 10 must write audit records to disk.'
  desc <<~DESC
    Audit data must be synchronously written to disk to ensure log integrity. This setting ensures that all audit event data is written to disk.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify the RHEL 10 audit system is configured to write logs to the disk with the following command:

    $ sudo grep write_logs /etc/audit/auditd.conf
    write_logs = yes

    If "write_logs" does not have a value of "yes", the line is commented out, or the line is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure the RHEL 10 audit system to write log files to the disk.

    Edit the "/etc/audit/auditd.conf" file and add or update the "write_logs" option to "yes":

    write_logs = yes

    Restart the audit daemon with the following command for changes to take effect:

    $ sudo service auditd restart
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281099'
  tag rid: 'SV-281099r1165652_rule'
  tag stig_id: 'RHEL-10-500015'
  tag gtitle: 'SRG-OS-000058-GPOS-00028'
  tag fix_id: 'F-85565r1165651_fix'
  tag cci: ['CCI-000163']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep write_logs /etc/audit/auditd.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
