control 'SV-281098' do
  title 'RHEL 10 must audit local events.'
  desc <<~DESC
    Without establishing what type of events occurred, along with the source, location, and outcome, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

    If option "local_events" is not set to "yes", only events from the network will be aggregated.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify that RHEL 10 generates audit records for local events with the following command:

    $ sudo grep local_events /etc/audit/auditd.conf
    local_events = yes

    If "local_events" is not set to "yes", the command does not return a line, or the line is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to generate audit records for local events by adding or updating the following line in "/etc/audit/auditd.conf":

    local_events = yes

    Restart the audit daemon with the following command for the changes to take effect:

    $ sudo service auditd restart
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281098'
  tag rid: 'SV-281098r1165649_rule'
  tag stig_id: 'RHEL-10-500010'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-85564r1165648_fix'
  tag cci: ['CCI-000169']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep local_events /etc/audit/auditd.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
