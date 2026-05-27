control 'SV-281109' do
  title 'RHEL 10 must take appropriate action when the internal event queue is full.'
  desc <<~DESC
    The audit system must have an action set up in case the internal event queue becomes full so that no data is lost. Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.

    Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224
  DESC
  desc 'check', <<~CHECKTEXT
    Verify the RHEL 10 audit system is configured to take an appropriate action when the internal event queue is full:

    $ sudo grep overflow_action /etc/audit/auditd.conf
    overflow_action = syslog

    If the value of the "overflow_action" option is not set to "syslog", "single", or "halt", or the line is commented out, ask the system administrator to indicate how the audit logs are off-loaded to a different system or media.

    If there is no evidence that the audit system is configured to off-load the audit logs to another system or media, and if the overflow action is not set to take appropriate action if the internal event queue becomes full, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to take appropriate action when the internal event queue is full.

    Edit the "/etc/audit/auditd.conf" file and add or update the "overflow_action" option:

    overflow_action = syslog

    Restart the audit daemon with the following command for the changes to take effect:

    $ sudo service auditd restart
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281109'
  tag rid: 'SV-281109r1184691_rule'
  tag stig_id: 'RHEL-10-500115'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-85575r1166278_fix'
  tag cci: ['CCI-001851']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep overflow_action /etc/audit/auditd.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
