control 'SV-281108' do
  title 'RHEL 10 must take action when allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity.'
  desc <<~DESC
    If action is not taken when storage volume reaches 95 percent utilization, the auditing system may fail when the storage volume reaches capacity.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured to take action if allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity with the following command:

    $ sudo grep admin_space_left_action /etc/audit/auditd.conf
    admin_space_left_action = single

    If the value of the "admin_space_left_action" is not set to "single", or if the line is commented out, ask the system administrator (SA) to indicate how the system is providing real-time alerts to the SA and information system security officer (ISSO).

    If there is no evidence that real-time alerts are configured on the system, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 auditd service to take action if allocated audit record storage volume reaching 95 percent of the repository maximum audit record storage capacity.

    Edit the following line in "/etc/audit/auditd.conf" to ensure the system is forced into single user mode if the audit record storage volume is about to reach maximum capacity:

    admin_space_left_action = single

    Restart the audit daemon with the following command for the changes to take effect:

    $ sudo service auditd restart
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281108'
  tag rid: 'SV-281108r1166276_rule'
  tag stig_id: 'RHEL-10-500110'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-85574r1166275_fix'
  tag cci: ['CCI-001855']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep admin_space_left_action /etc/audit/auditd.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
