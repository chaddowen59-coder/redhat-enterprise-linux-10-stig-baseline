control 'SV-281113' do
  title 'RHEL 10 must notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization.'
  desc <<~DESC
    If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 notifies the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity with the following command:

    $ sudo grep -w space_left_action /etc/audit/auditd.conf
    space_left_action = email

    If the value of the "space_left_action" is not set to "email", or if the line is commented out, ask the SA to indicate how the system is providing real-time alerts to the SA and ISSO.

    If there is no evidence that real-time alerts are configured on the system, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to initiate an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity by adding/modifying the following line in the "/etc/audit/auditd.conf" file.

    space_left_action = email

    Restart the audit daemon with the following command for the changes to take effect:

    $ sudo service auditd restart
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281113'
  tag rid: 'SV-281113r1184746_rule'
  tag stig_id: 'RHEL-10-500205'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-85579r1166290_fix'
  tag cci: ['CCI-001855']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -w space_left_action /etc/audit/auditd.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
