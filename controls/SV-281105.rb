control 'SV-281105' do
  title 'RHEL 10 must label all off-loaded audit logs before sending them to the central log server.'
  desc <<~DESC
    Enriched logging is needed to determine who, what, and when events occur on a system. Without this, determining root cause of an event will be much more difficult.

    When audit logs are not labeled before they are sent to a central log server, the audit data will not be able to be analyzed and tied back to the correct system.

    Satisfies: SRG-OS-000039-GPOS-00017, SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224
  DESC
  desc 'check', <<~CHECKTEXT
    Verify the RHEL 10 audit daemon is configured to label all off-loaded audit logs with the following command:

    $ sudo grep name_format /etc/audit/auditd.conf
    name_format = hostname

    If the "name_format" option is not "hostname", "fqd", or "numeric", or the line is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that all off-loaded audit logs are labeled before sending them to the central log server.

    Edit the "/etc/audit/auditd.conf" file and add or update the "name_format" option:

    name_format = hostname

    Restart the audit daemon with the following command for the changes to take effect:

    $ sudo service auditd restart
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281105'
  tag rid: 'SV-281105r1166267_rule'
  tag stig_id: 'RHEL-10-500045'
  tag gtitle: 'SRG-OS-000039-GPOS-00017'
  tag fix_id: 'F-85571r1166266_fix'
  tag cci: ['CCI-000132', 'CCI-001851']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep name_format /etc/audit/auditd.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
