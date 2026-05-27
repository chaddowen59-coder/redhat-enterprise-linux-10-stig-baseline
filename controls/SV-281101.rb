control 'SV-281101' do
  title 'RHEL 10 must allow only the information system security manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc <<~DESC
    Without the capability to restrict the roles and individuals that can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 sets the files in directory "/etc/audit/rules.d/" and "/etc/audit/auditd.conf" file to have a mode of "0640" or less permissive with the following command:

    $ sudo find /etc/audit/rules.d/ /etc/audit/audit.rules /etc/audit/auditd.conf -type f -exec stat -c "%a %n" {} \;
    600 /etc/audit/rules.d/audit.rules
    640 /etc/audit/audit.rules
    640 /etc/audit/auditd.conf

    If the audit configuration files have a mode more permissive than those shown, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the files in directory "/etc/audit/rules.d/" and the "/etc/audit/auditd.conf" file have a mode of "0640" with the following commands:

    $ sudo chmod 0600 /etc/audit/rules.d/audit.rules
    $ sudo chmod 0640 /etc/audit/rules.d/[customrulesfile].rules
    $ sudo chmod 0640 /etc/audit/auditd.conf
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281101'
  tag rid: 'SV-281101r1195411_rule'
  tag stig_id: 'RHEL-10-500025'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-85567r1195410_fix'
  tag cci: ['CCI-000171']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("find /etc/audit/rules.d/ /etc/audit/audit.rules /etc/audit/auditd.conf -type f -exec stat -c \"%a %n\" {} \\;") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
