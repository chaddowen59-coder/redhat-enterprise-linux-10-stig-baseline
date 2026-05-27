control 'SV-281052' do
  title 'RHEL 10 must enforce "root" ownership of audit logs to prevent unauthorized access.'
  desc <<~DESC
    Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

    Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059-GPOS-00029, SRG-OS-000206-GPOS-00084
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enforces "root" ownership of audit logs to prevent unauthorized access.

    Determine where the audit logs are stored with the following command:

    $ sudo grep "^log_file" /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log

    Using the location of the audit log file, determine if the audit log files are owned by "root" using the following command:

    $ sudo ls -la /var/log/audit/audit.log
    rw-------. 2 root root 237923 Jun 11 11:56 /var/log/audit/audit.log

    If the audit logs are not owned by "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enforce "root" ownership of audit logs to prevent unauthorized access with the following command:

    $ sudo chown root [audit_log_file]

    Replace "[audit_log_file]" with the correct audit log path. By default this location is "/var/log/audit/audit.log".
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281052'
  tag rid: 'SV-281052r1165511_rule'
  tag stig_id: 'RHEL-10-400175'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-85518r1165510_fix'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/audit/auditd.conf') do
    it { should exist }
    its('content') { should match(/^log_file/i) }
  end
end
