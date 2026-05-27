control 'SV-281102' do
  title 'RHEL 10 must allocate an "audit_backlog_limit" of sufficient size to capture processes that start prior to the audit daemon.'
  desc <<~DESC
    Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

    Audit records can be generated from various components within the information system (e.g., module or policy filter).

    Allocating an "audit_backlog_limit" of sufficient size is critical in maintaining a stable boot process. With an insufficient limit allocated, the system is susceptible to boot failures and crashes.

    Satisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000062-GPOS-00031, SRG-OS-000254-GPOS-00095, SRG-OS-000341-GPOS-00132, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 allocates a sufficient "audit_backlog_limit" to capture processes that start prior to the audit daemon with the following command:

    $ grep -oP 'audit_backlog_limit=\K[0-9]+' /proc/cmdline
    8192

    If the command returns any outputs, and "audit_backlog_limit" is less than "8192", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to allocate sufficient "audit_backlog_limit" to capture processes that start prior to the audit daemon with the following command:

    $ sudo grubby --update-kernel=ALL --args=audit_backlog_limit=8192

    The setting will be applied on reboot.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281102'
  tag rid: 'SV-281102r1195414_rule'
  tag stig_id: 'RHEL-10-500030'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-85568r1195413_fix'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-001464', 'CCI-001849', 'CCI-002884', 'CCI-000172']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe file('/proc/cmdline') do
    it { should exist }
    its('content') { should match(/audit_backlog_limit=\\k[0-9]+/i) }
  end
end
