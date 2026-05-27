control 'SV-281078' do
  title 'RHEL 10 must be configured so that audit tools are group-owned by "root".'
  desc <<~DESC
    Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data; therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

    RHEL 10 systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools, and the corresponding rights the user enjoys, to make access decisions regarding the access to audit tools.

    Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

    Satisfies: SRG-OS-000256-GPOS-00097, SRG-OS-000257-GPOS-00098, SRG-OS-000258-GPOS-00099
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 audit tools are group-owned by "root" with the following command:

    $ sudo stat -c "%G %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/rsyslogd /sbin/augenrules
    root /sbin/auditctl
    root /sbin/aureport
    root /sbin/ausearch
    root /sbin/auditd
    root /sbin/rsyslogd
    root /sbin/augenrules

    If any audit tools do not have a group owner of "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the audit tools are group-owned by "root" by running the following command:

    $ sudo chgrp root [audit_tool]

    Replace "[audit_tool]" with each audit tool not group-owned by "root".
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281078'
  tag rid: 'SV-281078r1165589_rule'
  tag stig_id: 'RHEL-10-400305'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-85544r1165588_fix'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("stat -c \"%G %n\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/rsyslogd /sbin/augenrules") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
