control 'SV-281097' do
  title 'RHEL 10 must enable auditing of processes that start prior to the audit daemon.'
  desc <<~DESC
    Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information available only if auditing is enabled before a given process is created.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that GRUB 2 enables auditing of processes that start prior to the audit daemon with the following commands:

    Check that the current GRUB 2 configuration enables auditing:

    $ sudo grubby --info=ALL | grep args | grep -v 'audit=1'

    If any output is returned, this is a finding.

    Check that auditing is enabled by default to persist in kernel updates:

    $ sudo grep audit /etc/default/grub
    GRUB_CMDLINE_LINUX="audit=1"

    If "audit" is not set to "1", is missing, or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enable auditing of processes that start prior to the audit daemon with the following command:

    $ sudo grubby --update-kernel=ALL --args="audit=1"

    Add or modify the following line in "/etc/default/grub" to ensure the configuration survives kernel updates:

    GRUB_CMDLINE_LINUX="audit=1"
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281097'
  tag rid: 'SV-281097r1165646_rule'
  tag stig_id: 'RHEL-10-500005'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85563r1165645_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("grubby --info=ALL | grep args | grep -v 'audit=1'") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
