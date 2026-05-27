control 'SV-281304' do
  title 'RHEL 10 must enable mitigations against processor-based vulnerabilities.'
  desc <<~DESC
    Kernel page-table isolation is a kernel feature that mitigates the Meltdown security vulnerability and hardens the kernel against attempts to bypass kernel address space layout randomization (KASLR).

    Satisfies: SRG-OS-000433-GPOS-00193, SRG-OS-000095-GPOS-00049
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enables kernel page-table isolation with the following command:

    $ sudo grubby --info=ALL | grep args | grep -v 'pti=on'

    If any output is returned, this is a finding.

    Check that kernel page-table isolation is enabled by default to persist in kernel updates:

    $ sudo grep pti /etc/default/grub
    GRUB_CMDLINE_LINUX="pti=on"

    If "pti" is not set to "on", is missing, or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enable kernel page-table isolation with the following command:

    $ sudo grubby --update-kernel=ALL --args="pti=on"
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281304'
  tag rid: 'SV-281304r1167062_rule'
  tag stig_id: 'RHEL-10-701020'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag fix_id: 'F-85770r1167061_fix'
  tag cci: ['CCI-002824', 'CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("grubby --info=ALL | grep args | grep -v 'pti=on'") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
