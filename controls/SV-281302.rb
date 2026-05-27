control 'SV-281302' do
  title 'RHEL 10 must clear the page allocator to prevent use-after-free attacks.'
  desc <<~DESC
    Poisoning writes an arbitrary value to freed pages, so any modification or reference to that page after being freed or before being initialized will be detected and prevented. This prevents many types of use-after-free vulnerabilities at little performance cost. It also prevents data leakage and detection of corrupted memory.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the current GRUB 2 configuration enables page poisoning to mitigate use-after-free vulnerabilities.

    Check that the current GRUB 2 configuration has page poisoning enabled with the following command:

    $ sudo grubby --info=ALL | grep args | grep -v 'page_poison=1'

    If any output is returned, this is a finding.

    Check that page poisoning is enabled by default to persist in kernel updates with the following command:

    $ sudo grep page_poison /etc/default/grub
    GRUB_CMDLINE_LINUX="page_poison=1"

    If "page_poison" is not set to "1", is missing or commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enable page poisoning with the following commands:

    $ sudo grubby --update-kernel=ALL --args="page_poison=1"
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281302'
  tag rid: 'SV-281302r1167056_rule'
  tag stig_id: 'RHEL-10-701000'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-85768r1167055_fix'
  tag cci: ['CCI-001084']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("grubby --info=ALL | grep args | grep -v 'page_poison=1'") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
