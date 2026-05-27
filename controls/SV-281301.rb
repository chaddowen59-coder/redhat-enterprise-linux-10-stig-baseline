control 'SV-281301' do
  title 'RHEL 10 must disable virtual system calls.'
  desc <<~DESC
    System calls are special routines in the Linux kernel, which userspace applications ask to do privileged tasks. Invoking a system call is an expensive operation because the processor must interrupt the currently executing task and switch context to kernel mode and then back to userspace after the system call completes. Virtual system calls map into user space a page that contains some variables and the implementation of some system calls. This allows the system calls to be executed in userspace to alleviate the context-switching expense.

    Virtual system calls provide an opportunity of attack for a user who has control of the return instruction pointer. Disabling virtual system calls help to prevent return-oriented programming attacks via buffer overflows and overruns.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the current GRUB 2 configuration disables virtual system calls with the following command:

    $ sudo grubby --info=ALL | grep args | grep -v 'vsyscall=none'

    If any output is returned, this is a finding.

    Check that virtual system calls are disabled by default to persist in kernel updates with the following command:

    $ sudo grep vsyscall /etc/default/grub
    GRUB_CMDLINE_LINUX="vsyscall=none"

    If "vsyscall" is not set to "none", is missing or commented out, and is not documented with the information system security officer as an operational requirement, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable virtual system calls with the following command:

    $ sudo grubby --update-kernel=ALL --args="vsyscall=none"
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281301'
  tag rid: 'SV-281301r1184700_rule'
  tag stig_id: 'RHEL-10-700990'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-85767r1167052_fix'
  tag cci: ['CCI-001084']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("grubby --info=ALL | grep args | grep -v 'vsyscall=none'") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
