control 'SV-281335' do
  title 'RHEL 10 must disable access to the network bpf system call from nonprivileged processes.'
  desc <<~DESC
    Loading and accessing the packet filters programs and maps using the bpf() system call has the potential to reveal sensitive information about the kernel state.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 prevents privilege escalation through the kernel by disabling access to the bpf system call.

    Check the status of the "kernel.unprivileged_bpf_disabled" kernel parameter with the following command:

    $ sysctl kernel.unprivileged_bpf_disabled
    kernel.unprivileged_bpf_disabled = 1

    If "kernel.unprivileged_bpf_disabled" is not set to "1" or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent privilege escalation through the kernel by disabling access to the bpf system call.

    Create the drop-in file if it does not already exist:

    $ sudo vi /etc/sysctl.d/99-kernel_unprivileged_bpf_disabled

    Add the following line to the file:

    kernel.unprivileged_bpf_disabled = 1

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281335'
  tag rid: 'SV-281335r1167155_rule'
  tag stig_id: 'RHEL-10-800030'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-85801r1167154_fix'
  tag cci: ['CCI-001082']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("sysctl kernel.unprivileged_bpf_disabled") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
