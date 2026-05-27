control 'SV-281337' do
  title 'RHEL 10 must enable hardening for the Berkeley Packet Filter (BPF) just-in-time compiler.'
  desc <<~DESC
    When hardened, the extended BPF just-in-time (JIT) compiler will randomize any kernel addresses in the BPF programs and maps, and will not expose the JIT addresses in "/proc/kallsyms".
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enables hardening for the BPF JIT compiler.

    Check the status of the "net.core.bpf_jit_harden" parameter with the following command:

    $ sudo sysctl net.core.bpf_jit_harden
    net.core.bpf_jit_harden = 2

    If "net.core.bpf_jit_harden" is not equal to "2" or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enable hardening for the BPF JIT compiler.

    Create the drop-in file if it does not already exist:

    $ sudo vi /etc/sysctl.d/99-net_core-bpf_jit_harden.conf

    Add the following line to the file:

    net.core.bpf_jit_harden = 2

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281337'
  tag rid: 'SV-281337r1167161_rule'
  tag stig_id: 'RHEL-10-800050'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-85803r1167160_fix'
  tag cci: ['CCI-002824']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe kernel_parameter('net.core.bpf_jit_harden') do
    its('value') { should cmp 2 }
  end
end
