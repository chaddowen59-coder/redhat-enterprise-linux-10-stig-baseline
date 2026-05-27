control 'SV-281316' do
  title 'RHEL 10 must restrict usage of ptrace to descendant processes.'
  desc <<~DESC
    Unrestricted usage of ptrace allows compromised binaries to run ptrace on other processes of the user. The attacker can then steal sensitive information from the target processes (e.g., SSH sessions, web browser, etc.) without any additional assistance from the user (i.e., without resorting to phishing).
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 restricts the usage of ptrace to descendant processes.

    Check the status of the "kernel.yama.ptrace_scope" kernel parameter with the following command:

    $ sysctl kernel.yama.ptrace_scope
    kernel.yama.ptrace_scope = 1

    If the network parameter "kernel.yama.ptrace_scope" is not equal to "1", or nothing is returned, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to restrict the usage of ptrace to descendant processes.

    Create the drop-in if it does not already exist:

    $ sudo vi /etc/sysctl.d/99-kernel_yama.ptrace_scope.conf

    Add the following line to the file:

    kernel.yama.ptrace_scope = 1

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281316'
  tag rid: 'SV-281316r1167098_rule'
  tag stig_id: 'RHEL-10-701140'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-85782r1167097_fix'
  tag cci: ['CCI-001082']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("sysctl kernel.yama.ptrace_scope") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
