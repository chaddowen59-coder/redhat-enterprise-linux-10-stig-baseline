control 'SV-281311' do
  title 'RHEL 10 must disable the "kernel.core_pattern".'
  desc <<~DESC
    A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 disables storing core dumps.

    Check the status of the "kernel.core_pattern" kernel parameter with the following command:

    $ sudo sysctl kernel.core_pattern
    kernel.core_pattern = |/bin/false

    If "kernel.core_pattern" is not set to "|/bin/false", or a line is not returned and the need for core dumps is not documented with the information system security officer as an operational requirement, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable storing core dumps. 

    Create a drop-in if it does not already exist:

    $ sudo vi /etc/sysctl.d/99-kernel_core_pattern.conf

    Add the following to the file:

    kernel.core_pattern = |/bin/false

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281311'
  tag rid: 'SV-281311r1167083_rule'
  tag stig_id: 'RHEL-10-701090'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85777r1167082_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("sysctl kernel.core_pattern") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
