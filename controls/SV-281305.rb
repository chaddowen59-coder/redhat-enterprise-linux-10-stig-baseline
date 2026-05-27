control 'SV-281305' do
  title 'RHEL 10 must restrict access to the kernel message buffer.'
  desc <<~DESC
    Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

    This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of information system components that are, or use, such products. This can be verified by acceptance/validation processes in DOD or other government agencies.

    There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.

    Restricting access to the kernel message buffer limits access to only root. This prevents attackers from gaining additional system information as a nonprivileged user.

    Satisfies: SRG-OS-000132-GPOS-00067, SRG-OS-000138-GPOS-00069
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured to restrict access to the kernel message buffer.

    Check the status of the "kernel.dmesg_restrict" kernel parameter with the following command:

    $ sudo sysctl kernel.dmesg_restrict
    kernel.dmesg_restrict = 1

    If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to restrict access to the kernel message buffer.

    Create a drop-in if it does not already exist:

    $ sudo vi /etc/sysctl.d/99-dmesg_restrict.conf

    Add the following to the file:

    kernel.dmesg_restrict = 1

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281305'
  tag rid: 'SV-281305r1167065_rule'
  tag stig_id: 'RHEL-10-701030'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-85771r1167064_fix'
  tag cci: ['CCI-001082', 'CCI-001090']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe kernel_parameter('kernel.dmesg_restrict') do
    its('value') { should cmp 1 }
  end
end
