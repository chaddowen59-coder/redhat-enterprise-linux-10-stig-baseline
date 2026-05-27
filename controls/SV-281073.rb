control 'SV-281073' do
  title 'RHEL 10 must be configured so that a sticky bit is set on all public directories.'
  desc <<~DESC
    Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

    This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of information system components that are, or use, such products. This can be verified by acceptance/validation processes in DOD or other government agencies.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that all world-writable directories have the sticky bit set with the following command:

    $ sudo find / -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null
    drwxrwxrwt 7 root root 4096 Jul 26 11:19 /tmp

    If any of the returned directories are world-writable and do not have the sticky bit set, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that all world-writable directories have the sticky bit set to prevent unauthorized and unintended information transferred via shared system resources.

    Set the sticky bit on all world-writable directories using the following command (replace "[World-Writable Directory]" with any directory path missing the sticky bit):

    $ chmod a+t [World-Writable Directory]
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281073'
  tag rid: 'SV-281073r1165574_rule'
  tag stig_id: 'RHEL-10-400280'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-85539r1165573_fix'
  tag cci: ['CCI-001090']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("find / -type d \\( -perm -0002 -a ! -perm -1000 \\) -print 2>/dev/null") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
