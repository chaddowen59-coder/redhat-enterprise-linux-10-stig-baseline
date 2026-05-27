control 'SV-281317' do
  title 'RHEL 10 must disable core dump backtraces.'
  desc <<~DESC
    A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers or system operators trying to debug problems.

    Enabling core dumps on production systems is not recommended; however, there may be overriding operational requirements to enable advanced debugging. Permitting temporary enablement of core dumps during such situations must be reviewed through local needs and policy.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If kernel dumps are disabled in accordance with RHEL-10-701090, this requirement is not applicable.

    Verify RHEL 10 disables core dump backtraces by issuing the following command:

    $ sudo grep -ir ProcessSizeMax /etc/systemd/ | grep -v '#'
    /etc/systemd/coredump.conf:ProcessSizeMax=0

    If the "ProcessSizeMax" item is missing or the value is anything other than "0", and the need for core dumps is not documented with the information system security officer as an operational requirement for all domains that have the "core" item assigned, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable core dump backtraces.

    Create or edit the setting in a drop-in configuration file:

    $ sudo vi /etc/systemd/coredump.conf:

    Add the following line:

    ProcessSizeMax=0
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281317'
  tag rid: 'SV-281317r1167101_rule'
  tag stig_id: 'RHEL-10-701150'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85783r1167100_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/systemd/coredump.conf') do
    it { should exist }
    its('content') { should match(/#/i) }
  end
end
