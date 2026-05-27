control 'SV-281319' do
  title 'RHEL 10 must disable core dumps for all users.'
  desc <<~DESC
    A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If kernel dumps are disabled in accordance with RHEL-10-701090, this requirement is not applicable.

    Verify RHEL 10 disables core dumps for all users by issuing the following command:

    $ sudo grep -r core /etc/security/ | grep -v '#'
    /etc/security/limits.d/core_dumps.conf:* hard core 0

    This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains.

    If the "core" item is missing or the value is anything other than "0", and the need for core dumps is not documented with the information system security officer as an operational requirement for all domains that have the "core" item assigned, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable core dumps for all users.

    Create or edit the setting in a drop-in configuration file:

    $ sudo vi /etc/security/limits.d/core_dumps.conf

    Add the following line:

    * hard core 0

    Remove any entries for users or groups with a value set to anything other than "0".
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281319'
  tag rid: 'SV-281319r1184633_rule'
  tag stig_id: 'RHEL-10-701170'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85785r1184632_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/security/limits.d/core_dumps.conf') do
    it { should exist }
    its('content') { should match(/#/i) }
  end
end
