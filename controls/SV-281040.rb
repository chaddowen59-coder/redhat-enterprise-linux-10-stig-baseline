control 'SV-281040' do
  title 'RHEL 10 must be configured so that library files are group-owned by "root" or a system account.'
  desc <<~DESC
    If RHEL 10 allowed any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

    This requirement applies to RHEL 10 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the systemwide shared library files are group-owned by "root"  or a system account with the following command:

    $ sudo find -L /lib /lib64 /usr/lib /usr/lib64 ! -group root ! -type d -exec stat -L -c "%G %n" {} \;

    If any systemwide shared library file is returned and is not group-owned by "root" or a required system account, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the systemwide shared library files (/lib, /lib64, /usr/lib, and /usr/lib64) are protected from unauthorized access.

    Run the following command, replacing "[FILE]" with any library file not group-owned by "root".

    $ sudo chgrp root [FILE]
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281040'
  tag rid: 'SV-281040r1184734_rule'
  tag stig_id: 'RHEL-10-400115'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-85506r1165474_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("find -L /lib /lib64 /usr/lib /usr/lib64 ! -group root ! -type d -exec stat -L -c \"%G %n\" {} \\;") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
