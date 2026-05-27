control 'SV-281041' do
  title 'RHEL 10 must be configured so that library directories are owned by "root".'
  desc <<~DESC
    If RHEL 10 allowed any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

    This requirement applies to RHEL 10 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the systemwide shared library directories are owned by "root" with the following command:

    $ sudo find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c "%U %n" {} \;

    If any systemwide shared library directory is not owned by "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the systemwide shared library directories (/lib, /lib64, /usr/lib, and /usr/lib64) are protected from unauthorized access.

    Run the following command, replacing "[DIRECTORY]" with any library directory not owned by "root".

    $ sudo chown root [DIRECTORY]
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281041'
  tag rid: 'SV-281041r1165478_rule'
  tag stig_id: 'RHEL-10-400120'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-85507r1165477_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c \"%U %n\" {} \\;") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
