control 'SV-281026' do
  title 'RHEL 10 must be configured so that the "/etc/passwd" file is group-owned by "root".'
  desc <<~DESC
    The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the "/etc/passwd" file is group-owned by "root" with the following command:

    $ sudo stat -c "%G %n" /etc/passwd
    root /etc/passwd

    If the "/etc/passwd" file does not have a group owner of "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the group of the "/etc/passwd" file is set to "root" by running the following command:

    $ sudo chgrp root /etc/passwd
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281026'
  tag rid: 'SV-281026r1165433_rule'
  tag stig_id: 'RHEL-10-400045'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85492r1165432_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("stat -c \"%G %n\" /etc/passwd") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
