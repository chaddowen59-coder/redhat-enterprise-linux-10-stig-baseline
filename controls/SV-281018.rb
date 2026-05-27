control 'SV-281018' do
  title 'RHEL 10 must be configured so that the "/etc/group" file is group-owned by "root".'
  desc <<~DESC
    The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the "/etc/group" file is group-owned by "root" with the following command:

    $ sudo stat -c "%G %n" /etc/group
    root /etc/group

    If the "/etc/group" file does not have a group owner of "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the group of the file "/etc/group" is set to "root" by running the following command:

    $ sudo chgrp root /etc/group
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281018'
  tag rid: 'SV-281018r1165409_rule'
  tag stig_id: 'RHEL-10-400005'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85484r1165408_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("stat -c \"%G %n\" /etc/group") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
