control 'SV-281032' do
  title 'RHEL 10 must be configured so that the "/etc/shadow-" file is group-owned by "root".'
  desc <<~DESC
    The "/etc/shadow-" file is a backup file of "/etc/shadow", and as such contains the list of local system accounts and password hashes. Protection of this file is critical for system security.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the "/etc/shadow-" file is group-owned by "root" with the following command:

    $ sudo stat -c "%G %n" /etc/shadow-
    root /etc/shadow-

    If the "/etc/shadow-" file does not have a group owner of "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the group of the "/etc/shadow-" file is set to "root" by running the following command:

    $ sudo chgrp root /etc/shadow-
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281032'
  tag rid: 'SV-281032r1165451_rule'
  tag stig_id: 'RHEL-10-400075'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85498r1165450_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("stat -c \"%G %n\" /etc/shadow-") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
