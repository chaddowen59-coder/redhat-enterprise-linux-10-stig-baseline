control 'SV-281074' do
  title 'RHEL 10 must be configured so that all local files and directories have a valid group owner.'
  desc <<~DESC
    Files without a valid group owner may be unintentionally inherited if a group is assigned the same group identifier (GID) as the GID of the files without a valid group owner.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that all local files and directories have a valid group with the following command:

    $ df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nogroup

    If any files on the system do not have an assigned group, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that all local files and directories have a valid group owner.

    Either remove all files and directories from RHEL 10 that do not have a valid group, or assign a valid group to all files and directories on the system with the "chgrp" command:

    $ sudo chgrp <group> <file>
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281074'
  tag rid: 'SV-281074r1165577_rule'
  tag stig_id: 'RHEL-10-400285'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85540r1165576_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nogroup") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
