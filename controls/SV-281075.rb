control 'SV-281075' do
  title 'RHEL 10 must be configured so that all local files and directories must have a valid owner.'
  desc <<~DESC
    Unowned files and directories may be unintentionally inherited if a user is assigned the same user identifier (UID) as the UID of the unowned files.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that all local files and directories have a valid owner with the following command:

    $ df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nouser

    If any files on the system do not have an assigned owner, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that all local files and directories must have a valid owner.

    Either remove all files and directories that do not have a valid user from the system, or assign a valid user to all unowned files and directories on RHEL 10 with the "chown" command:

    $ sudo chown <user> <file>
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281075'
  tag rid: 'SV-281075r1165580_rule'
  tag stig_id: 'RHEL-10-400290'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85541r1165579_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nouser") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
