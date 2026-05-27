control 'SV-281174' do
  title 'RHEL 10 must assign a primary group to all interactive users.'
  desc <<~DESC
    If a user is assigned the group identifier (GID) of a group that does not exist on the system, and a group with the GID is subsequently created, the user may have unintended rights to any files associated with the group.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 interactive users have a valid GID.

    Check that the interactive users have a valid GID with the following command:

    $ sudo pwck -r

    If pwck reports "no group" for any interactive user, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that all GIDs referenced in "/etc/passwd" are defined in "/etc/group".

    Edit the file "/etc/passwd" and ensure that every user's GID is a valid GID.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281174'
  tag rid: 'SV-281174r1166474_rule'
  tag stig_id: 'RHEL-10-600150'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-85640r1166473_fix'
  tag cci: ['CCI-000764']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("pwck -r") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
