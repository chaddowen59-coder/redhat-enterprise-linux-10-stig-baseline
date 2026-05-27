control 'SV-281202' do
  title 'RHEL 10 must have a unique group ID (GID) for each group in "/etc/group".'
  desc <<~DESC
    To ensure accountability and prevent unauthenticated access, groups must be identified uniquely to prevent potential misuse and compromise of the system.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 contains no duplicate GIDs for interactive users with the following command:

     $  cut -d : -f 3 /etc/group | uniq -d

    If the system has duplicate GIDs, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to contain no duplicate GIDs for interactive users.

    Edit the file "/etc/group", and provide each group that has a duplicate GID with a unique GID.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281202'
  tag rid: 'SV-281202r1166558_rule'
  tag stig_id: 'RHEL-10-600470'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-85668r1166557_fix'
  tag cci: ['CCI-000764']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("cut -d : -f 3 /etc/group | uniq -d") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
