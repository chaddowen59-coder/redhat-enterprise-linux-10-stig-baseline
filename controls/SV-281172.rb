control 'SV-281172' do
  title 'RHEL 10 must not allow duplicate user IDs (UIDs) to exist for interactive users.'
  desc <<~DESC
    To ensure accountability and prevent unauthenticated access, interactive users must be identified and authenticated to prevent potential misuse and compromise of the system.

    Satisfies: SRG-OS-000104-GPOS-00051, SRG-OS-000121-GPOS-00062
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 contains no duplicate UIDs for interactive users with the following command:

    $ sudo awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd

    If output is produced and the accounts listed are interactive user accounts, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to not allow duplicate UIDs to exist for interactive users.

    Edit the file "/etc/passwd", and provide each interactive user account that has a duplicate UID with a unique UID.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281172'
  tag rid: 'SV-281172r1166468_rule'
  tag stig_id: 'RHEL-10-600130'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-85638r1166467_fix'
  tag cci: ['CCI-000764', 'CCI-000804']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("awk -F \":\" 'list[$3]++{print $1, $3}' /etc/passwd") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
