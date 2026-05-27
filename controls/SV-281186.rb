control 'SV-281186' do
  title 'RHEL 10 must enforce that passwords have a 24 hours/1 day minimum lifetime restriction in "/etc/shadow".'
  desc <<~DESC
    Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy for password reuse.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify the minimum time period between password changes for each user account is one day or greater with the following command:

    $ sudo awk -F: '$4 < 1 {printf "%s %d\n", $1, $4}' /etc/shadow

    If any results are returned that are not associated with a system account, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that noncompliant accounts enforce a 24 hours/1 day minimum password lifetime:

    $ sudo passwd -n 1 [user]
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281186'
  tag rid: 'SV-281186r1184622_rule'
  tag stig_id: 'RHEL-10-600270'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-85652r1166509_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("awk -F: '$4 < 1 {printf \"%s %d\\n\", $1, $4}' /etc/shadow") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
