control 'SV-281170' do
  title 'RHEL 10 must, for user account passwords, have a 60-day maximum password lifetime restriction.'
  desc <<~DESC
    Any password, no matter how complex, can eventually be cracked. Therefore, passwords must be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enforces a 60-day maximum time period for existing user account passwords with the following commands:

    $ sudo awk -F: '$5 > 60 {print $1 "" "" $5}' /etc/shadow

    $ sudo awk -F: '$5 <= 0 {print $1 "" "" $5}' /etc/shadow

    If any results are returned that are not associated with a system account, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enforce a 60-day maximum password lifetime restriction on user account passwords.

    Set the 60-day maximum password lifetime restriction with the following command:

    $ sudo passwd -x 60 [user]
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281170'
  tag rid: 'SV-281170r1184651_rule'
  tag stig_id: 'RHEL-10-600110'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-85636r1166461_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("awk -F: '$5 > 60 {print $1 \"\" \"\" $5}' /etc/shadow") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
