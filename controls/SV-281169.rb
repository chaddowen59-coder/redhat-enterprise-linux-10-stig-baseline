control 'SV-281169' do
  title 'RHEL 10 must, for new users or password changes, have a 60-day maximum password lifetime restriction for user account passwords in "/etc/login.defs".'
  desc <<~DESC
    Any password, no matter how complex, can eventually be cracked; therefore, passwords must be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.

    Setting the password maximum age ensures users are required to periodically change their passwords. Requiring shorter password lifetimes increases the risk of users writing down the password in a convenient location subject to physical compromise.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enforces a 60-day maximum password lifetime for new user accounts by running the following command:

    $ sudo grep -i pass_max_days /etc/login.defs
    PASS_MAX_DAYS 60

    If the "PASS_MAX_DAYS" parameter value is greater than "60" or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enforce a 60-day maximum password lifetime.

    Add or modify the following line in the "/etc/login.defs" file:

    PASS_MAX_DAYS 60
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281169'
  tag rid: 'SV-281169r1166459_rule'
  tag stig_id: 'RHEL-10-600100'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-85635r1166458_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -i pass_max_days /etc/login.defs") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
