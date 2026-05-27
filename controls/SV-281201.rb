control 'SV-281201' do
  title 'RHEL 10 must not have accounts configured with blank or null passwords.'
  desc <<~DESC
    If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 prohibits null or blank passwords with the following command:

    $ sudo awk -F: '!$2 {print $1}' /etc/shadow

    If the command returns any results, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that all accounts have a password, or lock the account with the following commands:

    Perform a password reset:

    $ sudo passwd [username]

    To lock an account:

    $ sudo passwd -l [username]
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281201'
  tag rid: 'SV-281201r1166555_rule'
  tag stig_id: 'RHEL-10-600460'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-85667r1166554_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("awk -F: '!$2 {print $1}' /etc/shadow") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
