control 'SV-281171' do
  title 'RHEL 10 must assign a home directory for local interactive user accounts upon creation.'
  desc <<~DESC
    If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 assigns a home directory for local interactive user accounts upon creation with the following command:

    $ sudo grep -i create_home /etc/login.defs
    CREATE_HOME yes

    If the value for "CREATE_HOME" parameter is not set to "yes", the line is missing, or the line is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to assign home directories to all new local interactive users by setting the "CREATE_HOME" parameter in "/etc/login.defs" to "yes" as follows:

    CREATE_HOME yes
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281171'
  tag rid: 'SV-281171r1166465_rule'
  tag stig_id: 'RHEL-10-600120'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-85637r1166464_fix'
  tag cci: ['CCI-002824']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -i create_home /etc/login.defs") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
