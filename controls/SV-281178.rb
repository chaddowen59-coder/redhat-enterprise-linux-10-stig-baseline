control 'SV-281178' do
  title 'RHEL 10 must ensure that all local interactive user home directories defined in the "/etc/passwd" file must exist.'
  desc <<~DESC
    If a local interactive user has a home directory defined that does not exist, the user may be given access to the / directory as the current working directory upon login. This could create a denial of service because the user would not be able to access their login configuration files, and it may give them visibility to system files they normally would not be able to access.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 interactive users' home directories exist on the system with the following command:

    $ sudo pwck -r
    user 'mailnull': directory 'var/spool/mqueue' does not exist

    The output should not return any interactive users.

    If an interactive user's home directory does not exist, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 interactive users' home directories to exist on the system.

    Create home directories to all local interactive users that do not have a home directory assigned. Use the following commands to create the user home directory assigned in "/etc/ passwd":

    Note: The example will be for the user "disauser", who has a home directory of "/home/disauser", a user identifier (UID) of "disauser", and a group identifier (GID) of "users assigned" in "/etc/passwd".

    $ sudo mkdir /home/disauser
    $ sudo chown disauser /home/disauser
    $ sudo chgrp users /home/disauser
    $ sudo chmod 0750 /home/disauser
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281178'
  tag rid: 'SV-281178r1195418_rule'
  tag stig_id: 'RHEL-10-600190'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85644r1166485_fix'
  tag cci: ['CCI-002385']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("pwck -r") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
