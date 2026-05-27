control 'SV-281079' do
  title 'RHEL 10 must set the umask value to "077" for all local interactive user accounts.'
  desc <<~DESC
    The umask controls the default access mode assigned to newly created files. A umask of "077" limits new files to mode 600 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be "0". This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 sets the default umask for all local interactive users to "077".

    Identify the locations of all local interactive user home directories by looking at the "/etc/passwd" file.

    Check all local interactive user initialization files for interactive users with the following command:

    Note: The example is for a system that is configured to create users' home directories in the "/home" directory.

    $ sudo find /home -maxdepth 2 -type f -name ".[^.]*" -exec grep -iH -d skip --exclude=.bash_history umask {} \;
    /home/disauser/.bash_history:grep -i umask /etc/bashrc /etc/csh.cshrc /etc/profile
    /home/disauser/.bash_history:grep -i umask /etc/login.defs

    If any local interactive user initialization files are found to have a umask statement that sets a value less restrictive than "077", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to set the umask value for all local interactive user accounts to "077".

    Remove the umask statement from all local interactive users' initialization files.

    If the account is for an application, the requirement for a umask less restrictive than "077" can be documented with the information system security officer. However, the user agreement for access to the account must specify that the local interactive user must log in to their account first and then switch the user to the application account with the correct option to gain the account's environment variables.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281079'
  tag rid: 'SV-281079r1165592_rule'
  tag stig_id: 'RHEL-10-400310'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85545r1165591_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("find /home -maxdepth 2 -type f -name \".[^.]*\" -exec grep -iH -d skip --exclude=.bash_history umask {} \\;") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
