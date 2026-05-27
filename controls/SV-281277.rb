control 'SV-281277' do
  title 'RHEL 10 must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface.'
  desc <<~DESC
    A session timeout lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems must be able to identify when a user's session has idled and take action to initiate the session lock.

    The session lock is implemented at the point where session activity can be determined and/or controlled.

    Implementing session settings will have little value if a user is able to manipulate these settings from the defaults prescribed in the other requirements of this implementation guide.

    Satisfies: SRG-OS-000028-GPOS-00009, SRG-OS-000030-GPOS-00011
  DESC
  desc 'check', <<~CHECKTEXT
    Note: This requirement assumes the use of the RHEL 10 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is not applicable.

    Verify RHEL 10 prevents a user from overriding the screensaver lock-enabled setting with the following command:

    $ gsettings writable org.gnome.desktop.screensaver lock-enabled
    false

    If "lock-enabled" is writable, and the result is "true", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent a user from overriding settings for graphical user interfaces.

    Create a database to contain the systemwide screensaver settings (if it does not already exist) with the following command:

    Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

    Update the "/etc/dconf/db/local.d/locks/session" file to prevent nonprivileged users from modifying the screensaver lock:

    $ sudo vi /etc/dconf/db/local.d/locks/session

    /org/gnome/desktop/screensaver/lock-enabled

    Run the following command to update the database:

    $ sudo dconf update
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281277'
  tag rid: 'SV-281277r1166783_rule'
  tag stig_id: 'RHEL-10-700740'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-85743r1166782_fix'
  tag cci: ['CCI-000056', 'CCI-000057']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("gsettings writable org.gnome.desktop.screensaver lock-enabled") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
