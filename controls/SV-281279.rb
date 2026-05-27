control 'SV-281279' do
  title 'RHEL 10 must prevent a user from overriding the session idle-delay setting for the graphical user interface.'
  desc <<~DESC
    A session timeout lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, the GNOME desktop can be configured to identify when a user's session has idled and take action to initiate the session lock. Therefore, users should not be allowed to change session settings.

    Satisfies: SRG-OS-000029-GPOS-00010, SRG-OS-000031-GPOS-00012
  DESC
  desc 'check', <<~CHECKTEXT
    Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

    Verify RHEL 10 prevents a user from overriding settings for session idle delay with the following command:

    $ gsettings writable org.gnome.desktop.session idle-delay
    false

    If "idle-delay" is writable, and the result is "true", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent a user from overriding settings for graphical user interfaces.

    Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

    Update the "/etc/dconf/db/local.d/locks/session" file to prevent nonprivileged users from modifying the idle-delay lock:

    $ sudo vi /etc/dconf/db/local.d/locks/session

    /org/gnome/desktop/session/idle-delay

    Run the following command to update the database:

    $ sudo dconf update
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281279'
  tag rid: 'SV-281279r1166789_rule'
  tag stig_id: 'RHEL-10-700760'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-85745r1166788_fix'
  tag cci: ['CCI-000057', 'CCI-000060']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("gsettings writable org.gnome.desktop.session idle-delay") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
