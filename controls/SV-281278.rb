control 'SV-281278' do
  title 'RHEL 10 must automatically lock graphical user sessions after 15 minutes of inactivity.'
  desc <<~DESC
    A session timeout lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, the GNOME desktop can be configured to identify when a user's session has idled and take action to initiate a session lock.

    Satisfies: SRG-OS-000029-GPOS-00010, SRG-OS-000031-GPOS-00012
  DESC
  desc 'check', <<~CHECKTEXT
    Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

    Verify RHEL 10 initiates a session lock after a 15-minute period of inactivity for graphical user interfaces with the following command:

    $ sudo gsettings get org.gnome.desktop.session idle-delay
    uint32 900

    If "idle-delay" is set to "0" or a value greater than "900", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.

    Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

    Update the "/etc/dconf/db/local.d/00-screensaver" file to prevent nonprivileged users from modifying the screensaver idle-delay setting:

    $ sudo vi /etc/dconf/db/local.d/00-screensaver

    [org/gnome/desktop/session]
    # Set the lock time out to 900 seconds before the session is considered idle
    idle-delay=uint32 900

    Update the system databases:

    $ sudo dconf update
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281278'
  tag rid: 'SV-281278r1166786_rule'
  tag stig_id: 'RHEL-10-700750'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-85744r1166785_fix'
  tag cci: ['CCI-000057', 'CCI-000060']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("gsettings get org.gnome.desktop.session idle-delay") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
