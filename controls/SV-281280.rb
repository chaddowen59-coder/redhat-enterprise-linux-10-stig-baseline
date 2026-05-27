control 'SV-281280' do
  title 'RHEL 10 must initiate a session lock for graphical user interfaces when the screensaver is activated.'
  desc <<~DESC
    A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

    Satisfies: SRG-OS-000029-GPOS-00010, SRG-OS-000031-GPOS-00012
  DESC
  desc 'check', <<~CHECKTEXT
    Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

    Verify RHEL 10 initiates a session lock for graphical user interfaces when the screensaver is activated with the following command:

    $ gsettings get org.gnome.desktop.screensaver lock-delay
    uint32 5

    If the "uint32" setting is not set to "5" or less, or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to initiate a session lock for graphical user interfaces when a screensaver is activated.

    Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

    Create a database to contain the systemwide screensaver settings (if it does not already exist) with the following command:

    $ sudo vi /etc/dconf/db/local.d/00-screensaver

    [org/gnome/desktop/screensaver]
    lock-delay=uint32 5

    The "uint32" must be included along with the integer key values as shown.

    Update the system databases:

    $ sudo dconf update
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281280'
  tag rid: 'SV-281280r1166792_rule'
  tag stig_id: 'RHEL-10-700770'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-85746r1166791_fix'
  tag cci: ['CCI-000057', 'CCI-000060']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("gsettings get org.gnome.desktop.screensaver lock-delay") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
