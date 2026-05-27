control 'SV-281282' do
  title 'RHEL 10 must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc <<~DESC
    Setting the screensaver mode to blank-only conceals the contents of the display from passersby.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

    Verify RHEL 10 prevents a user from overriding settings a blank screensaver with the following command:

    $ gsettings writable org.gnome.desktop.screensaver picture-uri
    false

    If "picture-uri" is writable, and the result is "true", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent a user from overriding the picture-uri setting for graphical user interfaces.

    Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

    Update the "/etc/dconf/db/local.d/00-security-settings" file to prevent a user from overriding the "picture-uri" setting:

    $ sudo vi /etc/dconf/db/local.d/00-security-settings

    [org/gnome/desktop/screensaver]
    picture-uri=''

    Update the "/etc/dconf/db/local.d/locks/00-security-settings-lock" file to prevent a user from modifying the lock applied to the "picture-uri" setting:

    $ sudo vi /etc/dconf/db/local.d/locks/00-security-settings-lock

    /org/gnome/desktop/screensaver/picture-uri

    Update the dconf system databases:

    $ sudo dconf update
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281282'
  tag rid: 'SV-281282r1166798_rule'
  tag stig_id: 'RHEL-10-700790'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-85748r1166797_fix'
  tag cci: ['CCI-000060']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("gsettings writable org.gnome.desktop.screensaver picture-uri") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
