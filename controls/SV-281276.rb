control 'SV-281276' do
  title 'RHEL 10 must prevent a user from overriding the disabling of the graphical user smart card removal action.'
  desc <<~DESC
    A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, RHEL 10 must provide users with the ability to manually invoke a session lock so users can secure their session if they must temporarily vacate the immediate physical vicinity.

    Satisfies: SRG-OS-000028-GPOS-00009, SRG-OS-000030-GPOS-00011
  DESC
  desc 'check', <<~CHECKTEXT
    Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

    Verify RHEL 10 disables ability of the user to override the smart card removal action setting with the following command:

    $ gsettings writable org.gnome.settings-daemon.peripherals.smartcard removal-action
    false

    If "removal-action" is writable and the result is "true", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent a user from overriding the disabling of the graphical user smart card removal action.

    Add the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock" to prevent user override of the smart card removal action:

    /org/gnome/settings-daemon/peripherals/smartcard/removal-action

    Update the dconf system databases:

    $ sudo dconf update
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281276'
  tag rid: 'SV-281276r1166780_rule'
  tag stig_id: 'RHEL-10-700730'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-85742r1166779_fix'
  tag cci: ['CCI-000056', 'CCI-000057']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("gsettings writable org.gnome.settings-daemon.peripherals.smartcard removal-action") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
