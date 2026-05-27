control 'SV-281274' do
  title 'RHEL 10 must prevent a user from overriding the disabling of the graphical user interface autorun function.'
  desc <<~DESC
    Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., Transport Layer Security [TLS], WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.

    Satisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163
  DESC
  desc 'check', <<~CHECKTEXT
    Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

    Verify RHEL 10 disables ability of the user to override the graphical user interface autorun setting.

    Check that the autorun setting is set to prevent user modification with the following command:

    $ gsettings writable org.gnome.desktop.media-handling autorun-never
    false

    If "autorun-never" is writable, the result is "true". 

    If this is not documented with the information system security officer as an operational requirement, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the GNOME desktop does not allow a user to change the setting that disables autorun on removable media.

    Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

    Update the "/etc/dconf/db/local.d/locks/00-security-settings-lock" file to prevent user modification:

    $ sudo vi /etc/dconf/db/local.d/locks/00-security-settings-lock

    /org/gnome/desktop/media-handling/autorun-never

    Update the dconf system databases:

    $ sudo dconf update
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281274'
  tag rid: 'SV-281274r1197245_rule'
  tag stig_id: 'RHEL-10-700710'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-85740r1166773_fix'
  tag cci: ['CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("gsettings writable org.gnome.desktop.media-handling autorun-never") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
