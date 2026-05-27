control 'SV-281285' do
  title 'RHEL 10 must prevent a user from overriding the Ctrl-Alt-Del sequence settings for the graphical user interface.'
  desc <<~DESC
    A locally logged-in user who presses Ctrl-Alt-Del when at the console can reboot the system. If accidentally pressed, as could happen in the case of a mixed operating system environment, this can create the risk of short-term loss of systems' availability due to unintentional reboot.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

    Verify RHEL 10 users cannot enable the Ctrl-Alt-Del sequence in the GNOME desktop:

    $ gsettings writable org.gnome.settings-daemon.plugins.media-keys logout
    false

    If "logout" is writable and the result is "true", this is a finding.

    If GNOME is configured to shut down when Ctrl-Alt-Del is pressed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disallow the user changing the Ctrl-Alt-Del sequence in the GNOME desktop.

    Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

    Update the "/etc/dconf/db/local.d/locks/session" file to prevent nonprivileged users from modifying the Ctrl-Alt-Del setting:

    $ sudo vi /etc/dconf/db/local.d/locks/session

    /org/gnome/settings-daemon/plugins/media-keys/logout

    Run the following command to update the database:

    $ sudo dconf update
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281285'
  tag rid: 'SV-281285r1197249_rule'
  tag stig_id: 'RHEL-10-700820'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85751r1166806_fix'
  tag cci: ['CCI-002385']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("gsettings writable org.gnome.settings-daemon.plugins.media-keys logout") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
