control 'SV-281286' do
  title 'RHEL 10 must disable the ability of a user to accidentally press Ctrl-Alt-Del and cause a system to shut down or reboot.'
  desc <<~DESC
    A locally logged-in user who presses Ctrl-Alt-Del, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of mixed operating system environments, this can create the risk of short-term loss of availability of systems due to unintentional reboot.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

    Verify RHEL 10 is configured to ignore the Ctrl-Alt-Del sequence in the GNOME desktop with the following command:

    Check that the Ctrl-Alt-Del sequence settings for the graphical user interface cannot be overridden with the following command:

    $ gsettings get org.gnome.settings-daemon.plugins.media-keys logout
    @as []

    If the GNOME desktop is configured to shut down when Ctrl-Alt-Del is pressed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to ignore the Ctrl-Alt-Del sequence in the GNOME desktop.

    Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

    Update the "/etc/dconf/db/local.d/00-media-keys" file to set the media-keys logout setting as an empty string array:

    $ sudo vi /etc/dconf/db/local.d/00-media-keys

    [org/gnome/settings-daemon/plugins/media-keys]
    logout=@as []

    Run the following command to update the database:

    $ sudo dconf update
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281286'
  tag rid: 'SV-281286r1166810_rule'
  tag stig_id: 'RHEL-10-700830'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85752r1166809_fix'
  tag cci: ['CCI-002385']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("gsettings get org.gnome.settings-daemon.plugins.media-keys logout") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
