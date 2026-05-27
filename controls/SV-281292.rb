control 'SV-281292' do
  title 'RHEL 10 must disable the graphical user interface autorunner unless required.'
  desc <<~DESC
    Automatically running applications when media is inserted allows for the easy introduction of unknown data, thereby facilitating malicious activity.

    Satisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163
  DESC
  desc 'check', <<~CHECKTEXT
    Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

    Verify RHEL 10 disables the graphical user interface autorun function.

    Disable the setting with the following command:

    $ gsettings get org.gnome.desktop.media-handling autorun-never
    true

    If "autorun-never" is set to "false" and is not documented with the information system security officer as an operational requirement, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 GNOME to disable autorunning of removable media.

    Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

    Update the "/etc/dconf/db/local.d/00-security-settings" database to disable the GUI autorun function:

    $ sudo vi /etc/dconf/db/local.d/00-security-settings

    [org/gnome/desktop/media-handling]
    autorun-never=true

    Update the dconf system databases:

    $ sudo dconf update
  FIXTEXT
  impact 0.3
  tag check_id: 'M'
  tag severity: 'low'
  tag gid: 'V-281292'
  tag rid: 'SV-281292r1166828_rule'
  tag stig_id: 'RHEL-10-700890'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-85758r1166827_fix'
  tag cci: ['CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("gsettings get org.gnome.desktop.media-handling autorun-never") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
