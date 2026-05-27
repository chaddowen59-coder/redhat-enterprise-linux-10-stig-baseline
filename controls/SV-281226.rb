control 'SV-281226' do
  title 'RHEL 10 must prevent a user from overriding the banner-message-enable setting for the graphical user interface.'
  desc <<~DESC
    Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

    For U.S. Government systems, system use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.

    Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000228-GPOS-00088
  DESC
  desc 'check', <<~CHECKTEXT
    Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

    Verify RHEL 10 prevents a user from overriding settings for graphical user interfaces with the following command:

    $ gsettings writable org.gnome.login-screen banner-message-enable
    false

    If "banner-message-enable" is writable, or the result is "true", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent a user from overriding the banner setting for graphical user interfaces.

    Create a database to contain the systemwide graphical user login settings (if it does not already exist) with the following command:

    $ sudo vi /etc/dconf/db/local.d/locks/session

    Add the following setting to prevent nonprivileged users from modifying it:

    /org/gnome/login-screen/banner-message-enable

    Run the following command to update the database:

    $ sudo dconf update
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281226'
  tag rid: 'SV-281226r1166630_rule'
  tag stig_id: 'RHEL-10-700030'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-85692r1166629_fix'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("gsettings writable org.gnome.login-screen banner-message-enable") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
