control 'SV-281175' do
  title 'RHEL 10 must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc <<~DESC
    Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system.

    Disabling inactive accounts ensures accounts that may not have been responsibly removed are not available to attackers who may have compromised their credentials.

    Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

    Satisfies: SRG-OS-000118-GPOS-00060, SRG-OS-000590-GPOS-00110
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 account identifiers (individuals, groups, roles, and devices) are disabled after 35 days of inactivity.

    Check the account inactivity value by performing the following command:

    $ sudo grep -i inactive /etc/default/useradd
    INACTIVE=35

    If "INACTIVE" is set to "-1", a value greater than "35", or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable account identifiers after 35 days of inactivity after the password expiration.

    Run the following command to change the configuration for "useradd":

    $ sudo useradd -D -f 35

    A recommendation is 35 days, but a lower value is acceptable.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281175'
  tag rid: 'SV-281175r1197238_rule'
  tag stig_id: 'RHEL-10-600160'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-85641r1166476_fix'
  tag cci: ['CCI-003627', 'CCI-003628']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -i inactive /etc/default/useradd") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
