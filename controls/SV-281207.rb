control 'SV-281207' do
  title 'RHEL 10 must restrict privilege elevation to authorized personnel.'
  desc <<~DESC
    If the "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the target system.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 restricts privilege elevation to authorized personnel with the following command:

    $ sudo grep -riw ALL /etc/sudoers /etc/sudoers.d/ | grep -v "#"

    If the either of the following entries is returned, this is a finding:

    ALL     ALL=(ALL) ALL
    ALL     ALL=(ALL:ALL) ALL
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to restrict privilege elevation to authorized personnel.

    Remove the following entries from the "/etc/sudoers" file or configuration file under "/etc/sudoers.d/":

    ALL     ALL=(ALL) ALL
    ALL     ALL=(ALL:ALL) ALL
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281207'
  tag rid: 'SV-281207r1166573_rule'
  tag stig_id: 'RHEL-10-600520'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-85673r1166572_fix'
  tag cci: ['CCI-002696']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -riw ALL /etc/sudoers /etc/sudoers.d/ | grep -v \"#\"") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
