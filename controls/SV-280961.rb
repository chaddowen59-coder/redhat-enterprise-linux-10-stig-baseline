control 'SV-280961' do
  title 'RHEL 10 must disable network management of the chrony daemon.'
  desc <<~DESC
    Not exposing the management interface of the chrony daemon on the network diminishes the attack space.

    Satisfies: SRG-OS-000096-GPOS-00050, SRG-OS-000095-GPOS-00049
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 disables network management of the chrony daemon with the following command:

    $ sudo grep -w cmdport /etc/chrony.conf
    cmdport 0

    If the "cmdport" option is not set to "0", is commented out, or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable network management of the chrony daemon by adding/modifying the following line in the "/etc/chrony.conf" file:

    cmdport 0

    Restart the chronyd service with the following command for the changes to take effect:

    $ sudo systemctl restart chronyd
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280961'
  tag rid: 'SV-280961r1165238_rule'
  tag stig_id: 'RHEL-10-200543'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-85427r1165237_fix'
  tag cci: ['CCI-000382', 'CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -w cmdport /etc/chrony.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
