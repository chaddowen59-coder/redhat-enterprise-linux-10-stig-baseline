control 'SV-280960' do
  title 'RHEL 10 must disable the chrony daemon from acting as a server.'
  desc <<~DESC
    Minimizing the exposure of the server functionality of the chrony daemon diminishes the attack surface.

    Satisfies: SRG-OS-000096-GPOS-00050, SRG-OS-000095-GPOS-00049
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 disables the chrony daemon from acting as a server with the following command:

    $ sudo grep -w port /etc/chrony.conf
    port 0

    If the "port" option is not set to "0", is commented out, or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable the chrony daemon from acting as a server by adding/modifying the following line in the "/etc/chrony.conf" file:

    port 0

    Restart the chronyd service with the following command for the changes to take effect:

    $ sudo systemctl restart chronyd
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280960'
  tag rid: 'SV-280960r1165235_rule'
  tag stig_id: 'RHEL-10-200542'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-85426r1165234_fix'
  tag cci: ['CCI-000382', 'CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -w port /etc/chrony.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
