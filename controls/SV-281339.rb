control 'SV-281339' do
  title 'RHEL 10 must not have unauthorized IP tunnels configured.'
  desc <<~DESC
    IP tunneling mechanisms can be used to bypass network filtering. If tunneling is required, it must be documented with the information system security officer (ISSO).
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 does not have unauthorized IP tunnels configured.

    Determine if the IPsec service is active with the following command:

    $ systemctl is-active ipsec
    Inactive

    If the IPsec service is active, check for configured IPsec connections ("conn"), with the following command:

    $ sudo grep -rni conn /etc/ipsec.conf /etc/ipsec.d/

    Verify any returned results are documented with the ISSO.

    If the IPsec tunnels are active and not approved, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to not have unauthorized IP tunnels configured.

    Remove all unapproved tunnels from the system, or document them with the ISSO.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281339'
  tag rid: 'SV-281339r1167167_rule'
  tag stig_id: 'RHEL-10-800070'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85805r1167166_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("systemctl is-active ipsec") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
