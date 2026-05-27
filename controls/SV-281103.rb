control 'SV-281103' do
  title 'RHEL 10 must take appropriate action when a critical audit processing failure occurs.'
  desc <<~DESC
    It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

    Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify the RHEL 10 audit service is configured to panic on a critical error with the following command:

    $ sudo grep "\-f" /etc/audit/audit.rules
    -f 2

    If the value for "-f" is not "2", and availability is not documented as an overriding concern, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to shut down when auditing failures occur.

    Add the following line to the bottom of the "/etc/audit/rules.d/audit.rules" file:

    -f 2
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281103'
  tag rid: 'SV-281103r1166261_rule'
  tag stig_id: 'RHEL-10-500035'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-85569r1166260_fix'
  tag cci: ['CCI-000139']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/audit/audit.rules') do
    it { should exist }
    its('content') { should match(/\\-f/i) }
  end
end
