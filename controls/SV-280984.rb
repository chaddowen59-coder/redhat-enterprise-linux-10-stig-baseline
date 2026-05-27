control 'SV-280984' do
  title 'RHEL 10 must have the rsyslog service set to active.'
  desc <<~DESC
    The rsyslog service must be running to provide logging services, which are essential to system administration.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 rsyslog is active with the following command:

    $ systemctl is-active rsyslog
    active

    If the rsyslog service is not active, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enable the rsyslog service with the following command:

    $ sudo systemctl enable --now rsyslog
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280984'
  tag rid: 'SV-280984r1165307_rule'
  tag stig_id: 'RHEL-10-200641'
  tag gtitle: 'SRG-OS-000040-GPOS-00018'
  tag fix_id: 'F-85450r1165306_fix'
  tag cci: ['CCI-000133']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe service('rsyslog') do
    it { should be_enabled }
    it { should be_running }
  end
end
