control 'SV-280990' do
  title 'RHEL 10 must monitor all remote access methods.'
  desc <<~DESC
    Logging remote access methods can be used to trace the decrease in the risks associated with remote user access management. It can also be used to spot cyberattacks and ensure ongoing compliance with organizational policies surrounding the use of remote access methods.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 monitors all remote access methods with the following command:

    $ sudo grep -rE '(auth.\*|authpriv.\*|daemon.\*)' /etc/rsyslog.conf /etc/rsyslog.d/
    /etc/rsyslog.conf:authpriv.*                                              /var/log/secure

    If "auth.*", "authpriv.*", or "daemon.*" are not configured to be logged, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to monitor all remote access methods.

    Add or update the following lines to the "/etc/rsyslog.conf" file or a file in "/etc/rsyslog.d":

    auth.*;authpriv.*;daemon.* /var/log/secure

    Restart the "rsyslog" service with the following command for the changes to take effect:

    $ sudo systemctl restart rsyslog.service
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280990'
  tag rid: 'SV-280990r1165325_rule'
  tag stig_id: 'RHEL-10-200647'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-85456r1165324_fix'
  tag cci: ['CCI-000067']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/rsyslog.conf') do
    it { should exist }
    its('content') { should match(/(auth.\\*|authpriv.\\*|daemon.\\*)/i) }
  end
end
