control 'SV-280983' do
  title 'RHEL 10 must have the "rsyslog" package installed.'
  desc <<~DESC
    The "rsyslogd" is a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support local and remote logging. Couple this utility with "gnutls" (which is a secure communications library implementing the Secure Sockets Layer [SSL], Transport Layer Security [TLS], and Datagram TLS [DTLS] protocols), to create a method to securely encrypt and off-load auditing.

    Satisfies: SRG-OS-000479-GPOS-00224, SRG-OS-000051-GPOS-00024
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 has the "rsyslogd" package installed with the following command:

    $ sudo dnf list --installed rsyslog
    Installed Packages
    rsyslog.x86_64                                        8.2412.0-1.el10                                         @AppStream

    If the "rsyslogd" package is not installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "rsyslogd" package installed with the following command:

    $ sudo dnf -y install rsyslogd
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280983'
  tag rid: 'SV-280983r1195368_rule'
  tag stig_id: 'RHEL-10-200640'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-85449r1165303_fix'
  tag cci: ['CCI-001851', 'CCI-000154']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('rsyslog') do
    it { should_not be_installed }
  end
end
