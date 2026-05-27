control 'SV-280992' do
  title 'RHEL 10 must have the packages required for encrypting off-loaded audit logs installed.'
  desc <<~DESC
    The "rsyslog-gnutls" package provides Transport Layer Security (TLS) support for the rsyslog daemon, which enables secure remote logging.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 has the "rsyslog-gnutls" package installed with the following command:

    $ sudo dnf list --installed rsyslog-gnutls
    Installed Packages
    rsyslog-gnutls.x86_64                                     8.2412.0-1.el10                                     @AppStream

    If the "rsyslog-gnutls" package is not installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "rsyslog-gnutls" package installed with the following command:

    $ sudo dnf -y install rsyslog-gnutls
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280992'
  tag rid: 'SV-280992r1195379_rule'
  tag stig_id: 'RHEL-10-200650'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-85458r1165330_fix'
  tag cci: ['CCI-000803']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('rsyslog-gnutls') do
    it { should_not be_installed }
  end
end
