control 'SV-280987' do
  title 'RHEL 10 must authenticate the remote logging server for off-loading audit logs via "rsyslog".'
  desc <<~DESC
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.

    RHEL 10 installation media provides "rsyslogd", a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (a secure communications library implementing the Secure Sockets Layer (SSL), Transport Layer Security (TLS), and Datagram TLS (DTLS) protocols) creates a method to securely encrypt and off-load auditing.

    The "rsyslog" supported authentication modes include:
    - anon - Anonymous authentication.
    - x509/fingerprint - Certificate fingerprint authentication.
    - x509/certvalid - Certificate validation only.
    - x509/name - Certificate validation and subject name authentication.

    Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 authenticates the remote logging server for off-loading audit logs with the following command:

    $ sudo grep -r -E 'streamdriver.authmode|streamdriver.permittedpeer|tls.authmode|tls.permittedpeer' /etc/rsyslog.conf /etc/rsyslog.d/
    /etc/rsyslog.d/99-forwarding.conf:        streamdriver.authmode="x509/name"

    If the variable name "streamdriver.authmode" is present in an omfwd statement block, this is not a finding. However, if the "streamdriver.authmode" variable is in a module block, this is a finding.

    If the value of the "$ActionSendStreamDriverAuthMode" or "streamdriver.authmode" or "tls.authmode" option is not set to "x509/name", or the line is commented out, ask the system administrator to indicate how the audit logs are off-loaded to a different system or media.

    Additionally, if the permittedpeer is not specified in either of the following formats, this is a finding:
    streamdriver.permittedpeer="rsyslog.server.example.com"
    tls.permittedpeer="rsyslog.server.example.com"

    If there is no evidence that the transfer of the audit logs being off-loaded to another system or media is encrypted, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to authenticate the remote logging server for off-loading audit logs by setting the following options in "/etc/rsyslog.d/99-forwarding.conf":

    streamdriver.authmode="x509/name"

    Specify the logserver to prevent man-in-the-middle attacks in the following format:
    streamdriver.permittedpeer="rsyslog.server.example.com"
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280987'
  tag rid: 'SV-280987r1195371_rule'
  tag stig_id: 'RHEL-10-200644'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-85453r1195370_fix'
  tag cci: ['CCI-001851']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/rsyslog.conf') do
    it { should exist }
    its('content') { should match(/streamdriver.authmode|streamdriver.permittedpeer|tls.authmode|tls.permittedpeer/i) }
  end
end
