control 'SV-280988' do
  title 'RHEL 10 must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited via rsyslog.'
  desc <<~DESC
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.

    RHEL 10 installation media provides "rsyslogd", a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (a secure communications library implementing the Secure Sockets Layer [SSL], Transport Layer Security [TLS], and Datagram TLS [DTLS] protocols) creates a method to securely encrypt and off-load auditing. When this utility is coupled with the omfwd module, it can use the ossl network stream driver, which leverages the OpenSSL library for Transport Layer Security (TLS) to securely encrypt and off-load auditing.

    "Rsyslog" supported authentication modes include:
    - anon - Anonymous authentication.
    - x509/fingerprint - Certificate fingerprint authentication.
    - x509/certvalid - Certificate validation only.
    - x509/name - Certificate validation and subject name authentication.

    Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 encrypts audit records offloaded onto a different system via rsyslog using the modern "omfwd" action.

    Search for active TLS-enabling configurations within "omfwd" action blocks with the following command:

    $ sudo grep -rE 'tls="on"|StreamDriver.Mode\s*=\s*"1"' /etc/rsyslog.conf /etc/rsyslog.d/

    If an active TCP-based "omfwd" forwarding rule exists on the system but the command above returns no active configuration lines, or if all results are commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to encrypt off-loaded audit records via rsyslog by enabling TLS within the "omfwd" action rule.

    Edit the configuration file containing the "omfwd" rule (e.g., /etc/rsyslog.d/99-forwarding.conf) and add the tls="on" parameter.

    Example:
    action(
      type="omfwd"
      target="logserver.example.com"
      protocol="tcp"
      port="6514"
      tls="on"
    )

    After applying the configuration, restart the rsyslog service:
    $ sudo systemctl restart rsyslog
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280988'
  tag rid: 'SV-280988r1195374_rule'
  tag stig_id: 'RHEL-10-200645'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-85454r1195373_fix'
  tag cci: ['CCI-001851']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/rsyslog.conf') do
    it { should exist }
    its('content') { should match(/tls=/i) }
  end
end
