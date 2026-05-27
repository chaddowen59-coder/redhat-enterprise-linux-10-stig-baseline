control 'SV-281329' do
  title 'RHEL 10 must, for PKI-based authentication, validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc <<~DESC
    Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

    A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and Domain Name System Security Extensions (DNSSEC).

    When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a certification authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

    This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.

    Satisfies: SRG-OS-000066-GPOS-00034, SRG-OS-000384-GPOS-00167, SRG-OS-000775-GPOS-00230, SRG-OS-000780-GPOS-00240
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If the system administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

    Verify RHEL 10, for PKI-based authentication, has valid certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

    Check that the system has a valid DOD root CA installed with the following command:

    $ sudo openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem
    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 1 (0x1)
            Signature Algorithm: sha256WithRSAEncryption
            Issuer: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3
            Validity
            Not Before: Mar 20 18:46:41 2012 GMT
            Not After: Dec 30 18:46:41 2029 GMT
            Subject: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3
            Subject Public Key Info:
                Public Key Algorithm: rsaEncryption

    If the root CA file is not a DOD-issued certificate with a valid date and installed in the "/etc/sssd/pki/sssd_auth_ca_db.pem" location, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10, for PKI-based authentication, to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

    Obtain a valid copy of the DOD root CA file from the PKI CA certificate bundle from cyber.mil and copy the DoD_PKE_CA_chain.pem into the following file:

    /etc/sssd/pki/sssd_auth_ca_db.pem
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281329'
  tag rid: 'SV-281329r1195452_rule'
  tag stig_id: 'RHEL-10-701270'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-85795r1167136_fix'
  tag cci: ['CCI-000185', 'CCI-004068', 'CCI-004909', 'CCI-004910']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
