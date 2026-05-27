control 'SV-281001' do
  title 'RHEL 10 must have a Secure Shell (SSH) server installed for all networked systems.'
  desc <<~DESC
    Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and read or altered.

    This requirement applies to internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

    Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa.

    Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188, SRG-OS-000425-GPOS-00189, SRG-OS-000426-GPOS-00190
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 has the "openssh-server" package installed with the following command:

    $ sudo dnf list --installed openssh-server
    Installed Packages
    openssh-server.x86_64                                      9.9p1-7.el10_0                                      @anaconda

    If the "openssh-server" package is not installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "openssh-server" package installed with the following command:

    $ sudo dnf -y install openssh-server
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281001'
  tag rid: 'SV-281001r1195391_rule'
  tag stig_id: 'RHEL-10-200720'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-85467r1165357_fix'
  tag cci: ['CCI-002418', 'CCI-002421', 'CCI-002420', 'CCI-002422']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('openssh-server') do
    it { should_not be_installed }
  end
end
