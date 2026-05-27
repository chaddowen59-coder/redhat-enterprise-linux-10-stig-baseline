control 'SV-280975' do
  title 'RHEL 10 must have the "opensc" package installed.'
  desc <<~DESC
    The use of Personal Identity Verification (PIV) credentials facilitates standardization and reduces the risk of unauthorized access.

    The DOD has mandated the use of the common access card (CAC) to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.

    Satisfies: SRG-OS-000375-GPOS-00160, SRG-OS-000376-GPOS-00161
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 has the "opensc" package installed with the following command:

    $ sudo dnf list --installed opensc
    Installed Packages
    opensc.x86_64                               0.26.1-1.el10                                @rhel-10-for-x86_64-baseos-rpm

    If the "opensc" package is not installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "opensc" package installed with the following command:

    $ sudo dnf -y install opensc
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280975'
  tag rid: 'SV-280975r1195364_rule'
  tag stig_id: 'RHEL-10-200620'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-85441r1165279_fix'
  tag cci: ['CCI-004046', 'CCI-001953']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('opensc') do
    it { should_not be_installed }
  end
end
