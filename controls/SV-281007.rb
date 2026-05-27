control 'SV-281007' do
  title 'RHEL 10 must have the "crypto-policies" package installed.'
  desc <<~DESC
    Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.

    Satisfies: SRG-OS-000396-GPOS-00176, SRG-OS-000393-GPOS-00173, SRG-OS-000394-GPOS-00174
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 has the "crypto-policies" package installed with the following command:

    $ sudo dnf list --installed crypto-policies
    Installed Packages
    crypto-policies.noarch                  20250214-1.gitfd9b9b9.el10_0.1                   @rhel-10-for-x86_64-baseos-rpms

    If the "crypto-policies" package is not installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "crypto-policies" package installed with the following command:

    $ sudo dnf -y install crypto-policies
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-281007'
  tag rid: 'SV-281007r1195399_rule'
  tag stig_id: 'RHEL-10-300000'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-85473r1165375_fix'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('crypto-policies') do
    it { should_not be_installed }
  end
end
