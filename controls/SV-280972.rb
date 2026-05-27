control 'SV-280972' do
  title 'RHEL 10 must have the "pcsc-lite" package installed.'
  desc <<~DESC
    The "pcsc-lite" package must be installed if it is to be available for multifactor authentication using smart cards.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If the system administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

    Verify RHEL 10 has the "pcsc-lite" package installed with the following command:

    $ sudo dnf list --installed pcsc-lite
    Installed Packages
    pcsc-lite.x86_64                                         2.2.3-2.el10                                          @anaconda

    If the "pcsc-lite" package is not installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "pcsc-lite" package installed with the following command:

    $ sudo dnf -y install pcsc-lite
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280972'
  tag rid: 'SV-280972r1195360_rule'
  tag stig_id: 'RHEL-10-200610'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-85438r1165270_fix'
  tag cci: ['CCI-004046']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('pcsc-lite') do
    it { should_not be_installed }
  end
end
