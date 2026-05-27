control 'SV-280974' do
  title 'RHEL 10 must have the "pcsc-lite-ccid" package installed.'
  desc <<~DESC
    The "pcsc-lite-ccid" package must be installed if it is to be available for multifactor authentication using smart cards.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 has the "pcsc-lite-ccid" package installed with the following command:

    $ sudo dnf list --installed pcsc-lite-ccid
    Installed Packages
    pcsc-lite-ccid.x86_64                                       1.6.0-2.el10                                       @anaconda

    If the "pcsc-lite-ccid" package is not installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "pcsc-lite-ccid" package installed with the following command:

    $ sudo dnf -y install pcsc-lite-ccid
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280974'
  tag rid: 'SV-280974r1195362_rule'
  tag stig_id: 'RHEL-10-200612'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-85440r1165276_fix'
  tag cci: ['CCI-004046']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('pcsc-lite-ccid') do
    it { should_not be_installed }
  end
end
