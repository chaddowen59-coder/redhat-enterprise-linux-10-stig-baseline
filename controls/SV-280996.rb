control 'SV-280996' do
  title 'RHEL 10 must have the "libreswan" package installed.'
  desc <<~DESC
    Providing the ability for remote users or systems to initiate a secure virtual private network connection protects information when it is transmitted over a wide area network.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If there is no operational need for Libreswan to be installed, this rule is not applicable.

    Verify RHEL 10 has the "libreswan" service package installed with the following command:

    $ sudo dnf list --installed libreswan
    Installed Packages
    libreswan.x86_64                                         5.2-1.el10_0                                         @AppStream

    If the "libreswan" package is not installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "libreswan" service package installed with the following command:

    $ sudo dnf -y install libreswan
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280996'
  tag rid: 'SV-280996r1195385_rule'
  tag stig_id: 'RHEL-10-200680'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-85462r1165342_fix'
  tag cci: ['CCI-000803']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('libreswan') do
    it { should_not be_installed }
  end
end
