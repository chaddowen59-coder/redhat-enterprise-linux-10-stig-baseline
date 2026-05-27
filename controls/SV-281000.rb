control 'SV-281000' do
  title 'RHEL 10 must have the "cronie" package installed.'
  desc <<~DESC
    The "cronie" package must be installed if it is to be available for multifactor authentication using smart cards.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 has the "cronie" package installed with the following command:

    $ sudo dnf list --installed cronie
    Installed Packages
    cronie.x86_64                                           1.7.0-9.el10                                           @anaconda

    If the "cronie" package is not installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "cronie" package installed with the following command:

    $ sudo dnf -y install cronie
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281000'
  tag rid: 'SV-281000r1195389_rule'
  tag stig_id: 'RHEL-10-200700'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85466r1165354_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('cronie') do
    it { should_not be_installed }
  end
end
