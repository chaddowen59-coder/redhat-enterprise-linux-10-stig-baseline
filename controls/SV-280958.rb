control 'SV-280958' do
  title 'RHEL 10 must have the "chrony" package installed.'
  desc <<~DESC
    Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 has the "chrony" package installed with the following command:

    $ sudo dnf list --installed chrony
    Installed Packages
    chrony.x86_64                                           4.6.1-1.el10                                           @anaconda

    If the "chrony" package is not installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "chrony" package installed with the following command:

    $ sudo dnf -y install chrony
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280958'
  tag rid: 'SV-280958r1195348_rule'
  tag stig_id: 'RHEL-10-200540'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-85424r1165228_fix'
  tag cci: ['CCI-004923']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('chrony') do
    it { should_not be_installed }
  end
end
