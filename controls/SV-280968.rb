control 'SV-280968' do
  title 'RHEL 10 must have the "sudo" package installed.'
  desc <<~DESC
    The "sudo" package is a program designed to allow a system administrator to give limited root privileges to users and log root activity. The basic philosophy is to give as few privileges as possible but still allow system users to complete their work.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 has the "sudo" package installed with the following command:

    $ sudo dnf list --installed sudo
    Installed Packages
    sudo.x86_64                             1.9.15-8.p5.el10_0.2                             @rhel-10-for-x86_64-baseos-rpms

    If the "sudo" package is not installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "sudo" package installed with the following command:

    $ sudo dnf -y install sudo
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280968'
  tag rid: 'SV-280968r1195356_rule'
  tag stig_id: 'RHEL-10-200590'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-85434r1165258_fix'
  tag cci: ['CCI-002235']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('sudo') do
    it { should_not be_installed }
  end
end
