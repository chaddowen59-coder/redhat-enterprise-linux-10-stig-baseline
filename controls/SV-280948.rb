control 'SV-280948' do
  title 'RHEL 10 must not have the unbound package installed.'
  desc <<~DESC
    If the system is not a Domain Name Server (DNS), it should not have a DNS server package installed to decrease the attack surface of the system.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 does not have a DNS package installed with the following command:

    $ sudo dnf list --installed unbound
    Error: No matching Packages to list

    If the "unbound" package is installed, and the information system security officer lacks a documented requirement for a DNS, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to not have the unbound package installed with the following command:

    $ sudo dnf -y remove unbound
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280948'
  tag rid: 'SV-280948r1197218_rule'
  tag stig_id: 'RHEL-10-200060'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85414r1165198_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('unbound') do
    it { should_not be_installed }
  end
end
