control 'SV-280944' do
  title 'RHEL 10 must not have the "telnet-server" package installed.'
  desc <<~DESC
    It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities are often overlooked and therefore, may remain unsecure. They increase the risk to the platform by providing additional attack vectors.

    The telnet service provides an unencrypted remote access service, which does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log in using this service, the privileged user password could be compromised.

    Removing the "telnet-server" package decreases the risk of accidental (or intentional) activation of the telnet service.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 does not have the "telnet-server" package installed with the following command:

    $ sudo dnf list --installed telnet-server
    Error: No matching Packages to list

    If the "telnet-server" package is installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to not have the "telnet-server" package installed with the following command:

    $ sudo dnf -y remove telnet-server
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-280944'
  tag rid: 'SV-280944r1184749_rule'
  tag stig_id: 'RHEL-10-200020'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85410r1165186_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('telnet-server') do
    it { should_not be_installed }
  end
end
