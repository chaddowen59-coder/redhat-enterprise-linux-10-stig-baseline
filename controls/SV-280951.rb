control 'SV-280951' do
  title 'RHEL 10 must not have a File Transfer Protocol (FTP) server package installed.'
  desc <<~DESC
    The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log in using this service, the privileged user password could be compromised. Secure Shell (SSH) or other encrypted file transfer methods must be used in place of this service.

    Removing the "vsftpd" package decreases the risk of accidental activation.

    Satisfies: SRG-OS-000074-GPOS-00042, SRG-OS-000095-GPOS-00049
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 does not have an FTP server package installed with the following command:

    $ sudo dnf list --installed vsftp
    Error: No matching Packages to list

    If the "vsftp" package is installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to not have the FTP package installed with the following command (using "vsftpd" as an example):

    $ sudo dnf -y remove vsftpd
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-280951'
  tag rid: 'SV-280951r1184744_rule'
  tag stig_id: 'RHEL-10-200090'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-85417r1165207_fix'
  tag cci: ['CCI-000197', 'CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('vsftp') do
    it { should_not be_installed }
  end
end
