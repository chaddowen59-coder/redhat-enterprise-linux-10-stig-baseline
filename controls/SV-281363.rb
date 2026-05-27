control 'SV-281363' do
  title 'RHEL 10 must be configured to operate in secure mode if the Trivial File Transfer Protocol (TFTP) server service is required.'
  desc <<~DESC
    Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If a TFTP server is not installed, this rule is not applicable.

    Verify RHEL 10 is configured to operate in secure mode if the TFTP server service is required.

    Determine if the TFTP server is installed with the following command:

    $ sudo dnf list installed | grep tftp-server
    tftp-server.x86_64                                   5.2-48.el10                     @rhel-10-for-x86_64-appstream-rpms

    Verify that the TFTP daemon, if "tftp.server" is installed, is configured to operate in secure mode with the following command:

    $ systemctl cat tftp.service | grep -i execstart
    ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot

    Note: The "-s" option ensures that the TFTP server serves only files from the specified directory, which is a security measure to prevent unauthorized access to other parts of the file system.

    If the TFTP server is installed, but the TFTP daemon is not configured to operate in secure mode, and tftp is not documented as critical to the mission with the information system security officer, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 TFTP to operate in secure mode with the following command:

    $ sudo systemctl edit tftp.service

    In the editor, enter the following:

    [Service]
    ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot

    After making changes, reload the systemd daemon and restart the TFTP service as follows:

    $ sudo systemctl daemon-reload
    $ sudo systemctl restart tftp.service
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281363'
  tag rid: 'SV-281363r1195454_rule'
  tag stig_id: 'RHEL-10-800310'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-85829r1167238_fix'
  tag cci: ['CCI-000197']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("dnf list installed | grep tftp-server") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
