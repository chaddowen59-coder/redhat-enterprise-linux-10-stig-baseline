control 'SV-281313' do
  title 'RHEL 10 must disable the Stream Control Transmission Protocol (SCTP) kernel module.'
  desc <<~DESC
    It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

    Failing to disconnect unused protocols can result in a system compromise.

    The SCTP is a transport layer protocol, designed to support the idea of message-oriented communication, with several streams of messages within one connection. Disabling SCTP protects the system against exploitation of any flaws in its implementation.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 disables the ability to load the sctp kernel module with the following command:

    $ sudo grep -rs sctp /etc/modprobe.conf /etc/modprobe.d/* | grep -v '#'
    /etc/modprobe.d/sctp-blacklist.conf:install sctp /bin/false
    /etc/modprobe.d/sctp-blacklist.conf:blacklist sctp

    If the command does not return any output, or the lines are commented out, and use of sctp is not documented with the information system security officer as an operational requirement, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable the ability to load the sctp kernel module.

    Create a drop-in if it does not already exist:

    $ sudo vi /etc/modprobe.d/sctp.conf

    Add the following lines to the file:

    install sctp /bin/false
    blacklist sctp
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281313'
  tag rid: 'SV-281313r1184770_rule'
  tag stig_id: 'RHEL-10-701110'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85779r1167088_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe file('/etc/modprobe.d/sctp-blacklist.conf') do
    it { should exist }
    its('content') { should match(/#/i) }
  end
end
