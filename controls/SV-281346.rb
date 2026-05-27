control 'SV-281346' do
  title 'RHEL 10 must prevent Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages from being accepted.'
  desc <<~DESC
    ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.

    This feature of the IPv4 protocol has few legitimate uses. It must be disabled unless absolutely required.

    Satisfies: SRG-OS-000420-GPOS-00186, SRG-OS-000142-GPOS-00077
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 will not accept IPv4 ICMP redirect messages.

    Check the value of the default "net.ipv4.conf.default.accept_redirects" variable with the following command:

    $ sudo sysctl net.ipv4.conf.default.accept_redirects
    net.ipv4.conf.default.accept_redirects = 0

    If "net.ipv4.conf.default.accept_redirects" is not set to "0" or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent IPv4 ICMP redirect messages from being accepted.

    Create a configuration file if it does not already exist:

    $ sudo vi /etc/sysctl.d/99-ipv4_accept_redirects.conf

    Add the following line to the file:

    net.ipv4.conf.default.accept_redirects = 0

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281346'
  tag rid: 'SV-281346r1197251_rule'
  tag stig_id: 'RHEL-10-800140'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85812r1197250_fix'
  tag cci: ['CCI-002385', 'CCI-001101']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe kernel_parameter('net.ipv4.conf.default.accept_redirects') do
    its('value') { should cmp 0 }
  end
end
