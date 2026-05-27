control 'SV-281341' do
  title 'RHEL 10 must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.'
  desc <<~DESC
    ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.

    This feature of the IPv4 protocol has few legitimate uses. It should be disabled unless absolutely required.

    Satisfies: SRG-OS-000420-GPOS-00186, SRG-OS-000142-GPOS-00072
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 will not accept IPv4 ICMP redirect messages.

    Check the value of all "net.ipv4.conf.all.accept_redirects" variables with the following command:

    $ sudo sysctl net.ipv4.conf.all.accept_redirects
    net.ipv4.conf.all.accept_redirects = 0

    If "net.ipv4.conf.all.accept_redirects" is not set to "0" or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to ignore IPv4 ICMP redirect messages.

    Create a configuration file if it does not already exist:

    $ sudo vi /etc/sysctl.d/99-ipv4_accept_redirects.conf

    Add the following line to the file:

    net.ipv4.conf.all.accept_redirects = 0

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281341'
  tag rid: 'SV-281341r1167173_rule'
  tag stig_id: 'RHEL-10-800090'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85807r1167172_fix'
  tag cci: ['CCI-002385', 'CCI-001096']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
    its('value') { should cmp 0 }
  end
end
