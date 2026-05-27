control 'SV-281349' do
  title 'RHEL 10 must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc <<~DESC
    Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.

    Ignoring ICMP echo requests (pings) sent to broadcast or multicast addresses makes the system slightly more difficult to enumerate on the network.

    Satisfies: SRG-OS-000420-GPOS-00186, SRG-OS-000142-GPOS-00080
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 ignores ICMP echoes sent to a broadcast address.

    Check the value of the "net.ipv4.icmp_echo_ignore_broadcasts" variable with the following command:

    $ sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts
    net.ipv4.icmp_echo_ignore_broadcasts = 1

    If "net.ipv4.icmp_echo_ignore_broadcasts" is not set to "1" or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to ignore Internet Protocol version 4 (IPv4) ICMP echoes sent to a broadcast address.

    Create a configuration file if it does not already exist:

    $ sudo vi /etc/sysctl.d/ipv4_icmp_echo_ignore_broadcasts.conf

    Add the following line to the file:

    net.ipv4.icmp_echo_ignore_broadcasts = 1

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281349'
  tag rid: 'SV-281349r1167197_rule'
  tag stig_id: 'RHEL-10-800170'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85815r1167196_fix'
  tag cci: ['CCI-002385', 'CCI-001104']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should cmp 1 }
  end
end
