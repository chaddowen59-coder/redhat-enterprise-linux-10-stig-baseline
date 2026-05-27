control 'SV-281359' do
  title 'RHEL 10 must prevent Internet Protocol version 6 (IPv6) Internet Control Message Protocol (ICMP) redirect messages from being accepted.'
  desc <<~DESC
    ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.

    Satisfies: SRG-OS-000420-GPOS-00186, SRG-OS-000142-GPOS-00090
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If IPv6 is disabled on the system, this requirement is not applicable.

    Verify RHEL 10 prevents IPv6 ICMP redirect messages from being accepted.

    Check the value of the "net.ipv6.conf.default.accept_redirects" variables with the following command:

    $ sudo sysctl net.ipv6.conf.default.accept_redirects
    net.ipv6.conf.default.accept_redirects = 0

    If "net.ipv6.conf.default.accept_redirects" is not set to "0" or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent IPv6 ICMP redirect messages from being accepted.

    Create a configuration file if it does not already exist:

    $ sudo vi /etc/sysctl.d/ipv6_accept_redirects.conf

    Add the following line to the file:

    net.ipv6.conf.default.accept_redirects = 0

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281359'
  tag rid: 'SV-281359r1167227_rule'
  tag stig_id: 'RHEL-10-800270'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85825r1167226_fix'
  tag cci: ['CCI-002385', 'CCI-001114']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe kernel_parameter('net.ipv6.conf.default.accept_redirects') do
    its('value') { should cmp 0 }
  end
end
