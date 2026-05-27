control 'SV-281342' do
  title 'RHEL 10 must not forward Internet Protocol version 4 (IPv4) source-routed packets.'
  desc <<~DESC
    Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.

    Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It must be disabled unless it is absolutely required.

    Satisfies: SRG-OS-000420-GPOS-00186, SRG-OS-000142-GPOS-00073
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 will not accept IPv4 source-routed packets.

    Check the value of the "net.ipv4.conf.all.accept_source_route" variable with the following command:

    $ sudo sysctl net.ipv4.conf.all.accept_source_route
    net.ipv4.conf.all.accept_source_route = 0

    If "net.ipv4.conf.all.accept_source_route" is not set to "0" or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to ignore IPv4 source-routed packets.

    Create a configuration file if it does not already exist:

    $ sudo vi /etc/sysctl.d/99-ipv4_accept_source.conf

    Add the following line to the file:

    net.ipv4.conf.all.accept_source_route = 0

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281342'
  tag rid: 'SV-281342r1167176_rule'
  tag stig_id: 'RHEL-10-800100'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85808r1167175_fix'
  tag cci: ['CCI-002385', 'CCI-001097']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should cmp 0 }
  end
end
