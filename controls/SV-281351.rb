control 'SV-281351' do
  title 'RHEL 10 must not send Internet Control Message Protocol (ICMP) redirects.'
  desc <<~DESC
    ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology.

    The ability to send ICMP redirects is only appropriate for systems acting as routers.

    Satisfies: SRG-OS-000420-GPOS-00186, SRG-OS-000142-GPOS-00082
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 does not send IPv4 ICMP redirect messages.

    Check the value of the "net.ipv4.conf.all.send_redirects" variables with the following command:

    $ sudo sysctl net.ipv4.conf.all.send_redirects
    net.ipv4.conf.all.send_redirects = 0

    If "net.ipv4.conf.all.send_redirects" is not set to "0" and is not documented with the information system security officer as an operational requirement or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to not send IPv4 ICMP redirect messages.

    Create a configuration file if it does not already exist:

    $ sudo vi /etc/sysctl.d/ipv4_send_redirects.conf

    Add the following line to the file:

    net.ipv4.conf.all.send_redirects = 0

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281351'
  tag rid: 'SV-281351r1184698_rule'
  tag stig_id: 'RHEL-10-800190'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85817r1184697_fix'
  tag cci: ['CCI-002385', 'CCI-001106']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should cmp 0 }
  end
end
