control 'SV-281350' do
  title 'RHEL 10 must limit the number of bogus Internet Control Message Protocol (ICMP) response errors logs.'
  desc <<~DESC
    Some routers will send responses to broadcast frames that violate RFC-1122, which fills up a log file system with many useless error messages. An attacker may take advantage of this and attempt to flood the logs with bogus error logs. Ignoring bogus ICMP error responses reduces log size, although some activity would not be logged.

    Satisfies: SRG-OS-000420-GPOS-00186, SRG-OS-000142-GPOS-00081
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 limits the number of bogus ICMP response errors logs.

    Check the value of the "net.ipv4.icmp_ignore_bogus_error_response" variables with the following command:

    $ sudo sysctl net.ipv4.icmp_ignore_bogus_error_responses
    net.ipv4.icmp_ignore_bogus_error_responses = 1

    If "net.ipv4.icmp_ignore_bogus_error_response" is not set to "1" or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to not log bogus ICMP errors.

    Create a configuration file if it does not already exist:

    $ sudo vi /etc/sysctl.d/ipv4_icmp_ignore_bogus_error_responses.conf

    Add the following line to the file:

    net.ipv4.icmp_ignore_bogus_error_responses = 1

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281350'
  tag rid: 'SV-281350r1167200_rule'
  tag stig_id: 'RHEL-10-800180'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85816r1167199_fix'
  tag cci: ['CCI-002385', 'CCI-001105']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe kernel_parameter('net.ipv4.icmp_ignore_bogus_error_responses') do
    its('value') { should cmp 1 }
  end
end
