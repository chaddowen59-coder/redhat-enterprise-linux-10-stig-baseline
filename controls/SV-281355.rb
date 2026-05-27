control 'SV-281355' do
  title 'RHEL 10 must ignore IPv6 Internet Control Message Protocol (ICMP) redirect messages.'
  desc <<~DESC
    An illicit ICMP redirect message could result in a man-in-the-middle attack.

    Satisfies: SRG-OS-000420-GPOS-00186, SRG-OS-000142-GPOS-00086
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If IPv6 is disabled on the system, this requirement is not applicable.

    Verify RHEL 10 ignores IPv6 ICMP redirect messages.

    Check the value of the "net.ipv6.conf.all.accept_redirects" variable with the following command:

    $ sysctl net.ipv6.conf.all.accept_redirects
    net.ipv6.conf.all.accept_redirects = 0

    If "net.ipv6.conf.all.accept_redirects" is not set to "0" or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to ignore Internet Protocol version 6 (IPv6) ICMP redirect messages.

    Create a configuration file if it does not already exist:

    $ sudo vi /etc/sysctl.d/ipv6_accept_redirects.conf

    Add the following line to the file:

    net.ipv6.conf.all.accept_redirects = 0

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281355'
  tag rid: 'SV-281355r1167215_rule'
  tag stig_id: 'RHEL-10-800230'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85821r1167214_fix'
  tag cci: ['CCI-002385', 'CCI-001110']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("sysctl net.ipv6.conf.all.accept_redirects") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
