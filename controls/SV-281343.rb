control 'SV-281343' do
  title 'RHEL 10 must log Internet Protocol version 4 (IPv4) packets with impossible addresses.'
  desc <<~DESC
    The presence of "martian" packets (which have impossible addresses), as well as spoofed packets, source-routed packets, and redirects, could be a sign of nefarious network activity. Logging these packets enables this activity to be detected.

    Satisfies: SRG-OS-000420-GPOS-00186, SRG-OS-000142-GPOS-00074
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 logs IPv4 martian packets.

    Check the value of the "net.ipv4.conf.all.log_martians" variable with the following command:

    $ sudo sysctl net.ipv4.conf.all.log_martians
    net.ipv4.conf.all.log_martians = 1

    If "net.ipv4.conf.all.log_martians" is not set to "1" or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to log martian packets on IPv4 interfaces.

    Create a configuration file if it does not already exist:

    $ sudo vi /etc/sysctl.d/99-ipv4_log_martians.conf

    Add the following line to the file:

    net.ipv4.conf.all.log_martians=1

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281343'
  tag rid: 'SV-281343r1167179_rule'
  tag stig_id: 'RHEL-10-800110'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85809r1167178_fix'
  tag cci: ['CCI-002385', 'CCI-001098']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe kernel_parameter('net.ipv4.conf.all.log_martians') do
    its('value') { should cmp 1 }
  end
end
