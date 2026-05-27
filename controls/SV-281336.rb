control 'SV-281336' do
  title 'RHEL 10 must securely compare internal information system clocks at least every 24 hours.'
  desc <<~DESC
    Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

    Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

    Depending on the infrastructure being used, the "pool" directive may not be supported.

    Authoritative time sources include the United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DOD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).

    Satisfies: SRG-OS-000355-GPOS-00143, SRG-OS-000356-GPOS-00144, SRG-OS-000359-GPOS-00146, SRG-OS-000785-GPOS-00250
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is securely comparing internal information system clocks at least every 24 hours with an NTP server with the following commands:

    $ sudo grep maxpoll /etc/chrony.conf
    server 0.us.pool.ntp.mil iburst maxpoll 16

    If the "maxpoll" option is set to a number greater than 16, or the line is missing or commented out, this is a finding.

    Verify the "chrony.conf" file is configured to an authoritative DOD time source by running the following command:

    $ sudo grep -i server /etc/chrony.conf
    server 0.us.pool.ntp.mil

    If the parameter "server" is not set or is not set to an authoritative DOD time source, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to securely compare internal information system clocks at least every 24 hours with an NTP server by adding/modifying the following line in the "/etc/chrony.conf" file:

    server [ntp.server.name] iburst maxpoll 16
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281336'
  tag rid: 'SV-281336r1167158_rule'
  tag stig_id: 'RHEL-10-800040'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-85802r1167157_fix'
  tag cci: ['CCI-004923', 'CCI-004926', 'CCI-001890', 'CCI-004922']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep maxpoll /etc/chrony.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
