control 'SV-281362' do
  title 'RHEL 10 must configure a DNS processing mode in Network Manager to avoid conflicts with other Domain Name Server (DNS) managers and to not leak DNS queries to untrusted networks.'
  desc <<~DESC
    To ensure that DNS resolver settings are respected, a DNS mode in Network Manager must be configured. The following are common DNS values in "NetworkManager.conf [main]":

    - default: NetworkManager will update "/etc/resolv.conf" to reflect the nameservers provided by currently active connections.
    - none: NetworkManager will not modify "/etc/resolv.conf". Used when DNS is managed manually or by another service.
    - systemd-resolved: Uses "systemd-resolved" to manage DNS.
    - dnsmasq: Enables the internal "dnsmasq" plugin.

    Satisfies: SRG-OS-000420-GPOS-00186, SRG-OS-000142-GPOS-00091
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 has a DNS mode configured in Network Manager.

    $ NetworkManager --print-config
    [main]
    dns=none

    If the dns key under "main" does not exist or is set to "dnsmasq", this is a finding.

    Note: If RHEL 10 is configured to use a DNS resolver other than Network Manager, the configuration must be documented and approved by the information system security officer.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to use a DNS mode in Network Manager.

    In "/etc/NetworkManager/NetworkManager.conf", add the following line in the "[main]" section:

    dns = none

    Where <dns processing mode> is default, none, or systemd-resolved.

    Network Manager must be reloaded for the change to take effect:

    $ sudo systemctl reload NetworkManager
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281362'
  tag rid: 'SV-281362r1167236_rule'
  tag stig_id: 'RHEL-10-800300'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85828r1167235_fix'
  tag cci: ['CCI-002385', 'CCI-001115']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("NetworkManager --print-config") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
