control 'SV-281290' do
  title 'RHEL 10 must disable wireless network adapters.'
  desc <<~DESC
    This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with RHEL 10 systems. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR keyboards, mice and pointing devices, and near field communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. 

    Wireless peripherals must meet DOD requirements for wireless data transmission and be approved for use by the authorizing official. Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that must be protected, modification of communications with these wireless peripherals may be used to compromise the RHEL 10 operating system.

    Satisfies: SRG-OS-000299-GPOS-00117, SRG-OS-000300-GPOS-00118, SRG-OS-000424-GPOS-00188, SRG-OS-000481-GPOS-00481
  DESC
  desc 'check', <<~CHECKTEXT
    Note: This requirement is not applicable for systems that do not have physical wireless network radios.

    Verify RHEL 10 disables wireless interfaces on the system with the following command:

    $ nmcli device status
    DEVICE                    TYPE            STATE                    CONNECTION
    virbr0                      bridge         connected             virbr0
    wlp7s0                    wifi              connected            wifiSSID
    enp6s0                    ethernet     disconnected        --
    p2p-dev-wlp7s0     wifi-p2p     disconnected        --
    lo                             loopback    unmanaged           --
    virbr0-nic                tun              unmanaged          --

    If a wireless interface is configured and has not been documented and approved by the information system security officer, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable all wireless network interfaces with the following command:

    $ nmcli radio all off
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281290'
  tag rid: 'SV-281290r1166822_rule'
  tag stig_id: 'RHEL-10-700870'
  tag gtitle: 'SRG-OS-000299-GPOS-00117'
  tag fix_id: 'F-85756r1166821_fix'
  tag cci: ['CCI-001444', 'CCI-001443', 'CCI-002421', 'CCI-002418']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("nmcli device status") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
