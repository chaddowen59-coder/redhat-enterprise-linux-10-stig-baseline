control 'SV-280963' do
  title 'RHEL 10 must have the USBGuard package enabled.'
  desc <<~DESC
    The USBGuard-daemon is the main component of the USBGuard software framework. It runs as a service in the background and enforces the USB device authorization policy for all USB devices. The policy is defined by a set of rules using a rule language described in the "usbguard-rules.conf" file. The policy and the authorization state of USB devices can be modified during runtime using the USBGuard tool.

    The system administrator (SA) must work with the site information system security officer (ISSO) to determine a list of authorized peripherals and establish rules within the USBGuard software framework to allow only authorized devices.

    Satisfies: SRG-OS-000378-GPOS-00163, SRG-OS-000690-GPOS-00140
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If the system is virtual machine with no virtual or physical USB peripherals attached, this is not applicable.

    Verify RHEL 10 has USBGuard enabled with the following command:

    $ systemctl is-active usbguard
    active

    If USBGuard is not active, ask the SA to indicate how unauthorized peripherals are being blocked.

    If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the USBGuard service enabled by running the following command:

    $ sudo systemctl enable --now usbguard
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280963'
  tag rid: 'SV-280963r1165244_rule'
  tag stig_id: 'RHEL-10-200561'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-85429r1165243_fix'
  tag cci: ['CCI-001958', 'CCI-003959']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe service('usbguard') do
    it { should be_enabled }
    it { should be_running }
  end
end
