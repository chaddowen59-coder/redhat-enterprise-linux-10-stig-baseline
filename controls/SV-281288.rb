control 'SV-281288' do
  title 'RHEL 10 must be configured to disable USB mass storage.'
  desc <<~DESC
    USB mass storage permits easy introduction of unknown devices, thereby facilitating malicious activity.

    Satisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 disables the ability to load the USB Storage kernel module with the following command:

    $ sudo grep -rs usb-storage /etc/modprobe.conf /etc/modprobe.d/*
    /etc/modprobe.d/usb-storage.conf:install usb-storage /bin/false
    /etc/modprobe.d/usb-storage.conf:blacklist usb-storage

    If the command does not return any output, or either line is commented out, and use of USB Storage is not documented with the information system security officer as an operational requirement, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent the usb-storage kernel module from being loaded.

    Add the following lines to the file "/etc/modprobe.d/usb-storage.conf" (or create "usb-storage.conf" if it does not exist):

    $ sudo vi /etc/modprobe.d/usb-storage.conf

    install usb-storage /bin/false
    blacklist usb-storage
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281288'
  tag rid: 'SV-281288r1166816_rule'
  tag stig_id: 'RHEL-10-700850'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-85754r1166815_fix'
  tag cci: ['CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("grep -rs usb-storage /etc/modprobe.conf /etc/modprobe.d/*") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
