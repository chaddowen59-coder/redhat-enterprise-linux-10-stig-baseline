control 'SV-281312' do
  title 'RHEL 10 must be configured to disable the Controller Area Network (CAN) kernel module.'
  desc <<~DESC
    Disabling CAN protects the system against exploitation of any flaws in its implementation.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 disables the ability to load the CAN kernel module with the following command:

    $ sudo grep -rs can /etc/modprobe.conf /etc/modprobe.d/* | grep -v '#'
    /etc/modprobe.d/can.conf:install can /bin/false
    /etc/modprobe.d/can.conf:blacklist can

    If the command does not return any output, or the lines are commented out, and use of CAN is not documented with the information system security officer as an operational requirement, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable the ability to load the CAN kernel module.

    Create a drop-in if it does not already exist:

    $ sudo vi /etc/modprobe.d/can.conf

    Add the following lines to the file:

    install can /bin/false
    blacklist can
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281312'
  tag rid: 'SV-281312r1167086_rule'
  tag stig_id: 'RHEL-10-701100'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85778r1167085_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe file('/etc/modprobe.d/can.conf') do
    it { should exist }
    its('content') { should match(/#/i) }
  end
end
