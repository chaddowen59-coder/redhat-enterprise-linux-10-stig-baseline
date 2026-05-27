control 'SV-281251' do
  title 'RHEL 10 must use a Linux Security Module configured to enforce limits on system services.'
  desc <<~DESC
    Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. 

    Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

    This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.

    Satisfies: SRG-OS-000445-GPOS-00199, SRG-OS-000134-GPOS-00068
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enforces correct operation of security functions through the use of SELinux with the following command:

    $ getenforce
    Enforcing

    If SELINUX is not set to "Enforcing", this is a finding.

    Verify SELinux is configured to be enforcing at boot.

    $ sudo grep "SELINUX=" /etc/selinux/config | grep -v '#'
    SELINUX=enforcing

    If an uncommented SELinux line is missing or not set to "enforcing", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enforce correct operation of security functions.

    Edit the file "/etc/selinux/config" and add or modify the following line:

     SELINUX=enforcing

    A reboot is required for the changes to take effect.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281251'
  tag rid: 'SV-281251r1166705_rule'
  tag stig_id: 'RHEL-10-700420'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-85717r1166704_fix'
  tag cci: ['CCI-002696', 'CCI-001084']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe file('/etc/selinux/config') do
    it { should exist }
    its('content') { should match(/selinux=/i) }
  end
end
