control 'SV-281087' do
  title 'RHEL 10 must enforce "root" ownership of the "/boot/grub2/grub.cfg" file.'
  desc <<~DESC
    The " /boot/grub2/grub.cfg" file stores sensitive system configuration. Protection of this file is critical for system security.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enforces ownership of the "/boot/grub2/grub.cfg" file with the following command:

    $ sudo stat -c "%U %n" /boot/grub2/grub.cfg
    root /boot/grub2/grub.cfg

    If the "/boot/grub2/grub.cfg" file does not have an owner of "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enforce ownership of the "/boot/grub2/grub.cfg" file.

    Change the owner of the "/boot/grub2/grub.cfg" file to "root" by running the following command:

    $ sudo chown root /boot/grub2/grub.cfg
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281087'
  tag rid: 'SV-281087r1165616_rule'
  tag stig_id: 'RHEL-10-400350'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85553r1165615_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("stat -c \"%U %n\" /boot/grub2/grub.cfg") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
