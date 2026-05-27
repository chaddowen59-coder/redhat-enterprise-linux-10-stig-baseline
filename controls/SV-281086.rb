control 'SV-281086' do
  title 'RHEL 10 must enforce "root" group ownership of the "/boot/grub2/grub.cfg" file.'
  desc <<~DESC
    The "root" group is a highly privileged group. Furthermore, the group owner of this file should not have any access privileges anyway.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enforces group ownership of the "/boot/grub2/grub.cfg" file with the following command:

    $ sudo stat -c "%G %n" /boot/grub2/grub.cfg
    root /boot/grub2/grub.cfg

    If the "/boot/grub2/grub.cfg" file does not have a group owner of "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enforce group ownership of the "/boot/grub2/grub.cfg" file.

    Change the group owner of the file "/boot/grub2/grub.cfg" to "root" by running the following command:

    $ sudo chgrp root /boot/grub2/grub.cfg
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281086'
  tag rid: 'SV-281086r1165613_rule'
  tag stig_id: 'RHEL-10-400345'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85552r1165612_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("stat -c \"%G %n\" /boot/grub2/grub.cfg") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
