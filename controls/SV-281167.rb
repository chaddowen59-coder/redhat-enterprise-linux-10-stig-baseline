control 'SV-281167' do
  title 'RHEL 10 must require a unique superusers name upon booting into single-user and maintenance modes.'
  desc <<~DESC
    Having a nondefault grub superuser username makes password-guessing attacks less effective.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 requires a unique superusers name upon booting into single-user and maintenance modes.

    Verify that the boot loader superuser account has been set with the following command:

    $ sudo grep -A1 "superusers" /etc/grub2.cfg
    set superusers="<accountname>"
    export superusers
    password_pbkdf2 <accountname> ${GRUB2_PASSWORD}

    Verify <accountname> is not a common name such as root, admin, or administrator.

    If superusers contains easily guessable usernames, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have a unique username for the grub superuser account.

    Edit the "/etc/grub.d/01_users" file and add or modify the following lines with a nondefault username for the superuser account:

    set superusers="<accountname>"
    export superusers

    Once the superuser account has been added, update the "grub.cfg" file by regenerating the GRUB configuration with the following command:

    $ sudo grub2-mkconfig -o /boot/grub2/grub.cfg --update-bls-cmdline

    Reboot the system:

    $ sudo reboot
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281167'
  tag rid: 'SV-281167r1166453_rule'
  tag stig_id: 'RHEL-10-600010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85633r1166452_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe file('/etc/grub2.cfg') do
    it { should exist }
    its('content') { should match(/superusers/i) }
  end
end
