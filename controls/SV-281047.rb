control 'SV-281047' do
  title 'RHEL 10 must be configured so that the Secure Shell (SSH) server configuration file is group-owned by "root".'
  desc <<~DESC
    Service configuration files enable or disable features of their respective services, which if configured incorrectly can lead to insecure and vulnerable configurations. Therefore, service configuration files must be owned by the correct group to prevent unauthorized changes.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the "/etc/ssh/sshd_config" file and the contents of "/etc/ssh/sshd_config.d" are group-owned by "root" with the following command:

    $ sudo find /etc/ssh/sshd_config /etc/ssh/sshd_config.d -exec stat -c "%G %n" {} \;
    root /etc/ssh/sshd_config
    root /etc/ssh/sshd_config.d
    root /etc/ssh/sshd_config.d/50-cloud-init.conf
    root /etc/ssh/sshd_config.d/50-redhat.conf

    If the "/etc/ssh/sshd_config" file or "/etc/ssh/sshd_config.d" or any files in the "sshd_config.d" directory do not have a group owner of "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the "/etc/ssh/sshd_config" file and the contents of "/etc/ssh/sshd_config.d" are group-owned by "root" with the following command:

    $ sudo chgrp root /etc/ssh/sshd_config /etc/ssh/sshd_config.d
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281047'
  tag rid: 'SV-281047r1184647_rule'
  tag stig_id: 'RHEL-10-400150'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85513r1165495_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("find /etc/ssh/sshd_config /etc/ssh/sshd_config.d -exec stat -c \"%G %n\" {} \\;") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
