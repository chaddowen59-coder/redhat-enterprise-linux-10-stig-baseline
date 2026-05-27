control 'SV-281044' do
  title 'RHEL 10 must be configured so that cron configuration files directories are group-owned by root.'
  desc <<~DESC
    Service configuration files enable or disable features of their respective services, which if configured incorrectly can lead to insecure and vulnerable configurations. Therefore, service configuration files should be owned by the correct group to prevent unauthorized changes.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 group ownership of all cron configuration files with the following command:

    $ stat -c "%G %n" /etc/cron*
    root /etc/cron.d
    root /etc/cron.daily
    root /etc/cron.deny
    root /etc/cron.hourly
    root /etc/cron.monthly
    root /etc/crontab
    root /etc/cron.weekly

    If any crontab is not group-owned by "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that any cron configuration file directories are group-owned by "root" with the following command:

    $ sudo chgrp root [cron config file]
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281044'
  tag rid: 'SV-281044r1184618_rule'
  tag stig_id: 'RHEL-10-400135'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85510r1165486_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("stat -c \"%G %n\" /etc/cron*") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
