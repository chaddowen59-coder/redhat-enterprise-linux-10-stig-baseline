control 'SV-281043' do
  title 'RHEL 10 must be configured so that cron configuration file directories are owned by root.'
  desc <<~DESC
    Service configuration files enable or disable features of their respective services, which if configured incorrectly could lead to insecure and vulnerable configurations. Therefore, service configuration files must be owned by the correct group to prevent unauthorized changes.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 ownership of all cron configuration files with the following command:

    $ stat -c "%U %n" /etc/cron*
    root /etc/cron.d
    root /etc/cron.daily
    root /etc/cron.deny
    root /etc/cron.hourly
    root /etc/cron.monthly
    root /etc/crontab
    root /etc/cron.weekly

    If any crontab is not owned by root, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that cron configuration file directories are owned by root with the following command:

    $ sudo chown root [cron config file]
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281043'
  tag rid: 'SV-281043r1184617_rule'
  tag stig_id: 'RHEL-10-400130'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-85509r1165483_fix'
  tag cci: ['CCI-002696']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("stat -c \"%U %n\" /etc/cron*") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
