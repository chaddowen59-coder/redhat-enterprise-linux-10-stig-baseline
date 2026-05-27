control 'SV-280991' do
  title 'RHEL 10 must use cron logging.'
  desc <<~DESC
    Cron logging can be used to trace the successful or unsuccessful execution of cron jobs. It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 rsyslog is configured to log cron events with the following command:

    Note: If another logging package is used, substitute the utility configuration file for "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files.

    $ sudo grep -s cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf
    /etc/rsyslog.conf:*.info;mail.none;authpriv.none;cron.none /var/log/messages
    /etc/rsyslog.conf:cron.* /var/log/cron

    If the command does not return a response, check for cron logging all facilities with the following command:

    $ logger -p local0.info "Test message for all facilities."

    Check the logs for the test message with the following:

    $ sudo tail /var/log/messages

    If "rsyslog" is not logging messages for the cron facility or all facilities, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 rsyslog to log all cron messages by adding or updating the following line to "/etc/rsyslog.conf" or a configuration file in the "/etc/rsyslog.d/" directory:

    cron.* /var/log/cron

    Restart the rsyslog daemon with the following command for the changes to take effect:

    $ sudo systemctl restart rsyslog.service
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280991'
  tag rid: 'SV-280991r1165328_rule'
  tag stig_id: 'RHEL-10-200648'
  tag gtitle: 'SRG-OS-000040-GPOS-00018'
  tag fix_id: 'F-85457r1165327_fix'
  tag cci: ['CCI-000133']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -s cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
