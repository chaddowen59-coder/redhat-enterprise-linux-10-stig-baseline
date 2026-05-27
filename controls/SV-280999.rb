control 'SV-280999' do
  title 'RHEL 10 must be configured to prevent unrestricted mail relaying.'
  desc <<~DESC
    If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay to send spam or for other unauthorized activity.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If postfix is not installed, this is not applicable.

    Verify RHEL 10 is configured to prevent unrestricted mail relaying with the following command:

    $ postconf -n smtpd_client_restrictions
    smtpd_client_restrictions = permit_mynetworks,reject

    If the "smtpd_client_restrictions" parameter contains any entries other than "permit_mynetworks" and "reject", and the additional entries have not been documented with the information system security officer, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the postfix configuration file restricts client connections to the local network with the following command:

    $ sudo postconf -e 'smtpd_client_restrictions = permit_mynetworks,reject'
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280999'
  tag rid: 'SV-280999r1165352_rule'
  tag stig_id: 'RHEL-10-200692'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85465r1165351_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("postconf -n smtpd_client_restrictions") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
