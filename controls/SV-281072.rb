control 'SV-281072' do
  title 'RHEL 10 must enforce mode "0000" or less permissive for "/etc/shadow-" file to prevent unauthorized access.'
  desc <<~DESC
    The "/etc/shadow-" file is a backup file of "/etc/shadow", and as such contains the list of local system accounts and password hashes. Protection of this file is critical for system security.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the "/etc/shadow-" file has mode "0000" with the following command:

    $ sudo stat -c "%a %n" /etc/shadow-
    0 /etc/shadow-

    If a value of "0" is not returned, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the mode of the "/etc/shadow-" file is set to "0000" by running the following command:

    $ sudo chmod 0000 /etc/shadow-
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281072'
  tag rid: 'SV-281072r1165571_rule'
  tag stig_id: 'RHEL-10-400275'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85538r1165570_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("stat -c \"%a %n\" /etc/shadow-") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
