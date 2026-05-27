control 'SV-281070' do
  title 'RHEL 10 must enforce mode "0644" or less permissive for the "/etc/passwd" file to prevent unauthorized access.'
  desc <<~DESC
    If the "/etc/passwd" file is writable by a group-owner or the world, the risk of its compromise is increased. The file contains the list of accounts on the system and associated information, and protection of this file is critical for system security.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the "/etc/passwd" file has mode "0644" or less permissive with the following command:

    $ sudo stat -c "%a %n" /etc/passwd
    644 /etc/passwd

    If a value of "0644" or less permissive is not returned, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the mode of the file "/etc/passwd" is set to "0644" by running the following command:

    $ sudo chmod 0644 /etc/passwd
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281070'
  tag rid: 'SV-281070r1165565_rule'
  tag stig_id: 'RHEL-10-400265'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85536r1165564_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("stat -c \"%a %n\" /etc/passwd") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
