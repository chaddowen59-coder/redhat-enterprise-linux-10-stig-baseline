control 'SV-281064' do
  title 'RHEL 10 must enforce mode "0740" or less permissive for local initialization files.'
  desc <<~DESC
    Local initialization files are used to configure the user's shell environment upon login. Malicious modification of these files could compromise accounts upon login.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that all local initialization files have a mode of "0740" or less permissive with the following command:

    Note: The example will be for the "disauser" user, who has a home directory of "/home/disauser".

    $ sudo find /home -maxdepth 2 -type f -name ".*" -exec stat -c "%n %a" {} \; | awk '$2 > 740'
    /home/disauser/.bash_profile 770 

    If any local initialization files are returned, this indicates a mode more permissive than "0740", and this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that all local initialization files have a mode of "0740" or less permissive with the following command:

    Note: The example will be for the "disauser" user, who has a home directory of "/home/disauser".

    $ sudo chmod 0740 /home/disauser/.<INIT_FILE>
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281064'
  tag rid: 'SV-281064r1165547_rule'
  tag stig_id: 'RHEL-10-400235'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85530r1165546_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("find /home -maxdepth 2 -type f -name \".*\" -exec stat -c \"%n %a\" {} \\; | awk '$2 > 740'") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
