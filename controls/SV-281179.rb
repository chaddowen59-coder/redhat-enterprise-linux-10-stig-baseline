control 'SV-281179' do
  title 'RHEL 10 must enforce a delay of at least four seconds between login prompts following a failed login attempt.'
  desc <<~DESC
    Increasing the time between a failed authentication attempt and reprompting to enter credentials helps to slow a single-threaded brute-force attack.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enforces a delay of at least four seconds between console login prompts following a failed login attempt with the following command:

    $ sudo grep -i fail_delay /etc/login.defs
    FAIL_DELAY 4

    If the value of "FAIL_DELAY" is not set to "4" or greater, or the line is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enforce a delay of at least four seconds between login prompts following a failed console login attempt.

    Modify the "/etc/login.defs" file to set the "FAIL_DELAY" parameter to "4" or greater:

    FAIL_DELAY 4
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281179'
  tag rid: 'SV-281179r1166489_rule'
  tag stig_id: 'RHEL-10-600200'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-85645r1166488_fix'
  tag cci: ['CCI-002238']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -i fail_delay /etc/login.defs") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
