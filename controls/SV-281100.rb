control 'SV-281100' do
  title 'RHEL 10 must log username information when unsuccessful login attempts occur.'
  desc <<~DESC
    Without auditing of these events, it may be harder or impossible to identify what an attacker did after an attack.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 "/etc/security/faillock.conf" is configured to log username information when unsuccessful login attempts occur with the following command:

    $ sudo grep audit /etc/security/faillock.conf
    audit

    If the "audit" option is not set, is missing, or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to log username information when unsuccessful login attempts occur.

    Enable the feature using the following command:

    $ sudo authselect enable-feature with-faillock

    Add/modify the "/etc/security/faillock.conf" file to match the following line:

    audit
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281100'
  tag rid: 'SV-281100r1165655_rule'
  tag stig_id: 'RHEL-10-500020'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-85566r1165654_fix'
  tag cci: ['CCI-000044']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep audit /etc/security/faillock.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
