control 'SV-281173' do
  title 'RHEL 10 must automatically expire temporary accounts within 72 hours.'
  desc <<~DESC
    Temporary accounts are privileged or nonprivileged accounts that are established during pressing circumstances, such as new software or hardware configuration or an incident response, where the need for prompt account activation requires bypassing normal account authorization procedures. If any inactive temporary accounts are left enabled on the system and are not manually removed or automatically expired within 72 hours, the security posture of the system will be degraded and exposed to exploitation by unauthorized users or insider threat actors.

    Temporary accounts are different from emergency accounts. Emergency accounts, also known as "last resort" or "break glass" accounts, are local login accounts enabled on the system for emergency use by authorized system administrators to manage a system when standard login methods are failing or not available. Emergency accounts are not subject to manual removal or scheduled expiration requirements.

    The automatic expiration of temporary accounts may be extended as needed by the circumstances, but it must not be extended indefinitely. A documented permanent account should be established for privileged users who need long-term maintenance accounts.

    Satisfies: SRG-OS-000123-GPOS-00064, SRG-OS-000002-GPOS-00002
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 automatically expires temporary accounts within 72 hours.

    For every existing temporary account, run the following command to obtain its account expiration information:

    $ sudo chage -l <temporary_account_name> | grep -i "account expires"

    Verify each of these accounts has an expiration date set within 72 hours.

    If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to expire temporary accounts after 72 hours with the following command:

    $ sudo chage -E $(date -d +3days +%Y-%m-%d) <temporary_account_name>
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281173'
  tag rid: 'SV-281173r1166471_rule'
  tag stig_id: 'RHEL-10-600140'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-85639r1166470_fix'
  tag cci: ['CCI-001682', 'CCI-000016']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("chage -l <temporary_account_name> | grep -i \"account expires\"") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
